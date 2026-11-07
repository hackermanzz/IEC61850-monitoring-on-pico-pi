/** @file capture_hw.c
 * @brief DMA fills one buffer while a task decodes the other, on Core 1.
 *
 * ISRs never call the kernel, print, allocate or decode. Local interrupt
 * masking protects slot transitions because every writer is pinned to Core 1.
 * Core 0 reads only C11 atomic diagnostic counters. Two buffers prevent reuse
 * during decoding; they do not promise gap-free capture at arbitrary load.
 */
#include "capture_hw.h"

#if PORT_CAPTURE
#include <stdatomic.h> /* Cross-core counters, not volatile synchronization. */
#include "hardware/clocks.h" /* Integer-only PIO divider. */
#include "hardware/dma.h"    /* Claimed DMA channel and E5-safe stop. */
#include "hardware/gpio.h"   /* Confirmed input wires. */
#include "hardware/irq.h"    /* Core-local IRQ ownership. */
#include "hardware/pio.h"    /* Two claimed state machines. */
#include "hardware/regs/dma.h"
#include "hardware/sync.h"    /* Local interrupt masks. */
#include "pico/platform.h"    /* Core ID. */
#include "pico/time.h"        /* Hardware microsecond clock. */
#include "capture_rx.pio.h"   /* Generated from reviewed PIO source. */
#include "pico/binary_info.h" /* Image pin metadata. */

bi_decl(bi_1pin_with_name(4u, "LAN8720 CRS_DV receive input"));
bi_decl(bi_1pin_with_name(5u, "LAN8720 RXD0 receive input"));
bi_decl(bi_1pin_with_name(6u, "LAN8720 RXD1 receive input"));

_Static_assert(2 == ATOMIC_INT_LOCK_FREE,
               "ISR counters require lock-free atomics");

#define CAPTURE_PIN_BASE 4u
#define CAPTURE_RATE_HZ  50000000u

typedef enum
{
    RAW_FREE,
    RAW_FILLING,
    RAW_READY,
    RAW_READING
} raw_state_t;

typedef struct
{
    uint32_t    words[CAPTURE_RAW_WORDS];
    size_t      count;
    uint64_t    timestamp;
    uint32_t    sequence;
    raw_state_t state;
    bool        b_damaged;
    uint32_t    end_pc;
    uint32_t    pio_irq;
    uint32_t    irq_enable;
    uint32_t    irq_status;
    uint32_t    pin_levels;
    uint32_t    stop_reason;
    uint32_t    dma_remaining;
    uint32_t    dma_words;
} raw_slot_t;

static raw_slot_t  g_slots[2];
static PIO         gp_pio      = pio0;
static int         g_dma       = -1;
static int         g_sample_sm = -1;
static int         g_end_sm    = -1;
static uint32_t    g_sample_offset;
static uint32_t    g_end_offset;
static int         g_active = -1;
static uint64_t    g_stopped_us;
static bool        gb_initialized;
static atomic_uint g_completed;
static atomic_uint g_full;
static atomic_uint g_stall;
static atomic_uint g_pauses;
static atomic_uint g_high_arm;
static atomic_uint g_max_rearm;
static atomic_uint g_self_test_flags;
static atomic_uint g_self_test_word;
static atomic_uint g_self_test_end_pc;
static atomic_uint g_self_test_irq;
static atomic_uint g_eof_interrupts;

static void capture_hw_arm(void);
static void capture_hw_finish(bool b_full);
static void capture_hw_pio_isr(void);
static void capture_hw_dma_isr(void);
static bool capture_hw_self_test(void);
static void capture_hw_unclaim(void);

/** @brief Release fully claimed, stopped receive resources after init failure.
 */
static void
capture_hw_unclaim (void)
{
    pio_remove_program(gp_pio, &capture_end_program, g_end_offset);
    pio_remove_program(gp_pio, &capture_samples_program, g_sample_offset);
    pio_sm_unclaim(gp_pio, (uint32_t) g_sample_sm);
    pio_sm_unclaim(gp_pio, (uint32_t) g_end_sm);
    dma_channel_unclaim((uint32_t) g_dma);
}

/** @brief Test PIO inputs internally; never enable a physical output driver.
 * @note IRQ handlers and DMA are not enabled yet. Override all three INPUT
 * paths for a known sample, then drive only the internal CRS input low.
 * Both SMs stop and all overrides return to normal on either result.
 */
static bool
capture_hw_self_test (void)
{
    uint32_t saved = save_and_disable_interrupts();
    uint32_t pin   = 0u;
    uint32_t word  = 0u;
    uint32_t flags = 0u;
    uint32_t mask =
        (1u << (uint32_t) g_sample_sm) | (1u << (uint32_t) g_end_sm);

    for (pin = CAPTURE_PIN_BASE; CAPTURE_PIN_BASE + 3u > pin; pin++)
    {
        gpio_set_inover(pin, (CAPTURE_PIN_BASE == pin) ? GPIO_OVERRIDE_HIGH
                                                       : GPIO_OVERRIDE_LOW);
    }
    pio_interrupt_clear(gp_pio, 0u);
    pio_enable_sm_mask_in_sync(gp_pio, mask);
    busy_wait_us_32(5u);
    if (!pio_sm_is_rx_fifo_empty(gp_pio, (uint32_t) g_sample_sm))
    {
        word = pio_sm_get(gp_pio, (uint32_t) g_sample_sm);
        if (0x24924924u == (word & 0xfffffffcu))
        {
            flags |= 1u;
        }
    }
    pio_sm_set_enabled(gp_pio, (uint32_t) g_sample_sm, false);
    pio_sm_clear_fifos(gp_pio, (uint32_t) g_sample_sm);
    pio_sm_restart(gp_pio, (uint32_t) g_sample_sm);
    pio_sm_exec(gp_pio, (uint32_t) g_sample_sm,
                pio_encode_jmp(g_sample_offset));
    gpio_set_inover(CAPTURE_PIN_BASE + 1u, GPIO_OVERRIDE_HIGH);
    gpio_set_inover(CAPTURE_PIN_BASE + 2u, GPIO_OVERRIDE_HIGH);
    pio_sm_set_enabled(gp_pio, (uint32_t) g_sample_sm, true);
    busy_wait_us_32(5u);
    if (!pio_sm_is_rx_fifo_empty(gp_pio, (uint32_t) g_sample_sm))
    {
        word = pio_sm_get(gp_pio, (uint32_t) g_sample_sm);
        if (0xfffffffcu == (word & 0xfffffffcu))
        {
            flags |= 2u;
        }
    }
    /* End must not assert while CRS is held high. */
    if (!pio_interrupt_get(gp_pio, 0u))
    {
        gpio_set_inover(CAPTURE_PIN_BASE, GPIO_OVERRIDE_LOW);
        busy_wait_us_32(5u);
        if (pio_interrupt_get(gp_pio, 0u))
        {
            flags |= 4u;
        }
    }
    pio_set_sm_mask_enabled(gp_pio, mask, false);
    atomic_store(&g_self_test_end_pc,
                 (pio_sm_get_pc(gp_pio, (uint32_t) g_end_sm) - g_end_offset)
                     & 31u);
    atomic_store(&g_self_test_irq, gp_pio->irq);
    for (pin = CAPTURE_PIN_BASE; CAPTURE_PIN_BASE + 3u > pin; pin++)
    {
        gpio_set_inover(pin, GPIO_OVERRIDE_NORMAL);
    }
    pio_interrupt_clear(gp_pio, 0u);
    atomic_store(&g_self_test_word, word);
    atomic_store(&g_self_test_flags, flags);
    restore_interrupts(saved);
    return 7u == flags;
}

/** @brief Arm only FREE storage. Caller has masked local interrupts. */
static void
capture_hw_arm (void)
{
    uint32_t index   = 0u;
    uint32_t elapsed = 0u;
    uint32_t mask =
        (1u << (uint32_t) g_sample_sm) | (1u << (uint32_t) g_end_sm);

    for (index = 0u; (2u > index) && (0 > g_active); index++)
    {
        if (RAW_FREE == g_slots[index].state)
        {
            g_active = (int) index;
        }
    }
    if (0 > g_active)
    {
        atomic_fetch_add(&g_pauses, 1u);
        return;
    }
    g_slots[g_active].state = RAW_FILLING;
    pio_sm_clear_fifos(gp_pio, (uint32_t) g_sample_sm);
    pio_sm_restart(gp_pio, (uint32_t) g_sample_sm);
    pio_sm_restart(gp_pio, (uint32_t) g_end_sm);
    pio_sm_exec(gp_pio, (uint32_t) g_sample_sm,
                pio_encode_jmp(g_sample_offset));
    pio_sm_exec(gp_pio, (uint32_t) g_end_sm, pio_encode_jmp(g_end_offset));
    pio_interrupt_clear(gp_pio, 0u);
    gp_pio->fdebug = 1u << (PIO_FDEBUG_RXSTALL_LSB + (uint32_t) g_sample_sm);
    dma_hw->ints1  = 1u << (uint32_t) g_dma;
    dma_channel_set_write_addr((uint32_t) g_dma, g_slots[g_active].words,
                               false);
    dma_channel_set_trans_count((uint32_t) g_dma, CAPTURE_RAW_WORDS, true);
    if (gpio_get(CAPTURE_PIN_BASE))
    {
        atomic_fetch_add(&g_high_arm, 1u);
    }
    if (0u != g_stopped_us)
    {
        elapsed = (uint32_t) (time_us_64() - g_stopped_us);
        if (atomic_load(&g_max_rearm) < elapsed)
        {
            atomic_store(&g_max_rearm, elapsed);
        }
    }
    pio_enable_sm_mask_in_sync(gp_pio, mask);
}

/** @brief Stop DMA before publishing READY; a published buffer never changes.
 */
static void
capture_hw_finish (bool b_full)
{
    raw_slot_t * p_slot     = NULL;
    uint32_t     stall_mask = 1u
                           << (PIO_FDEBUG_RXSTALL_LSB + (uint32_t) g_sample_sm);
    uint32_t     mask =
        (1u << (uint32_t) g_sample_sm) | (1u << (uint32_t) g_end_sm);
    bool b_stalled       = false;
    bool b_pointer_valid = false;

    if (0 > g_active)
    {
        pio_interrupt_clear(gp_pio, 0u);
        dma_hw->ints1 = 1u << (uint32_t) g_dma;
        return;
    }
    pio_set_sm_mask_enabled(gp_pio, mask, false);
    g_stopped_us = time_us_64();
    p_slot       = &g_slots[g_active];
    p_slot->end_pc =
        (pio_sm_get_pc(gp_pio, (uint32_t) g_end_sm) - g_end_offset) & 31u;
    p_slot->pio_irq     = gp_pio->irq;
    p_slot->irq_enable  = gp_pio->inte0;
    p_slot->irq_status  = gp_pio->ints0;
    p_slot->pin_levels  = (gpio_get_all() >> CAPTURE_PIN_BASE) & 7u;
    p_slot->stop_reason = b_full ? 1u : 0u;
    p_slot->dma_remaining =
        dma_channel_hw_addr((uint32_t) g_dma)->transfer_count
        & DMA_CH0_TRANS_COUNT_COUNT_BITS;
    /* RP2350 erratum E5: clear EN before abort, with no chained channel. */
    dma_channel_hw_addr((uint32_t) g_dma)->al1_ctrl &=
        ~DMA_CH0_CTRL_TRIG_EN_BITS;
    dma_channel_abort((uint32_t) g_dma);
    /* The post-stop write pointer independently records completed writes.
     * Do not infer a full buffer solely from an inactive transfer counter.
     */
    p_slot->count   = 0u;
    b_pointer_valid = capture_hw_dma_count(
        (uintptr_t) p_slot->words,
        dma_channel_hw_addr((uint32_t) g_dma)->write_addr, &p_slot->count);
    p_slot->dma_words = (uint32_t) p_slot->count;
    /* Drain completed words still in PIO FIFO. The partial input shift
     * register holds idle after the qualified tail; do not push it.
     */
    while ((!pio_sm_is_rx_fifo_empty(gp_pio, (uint32_t) g_sample_sm))
           && b_pointer_valid && (CAPTURE_RAW_WORDS > p_slot->count))
    {
        p_slot->words[p_slot->count++] =
            pio_sm_get(gp_pio, (uint32_t) g_sample_sm);
    }
    b_stalled         = 0u != (gp_pio->fdebug & stall_mask);
    b_full            = b_full || (CAPTURE_RAW_WORDS == p_slot->count);
    p_slot->b_damaged = b_full || b_stalled || (!b_pointer_valid);
    p_slot->timestamp =
        g_stopped_us; /* Qualified end-service time, not arrival. */
    p_slot->sequence = atomic_fetch_add(&g_completed, 1u) + 1u;
    if (b_full)
    {
        atomic_fetch_add(&g_full, 1u);
    }
    if (b_stalled)
    {
        atomic_fetch_add(&g_stall, 1u);
    }
    __dmb(); /* DMA/FIFO writes precede publication to the local task. */
    p_slot->state = RAW_READY;
    g_active      = -1;
    pio_interrupt_clear(gp_pio, 0u);
    dma_hw->ints1 = 1u << (uint32_t) g_dma;
    capture_hw_arm();
    __sev(); /* Wake the raw-buffer service task without a kernel ISR call. */
}

static void
capture_hw_pio_isr (void)
{
    if (pio_interrupt_get(gp_pio, 0u))
    {
        atomic_fetch_add(&g_eof_interrupts, 1u);
        capture_hw_finish(false);
    }
}

static void
capture_hw_dma_isr (void)
{
    if (0u != (dma_hw->ints1 & (1u << (uint32_t) g_dma)))
    {
        capture_hw_finish(true);
    }
}

bool
capture_hw_init (void)
{
    uint32_t      pin     = 0u;
    uint32_t      divider = (uint32_t) (((uint64_t) clock_get_hz(clk_sys) * 256u
                                         + CAPTURE_RATE_HZ / 2u)
                                        / CAPTURE_RATE_HZ);
    uint32_t      saved   = 0u;
    uint64_t      deadline = 0u;
    pio_sm_config sample_config;
    pio_sm_config end_config;
    dma_channel_config dma_config;

    if ((1u != get_core_num()) || gb_initialized || (256u > divider)
        || (NULL != irq_get_exclusive_handler(PIO0_IRQ_0))
        || irq_has_shared_handler(PIO0_IRQ_0)
        || (NULL != irq_get_exclusive_handler(DMA_IRQ_1))
        || irq_has_shared_handler(DMA_IRQ_1)
        || (!pio_can_add_program(gp_pio, &capture_samples_program)))
    {
        return false;
    }
    g_sample_sm = pio_claim_unused_sm(gp_pio, false);
    g_end_sm    = pio_claim_unused_sm(gp_pio, false);
    g_dma       = dma_claim_unused_channel(false);
    if ((0 > g_sample_sm) || (0 > g_end_sm) || (0 > g_dma))
    {
        if (0 <= g_sample_sm)
        {
            pio_sm_unclaim(gp_pio, (uint32_t) g_sample_sm);
        }
        if (0 <= g_end_sm)
        {
            pio_sm_unclaim(gp_pio, (uint32_t) g_end_sm);
        }
        if (0 <= g_dma)
        {
            dma_channel_unclaim((uint32_t) g_dma);
        }
        return false;
    }
    g_sample_offset = pio_add_program(gp_pio, &capture_samples_program);
    if (!pio_can_add_program(gp_pio, &capture_end_program))
    {
        pio_remove_program(gp_pio, &capture_samples_program, g_sample_offset);
        pio_sm_unclaim(gp_pio, (uint32_t) g_sample_sm);
        pio_sm_unclaim(gp_pio, (uint32_t) g_end_sm);
        dma_channel_unclaim((uint32_t) g_dma);
        return false;
    }
    g_end_offset = pio_add_program(gp_pio, &capture_end_program);
    for (pin = CAPTURE_PIN_BASE; CAPTURE_PIN_BASE + 3u > pin; pin++)
    {
        pio_gpio_init(gp_pio, pin);
        gpio_disable_pulls(pin);
    }
    pio_sm_set_consecutive_pindirs(gp_pio, (uint32_t) g_sample_sm,
                                   CAPTURE_PIN_BASE, 3u, false);
    sample_config = capture_samples_program_get_default_config(g_sample_offset);
    sm_config_set_in_pins(&sample_config, CAPTURE_PIN_BASE);
    sm_config_set_in_shift(&sample_config, true, true, 30u);
    sm_config_set_fifo_join(&sample_config, PIO_FIFO_JOIN_RX);
    sm_config_set_clkdiv_int_frac8(&sample_config, divider / 256u,
                                   (uint8_t) (divider & 255u));
    end_config = capture_end_program_get_default_config(g_end_offset);
    sm_config_set_in_pins(&end_config, CAPTURE_PIN_BASE);
    sm_config_set_jmp_pin(&end_config, CAPTURE_PIN_BASE);
    sm_config_set_clkdiv_int_frac8(&end_config, divider / 256u,
                                   (uint8_t) (divider & 255u));
    pio_sm_init(gp_pio, (uint32_t) g_sample_sm, g_sample_offset,
                &sample_config);
    pio_sm_init(gp_pio, (uint32_t) g_end_sm, g_end_offset, &end_config);
    if (!capture_hw_self_test())
    {
        capture_hw_unclaim();
        return false;
    }
    dma_config = dma_channel_get_default_config((uint32_t) g_dma);
    channel_config_set_transfer_data_size(&dma_config, DMA_SIZE_32);
    channel_config_set_read_increment(&dma_config, false);
    channel_config_set_write_increment(&dma_config, true);
    channel_config_set_dreq(
        &dma_config, pio_get_dreq(gp_pio, (uint32_t) g_sample_sm, false));
    dma_channel_configure((uint32_t) g_dma, &dma_config, g_slots[0].words,
                          &gp_pio->rxf[g_sample_sm], CAPTURE_RAW_WORDS, false);
    irq_set_exclusive_handler(PIO0_IRQ_0, capture_hw_pio_isr);
    irq_set_exclusive_handler(DMA_IRQ_1, capture_hw_dma_isr);
    irq_set_priority(PIO0_IRQ_0, 0x40u);
    irq_set_priority(DMA_IRQ_1, 0x40u);
    pio_interrupt_clear(gp_pio, 0u);
    dma_hw->ints1 = 1u << (uint32_t) g_dma;
    irq_clear(PIO0_IRQ_0);
    irq_clear(DMA_IRQ_1);
    pio_set_irq0_source_enabled(gp_pio, pis_interrupt0, true);
    dma_channel_set_irq1_enabled((uint32_t) g_dma, true);
    irq_set_enabled(PIO0_IRQ_0, true);
    irq_set_enabled(DMA_IRQ_1, true);
    /* Prove the actual Core 1 interrupt route while acquisition is stopped.
     * The ISR sees no active buffer, acknowledges the flag and returns.
     */
    pio_sm_exec(gp_pio, (uint32_t) g_end_sm, pio_encode_irq_set(false, 0u));
    deadline = time_us_64() + 100u;
    while ((0u == atomic_load(&g_eof_interrupts)) && (time_us_64() < deadline))
    {
        tight_loop_contents();
    }
    if (0u == atomic_load(&g_eof_interrupts))
    {
        irq_set_enabled(PIO0_IRQ_0, false);
        irq_set_enabled(DMA_IRQ_1, false);
        pio_set_irq0_source_enabled(gp_pio, pis_interrupt0, false);
        dma_channel_set_irq1_enabled((uint32_t) g_dma, false);
        pio_interrupt_clear(gp_pio, 0u);
        irq_remove_handler(PIO0_IRQ_0, capture_hw_pio_isr);
        irq_remove_handler(DMA_IRQ_1, capture_hw_dma_isr);
        capture_hw_unclaim();
        return false;
    }
    atomic_fetch_or(&g_self_test_flags, 8u);
    atomic_store(&g_eof_interrupts,
                 0u); /* Do not count the injected interrupt. */
    gb_initialized = true;
    saved          = save_and_disable_interrupts();
    capture_hw_arm();
    restore_interrupts(saved);
    return true;
}

bool
capture_hw_take (capture_raw_t * p_raw)
{
    uint32_t saved  = save_and_disable_interrupts();
    int      chosen = -1;
    uint32_t index  = 0u;

    for (index = 0u; 2u > index; index++)
    {
        if ((RAW_READY == g_slots[index].state)
            && ((0 > chosen)
                || ((int32_t) (g_slots[index].sequence
                               - g_slots[chosen].sequence)
                    < 0)))
        {
            chosen = (int) index;
        }
    }
    if ((NULL != p_raw) && (0 <= chosen))
    {
        g_slots[chosen].state = RAW_READING;
        p_raw->p_words        = g_slots[chosen].words;
        p_raw->word_count     = g_slots[chosen].count;
        p_raw->timestamp_us   = g_slots[chosen].timestamp;
        p_raw->sequence       = g_slots[chosen].sequence;
        p_raw->slot           = (uint32_t) chosen;
        p_raw->b_damaged      = g_slots[chosen].b_damaged;
        p_raw->end_pc         = g_slots[chosen].end_pc;
        p_raw->pio_irq        = g_slots[chosen].pio_irq;
        p_raw->irq_enable     = g_slots[chosen].irq_enable;
        p_raw->irq_status     = g_slots[chosen].irq_status;
        p_raw->pin_levels     = g_slots[chosen].pin_levels;
        p_raw->stop_reason    = g_slots[chosen].stop_reason;
        p_raw->dma_remaining  = g_slots[chosen].dma_remaining;
        p_raw->dma_words      = g_slots[chosen].dma_words;
    }
    restore_interrupts(saved);
    return (NULL != p_raw) && (0 <= chosen);
}

void
capture_hw_release (uint32_t slot)
{
    uint32_t saved = save_and_disable_interrupts();

    if ((2u > slot) && (RAW_READING == g_slots[slot].state))
    {
        g_slots[slot].state = RAW_FREE;
        if (0 > g_active)
        {
            capture_hw_arm();
        }
    }
    restore_interrupts(saved);
}

void
capture_hw_stats (capture_hw_stats_t * p_stats)
{
    p_stats->completed        = atomic_load(&g_completed);
    p_stats->dma_full         = atomic_load(&g_full);
    p_stats->fifo_stall       = atomic_load(&g_stall);
    p_stats->pauses           = atomic_load(&g_pauses);
    p_stats->armed_while_high = atomic_load(&g_high_arm);
    p_stats->max_rearm_us     = atomic_load(&g_max_rearm);
    p_stats->self_test_flags  = atomic_load(&g_self_test_flags);
    p_stats->self_test_word   = atomic_load(&g_self_test_word);
    p_stats->self_test_end_pc = atomic_load(&g_self_test_end_pc);
    p_stats->self_test_irq    = atomic_load(&g_self_test_irq);
    p_stats->eof_interrupts   = atomic_load(&g_eof_interrupts);
}
#endif /* PORT_CAPTURE */

/*** end of file ***/
