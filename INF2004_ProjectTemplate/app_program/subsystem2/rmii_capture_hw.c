/*
 * rmii_capture_hw.c  (owner: Buddy 2, Jonathan)
 * Hardware layer of the RMII capture for the µT-Kernel 3 SMP build.
 * Ported from rmii/src/rmii_ethernet.c (Sandeep Mistry, BSD-3-Clause):
 *   - receive only: the TX program, TX DMA channel and TX buffers are gone;
 *   - no lwIP netif and no SDK critical_section (kernel owns spin locks 0-2);
 *   - two sample buffers so the receiver is re-armed inside the ISR.
 */
#include "../monitor_config.h"
#if !MONITOR_SYNTHETIC
#include "rmii_capture_hw.h"

#include <string.h>

#include "hardware/dma.h"
#include "hardware/gpio.h"
#include "hardware/pio.h"
#include "hardware/structs/io_bank0.h"
#include "hardware/structs/timer.h"
#include "hardware/sync.h"

#include "app_config.h"
#include "rmii_ethernet_phy_rx.pio.h"

/* 62400 samples at 50 MS/s (125 MHz / 2.5) cover 1.25 ms, enough for a
 * maximum size frame at 10 Mbps. 16 samples per 32 bit word. */
#define RX_SAMPLE_WORDS          (3900u)
#define RX_MIN_CAPTURE_WORDS     (4u)
#define RX_PIO                   (pio0)
#define RX_SM                    (0u)

#define MDIO_PREAMBLE_BITS       (32u)
#define MDIO_ADDRESS_BITS        (5u)
#define MDIO_REGISTER_BITS       (5u)
#define MDIO_DATA_BITS           (16u)
#define MDIO_PHY_ADDRESS_COUNT   (32u)
#define MDIO_REG_CONTROL         (0u)
#define MDIO_REG_STATUS          (1u)
#define MDIO_REG_ID1             (2u)
#define MDIO_REG_ID2             (3u)
#define MDIO_REG_ADVERTISE       (4u)
#define MDIO_REG_PARTNER         (5u)
#define MDIO_REG_SPECIAL         (31u)
#define MDIO_CONTROL_RESET       (0x8000u)
#define MDIO_CONTROL_ANEG_RESTART (0x1200u)
#define MDIO_ADVERTISE_10M_ONLY  (0x0061u)
#define MDIO_STATUS_LINK         (0x0004u)
#define MDIO_ID_UNDRIVEN         (0xFFFFu)
#define MDIO_LAN8720_ID1         (0x0007u)
#define MDIO_LAN8720_ID2         (0xC0F0u)
#define MDIO_MODEL_MASK          (0xFFF0u) /* low nibble is silicon revision */
#define MDIO_RESET_POLL_LIMIT    (1000u)
#define GPIO_EVENTS_PER_REGISTER (8u)
#define GPIO_EVENT_FIELD_BITS    (4u)
#define GPIO_EVENT_FIELD_MASK    (0xFu)

typedef struct
{
    uint32_t bytes;
    uint64_t timestamp_us;
    uint32_t order;
} sample_slot_t;

static uint32_t          g_samples[RMII_HW_BUFFER_COUNT][RX_SAMPLE_WORDS];
static sample_slot_t     g_slots[RMII_HW_BUFFER_COUNT];
static volatile uint32_t g_ready_mask;   /* bit n: buffer n waits for decode */
static volatile uint32_t g_active;       /* buffer the DMA is filling */
static volatile bool     g_armed;
static volatile uint32_t g_order;
static volatile uint32_t g_isr_count;
static volatile uint32_t g_overruns;
static volatile uint32_t g_dma_full;
static uint              g_offset;
static int               g_dma = -1;
static dma_channel_config g_dma_config;
static uint32_t          g_phy_address;

/* ------------------------------------------------------------- time */

uint64_t
rmii_hw_time_us (void)
{
    uint32_t high_first = 0u;
    uint32_t low        = 0u;
    uint32_t high       = 0u;

    do
    {
        high_first = timer_hw->timerawh;
        low        = timer_hw->timerawl;
        high       = timer_hw->timerawh;
    } while (high != high_first);
    return ((uint64_t) high << 32u) | low;
}

static void
delay_us (uint32_t microseconds)
{
    const uint64_t end = rmii_hw_time_us() + microseconds;

    while (rmii_hw_time_us() < end)
    {
        __asm volatile("nop");
    }
}

/* ------------------------------------------------------------- MDIO */

static void
mdio_clock_out (uint32_t bit)
{
    gpio_put(IS18_RMII_MDC_PIN, 0);
    gpio_put(IS18_RMII_MDIO_PIN, bit != 0u);
    delay_us(1u); /* data setup before the PHY's rising-edge latch */
    gpio_put(IS18_RMII_MDC_PIN, 1);
    delay_us(1u);
}

static uint32_t
mdio_clock_in (void)
{
    uint32_t bit = 0u;

    gpio_put(IS18_RMII_MDC_PIN, 0);
    delay_us(1u);
    /* LAN8720A SMI output can change 0..300 ns after rising MDC. Read
     * the bit already driven during this low phase, before advancing it.
     * Sampling after the following high-phase delay loses D15 and reads
     * idle as D0: e.g. ID 0007/c0f1 becomes 000f/81e3. */
    bit = gpio_get(IS18_RMII_MDIO_PIN) ? 1u : 0u;
    gpio_put(IS18_RMII_MDC_PIN, 1);
    delay_us(1u);
    return bit;
}

static void
mdio_header (uint32_t address, uint32_t reg, bool read)
{
    uint32_t index = 0u;

    gpio_set_dir(IS18_RMII_MDIO_PIN, GPIO_OUT);
    for (index = 0u; index < MDIO_PREAMBLE_BITS; ++index)
    {
        mdio_clock_out(1u);
    }
    mdio_clock_out(0u); /* start */
    mdio_clock_out(1u);
    mdio_clock_out(read ? 1u : 0u); /* opcode 10 = read, 01 = write */
    mdio_clock_out(read ? 0u : 1u);
    for (index = 0u; index < MDIO_ADDRESS_BITS; ++index)
    {
        mdio_clock_out((address >> (MDIO_ADDRESS_BITS - 1u - index)) & 1u);
    }
    for (index = 0u; index < MDIO_REGISTER_BITS; ++index)
    {
        mdio_clock_out((reg >> (MDIO_REGISTER_BITS - 1u - index)) & 1u);
    }
}

static uint16_t
mdio_read (uint32_t address, uint32_t reg)
{
    uint32_t index = 0u;
    uint16_t data  = 0u;

    mdio_header(address, reg, true);
    gpio_set_dir(IS18_RMII_MDIO_PIN, GPIO_IN); /* turnaround */
    mdio_clock_out(0u);
    const bool acknowledged = mdio_clock_in() == 0u; /* Z, then PHY's 0 */
    for (index = 0u; index < MDIO_DATA_BITS; ++index)
    {
        data = (uint16_t) ((data << 1u) | mdio_clock_in());
    }
    /* Always drain all 16 clocks even without an acknowledgment, leaving
     * the bus released and the next transaction aligned. */
    return acknowledged ? data : MDIO_ID_UNDRIVEN;
}

static void
mdio_write (uint32_t address, uint32_t reg, uint16_t value)
{
    uint32_t index = 0u;

    mdio_header(address, reg, false);
    mdio_clock_out(1u); /* turnaround */
    mdio_clock_out(0u);
    for (index = 0u; index < MDIO_DATA_BITS; ++index)
    {
        mdio_clock_out(((uint32_t) value >> (MDIO_DATA_BITS - 1u - index)) &
                       1u);
    }
    gpio_set_dir(IS18_RMII_MDIO_PIN, GPIO_IN);
}

bool
rmii_hw_phy_init (uint32_t * phy_address)
{
    uint32_t address = 0u;
    uint32_t polls   = 0u;
    bool     found   = false;

    gpio_init(IS18_RMII_MDIO_PIN);
    gpio_init(IS18_RMII_MDC_PIN);
    gpio_set_dir(IS18_RMII_MDC_PIN, GPIO_OUT);
    gpio_set_dir(IS18_RMII_MDIO_PIN, GPIO_IN);

    for (address = 0u; address < MDIO_PHY_ADDRESS_COUNT && !found; ++address)
    {
        const uint16_t id1 = mdio_read(address, MDIO_REG_ID1);
        const uint16_t id2 = mdio_read(address, MDIO_REG_ID2);
        if (id1 == MDIO_LAN8720_ID1 &&
            (id2 & MDIO_MODEL_MASK) == MDIO_LAN8720_ID2)
        {
            g_phy_address = address;
            found         = true;
        }
    }
    if (!found)
    {
        return false;
    }
    /* Software reset replaces the nRST pin the module does not expose. */
    mdio_write(g_phy_address, MDIO_REG_CONTROL, MDIO_CONTROL_RESET);
    while ((mdio_read(g_phy_address, MDIO_REG_CONTROL) & MDIO_CONTROL_RESET) !=
               0u &&
           polls < MDIO_RESET_POLL_LIMIT)
    {
        ++polls;
    }
    if (polls == MDIO_RESET_POLL_LIMIT) return false;
    /* Decoder timing is 10 Mbps only. CRS_DV can toggle while receive data
     * drains at either speed (datasheet section 3.4.1.1); the first-fall EOF
     * approach below remains a hardware-qualification limitation. */
    mdio_write(g_phy_address, MDIO_REG_ADVERTISE, MDIO_ADVERTISE_10M_ONLY);
    if ((mdio_read(g_phy_address, MDIO_REG_ADVERTISE) & 0x01FFu) !=
        MDIO_ADVERTISE_10M_ONLY) return false;
    mdio_write(g_phy_address, MDIO_REG_CONTROL, MDIO_CONTROL_ANEG_RESTART);
    /* Ignore the self-clearing restart bit; verify AN enable and that
     * loopback, speed-force, power-down, isolate and duplex-force are off. */
    if ((mdio_read(g_phy_address, MDIO_REG_CONTROL) & 0x7D00u) != 0x1000u)
        return false;
    if (phy_address != NULL)
    {
        *phy_address = g_phy_address;
    }
    return true;
}

bool
rmii_hw_link_up (void)
{
    /* Link status latches low: read twice. */
    (void) mdio_read(g_phy_address, MDIO_REG_STATUS);
    return (mdio_read(g_phy_address, MDIO_REG_STATUS) & MDIO_STATUS_LINK) != 0u;
}

void rmii_hw_phy_diagnostics(rmii_hw_phy_diag_t *out)
{
    if (out == NULL) return;
    out->id1 = mdio_read(g_phy_address, MDIO_REG_ID1);
    out->id2 = mdio_read(g_phy_address, MDIO_REG_ID2);
    out->control = mdio_read(g_phy_address, MDIO_REG_CONTROL);
    (void)mdio_read(g_phy_address, MDIO_REG_STATUS);
    out->status = mdio_read(g_phy_address, MDIO_REG_STATUS);
    out->advertise = mdio_read(g_phy_address, MDIO_REG_ADVERTISE);
    out->partner = mdio_read(g_phy_address, MDIO_REG_PARTNER);
    out->special = mdio_read(g_phy_address, MDIO_REG_SPECIAL);
    out->io_levels = (uint16_t)(
        (gpio_get(IS18_RMII_CRS_DV_PIN) ? 1u : 0u) |
        (gpio_get(IS18_RMII_RXD0_PIN) ? 2u : 0u) |
        (gpio_get(IS18_RMII_RXD0_PIN + 1u) ? 4u : 0u));
}

/* ------------------------------------------------------------- receive */

/* Restart the sampler at the start of its program (wait for idle, then
 * carrier) and point the DMA at one buffer. Interrupts must be masked or
 * the caller must be the ISR. */
static void
arm_buffer (uint32_t buffer)
{
    pio_sm_set_enabled(RX_PIO, RX_SM, false);
    pio_sm_clear_fifos(RX_PIO, RX_SM);
    pio_sm_restart(RX_PIO, RX_SM);
    pio_sm_exec(RX_PIO, RX_SM, pio_encode_jmp(g_offset));
    dma_channel_configure((uint) g_dma, &g_dma_config, g_samples[buffer],
                          &RX_PIO->rxf[RX_SM], RX_SAMPLE_WORDS, true);
    g_active = buffer;
    g_armed  = true;
    pio_sm_set_enabled(RX_PIO, RX_SM, true);
}

bool
rmii_hw_rx_start (void)
{
    uint32_t saved = 0u;

    if (!pio_can_add_program(RX_PIO, &rmii_ethernet_phy_rx_data_program) ||
        pio_sm_is_claimed(RX_PIO, RX_SM))
    {
        return false;
    }
    pio_sm_claim(RX_PIO, RX_SM);
    g_offset = (uint) pio_add_program(RX_PIO, &rmii_ethernet_phy_rx_data_program);

    g_dma = dma_claim_unused_channel(false);
    if (g_dma < 0)
    {
        pio_remove_program(RX_PIO, &rmii_ethernet_phy_rx_data_program, g_offset);
        pio_sm_unclaim(RX_PIO, RX_SM);
        return false;
    }
    g_dma_config = dma_channel_get_default_config((uint) g_dma);
    channel_config_set_read_increment(&g_dma_config, false);
    channel_config_set_write_increment(&g_dma_config, true);
    channel_config_set_dreq(&g_dma_config, pio_get_dreq(RX_PIO, RX_SM, false));
    channel_config_set_transfer_data_size(&g_dma_config, DMA_SIZE_32);

    /* Pins, shift, FIFO join and clock divider (clk_sys / 50 MHz = 2.5).
     * This also starts the SM, so stop it until arm_buffer(). */
    rmii_ethernet_phy_rx_init(RX_PIO, RX_SM, g_offset, IS18_RMII_RXD0_PIN,
                              IS18_RMII_CRS_DV_PIN);
    pio_sm_set_enabled(RX_PIO, RX_SM, false);

    g_ready_mask = 0u;
    saved        = save_and_disable_interrupts();
    arm_buffer(0u);
    /* gpio_set_irq_enabled() writes the INTE register of the calling core,
     * so running this on core 1 keeps CRS_DV away from core 0. */
    gpio_set_irq_enabled(IS18_RMII_CRS_DV_PIN, GPIO_IRQ_EDGE_FALL, true);
    restore_interrupts(saved);
    return true;
}

uint32_t
rmii_hw_irq_number (void)
{
    return (uint32_t) IO_IRQ_BANK0;
}

bool
rmii_hw_isr (void)
{
    const uint32_t pin    = IS18_RMII_CRS_DV_PIN;
    io_bank0_irq_ctrl_hw_t * const irq_ctrl = get_core_num() == 0 ?
        &io_bank0_hw->proc0_irq_ctrl : &io_bank0_hw->proc1_irq_ctrl;
    const uint32_t events =
        (irq_ctrl->ints[pin / GPIO_EVENTS_PER_REGISTER] >>
         (GPIO_EVENT_FIELD_BITS * (pin % GPIO_EVENTS_PER_REGISTER))) &
        GPIO_EVENT_FIELD_MASK;
    uint64_t  timestamp_us = 0u;
    uint32_t  buffer       = 0u;
    uint32_t  other        = 0u;
    uintptr_t write_addr   = 0u;
    uintptr_t start        = 0u;
    uintptr_t end          = 0u;

    if ((events & GPIO_IRQ_EDGE_FALL) == 0u)
    {
        return false;
    }
    gpio_acknowledge_irq(pin, GPIO_IRQ_EDGE_FALL);
    timestamp_us = rmii_hw_time_us(); /* frame end, before any decoding */
    if (!g_armed)
    {
        return false;
    }
    pio_sm_set_enabled(RX_PIO, RX_SM, false);
    /* Finish the partial shift word with zeros. A plain PUSH would leave the
     * final dibits in the high bits (right-shifting ISR), inserting a gap in
     * the decoded frame. Sixteen injected null dibits guarantee one aligned
     * autopush while DMA still drains the RX FIFO. CRC ignores trailing zeros.
     * Timing and FIFO behavior still require hardware qualification. */
    if (dma_hw->ch[g_dma].transfer_count != 0) {
        for (unsigned i = 0; i < 16; i++)
            pio_sm_exec(RX_PIO, RX_SM, pio_encode_in(pio_null, 2));
    } else ++g_dma_full;
    dma_channel_abort((uint) g_dma);
    ++g_isr_count;

    buffer     = g_active;
    write_addr = (uintptr_t) dma_hw->ch[g_dma].write_addr;
    start      = (uintptr_t) g_samples[buffer];
    end        = start + sizeof(g_samples[buffer]);
    g_slots[buffer].bytes =
        (write_addr > start && write_addr <= end) ? (uint32_t) (write_addr - start)
                                                  : 0u;
    g_slots[buffer].timestamp_us = timestamp_us;
    g_slots[buffer].order        = ++g_order;
    g_ready_mask |= (1u << buffer);

    other = buffer ^ 1u;
    if ((g_ready_mask & (1u << other)) == 0u)
    {
        arm_buffer(other); /* IRQ entry delay still contributes to blind time. */
    }
    else
    {
        g_armed = false; /* both buffers wait for decode */
        ++g_overruns;
    }
    return true;
}

bool
rmii_hw_next_capture (rmii_hw_capture_t * capture)
{
    uint32_t saved  = 0u;
    uint32_t mask   = 0u;
    uint32_t buffer = 0u;

    if (capture == NULL)
    {
        return false;
    }
    saved = save_and_disable_interrupts();
    mask  = g_ready_mask;
    if (mask == 0u)
    {
        restore_interrupts(saved);
        return false;
    }
    if (mask == 3u)
    {
        /* At most two consecutive completions are pending. Serial arithmetic
         * keeps their order correct when the 32-bit completion count wraps. */
        buffer = (int32_t)(g_slots[0].order - g_slots[1].order) < 0 ? 0u : 1u;
    }
    else
    {
        buffer = (mask == 1u) ? 0u : 1u;
    }
    capture->buffer       = (uint8_t) buffer;
    capture->samples      = g_samples[buffer];
    capture->word_count   = g_slots[buffer].bytes / sizeof(uint32_t);
    capture->timestamp_us = g_slots[buffer].timestamp_us;
    restore_interrupts(saved);
    if (capture->word_count < RX_MIN_CAPTURE_WORDS)
    {
        capture->word_count = 0u;
    }
    return true;
}

void
rmii_hw_release_capture (uint8_t buffer)
{
    if (buffer >= RMII_HW_BUFFER_COUNT) return;
    const uint32_t saved = save_and_disable_interrupts();

    if ((g_ready_mask & (1u << buffer)) == 0u) {
        restore_interrupts(saved);
        return;
    }
    g_ready_mask &= ~(1u << buffer);
    if (!g_armed)
    {
        arm_buffer(buffer);
    }
    restore_interrupts(saved);
}

uint32_t
rmii_hw_isr_count (void)
{
    return g_isr_count;
}

uint32_t
rmii_hw_overrun_count (void)
{
    return g_overruns;
}

uint32_t rmii_hw_dma_full_count(void)
{
    return g_dma_full;
}
#endif /* !MONITOR_SYNTHETIC */
