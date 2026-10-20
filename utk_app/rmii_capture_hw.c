/*
 * rmii_capture_hw.c  (owner: Buddy 2, Jonathan)
 * Hardware layer of the RMII capture for the µT-Kernel 3 SMP build.
 * Ported from rmii/src/rmii_ethernet.c (Sandeep Mistry, BSD-3-Clause):
 *   - receive only: the TX program, TX DMA channel and TX buffers are gone;
 *   - no lwIP netif and no SDK critical_section (kernel owns spin locks 0-2);
 *   - two sample buffers so the receiver is re-armed inside the ISR.
 */
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
#define MDIO_CONTROL_RESET       (0x8000u)
#define MDIO_CONTROL_ANEG_RESTART (0x1200u)
#define MDIO_ADVERTISE_10M_ONLY  (0x0061u)
#define MDIO_STATUS_LINK         (0x0004u)
#define MDIO_ID_UNDRIVEN         (0xFFFFu)
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
    delay_us(1u);
    gpio_put(IS18_RMII_MDIO_PIN, bit != 0u);
    gpio_put(IS18_RMII_MDC_PIN, 1);
    delay_us(1u);
}

static uint32_t
mdio_clock_in (void)
{
    uint32_t bit = 0u;

    gpio_put(IS18_RMII_MDC_PIN, 0);
    delay_us(1u);
    gpio_put(IS18_RMII_MDC_PIN, 1);
    bit = gpio_get(IS18_RMII_MDIO_PIN) ? 1u : 0u;
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
    mdio_clock_out(0u);
    for (index = 0u; index < MDIO_DATA_BITS; ++index)
    {
        data = (uint16_t) ((data << 1u) | mdio_clock_in());
    }
    return data;
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
        if (id1 != 0u && id1 != MDIO_ID_UNDRIVEN && id2 != 0u &&
            id2 != MDIO_ID_UNDRIVEN)
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
    /* 10 Mbps only: at 100 Mbps CRS_DV toggles at frame end and the
     * sampler would treat each toggle as a new frame. */
    mdio_write(g_phy_address, MDIO_REG_ADVERTISE, MDIO_ADVERTISE_10M_ONLY);
    mdio_write(g_phy_address, MDIO_REG_CONTROL, MDIO_CONTROL_ANEG_RESTART);
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
    io_bank0_irq_ctrl_hw_t * const irq_ctrl = &io_bank0_hw->proc1_irq_ctrl;
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
        arm_buffer(other); /* receiver blind only for the ISR itself */
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
        buffer = (g_slots[0].order < g_slots[1].order) ? 0u : 1u; /* oldest */
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
    const uint32_t saved = save_and_disable_interrupts();

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
