/** @file rmii_capture_hw.c
 *
 * @brief Hardware layer of the RMII capture for the micro T-Kernel 3 SMP
 * build: LAN8720 management over MDIO, and frame reception with PIO0, one
 * DMA channel and two sample buffers.
 *
 * @par
 * Ported from rmii_ethernet.c (Sandeep Mistry, BSD-3-Clause):
 * - receive only: the TX program, TX DMA channel and TX buffers are gone;
 * - no lwIP netif and no SDK critical_section (the kernel owns spin locks
 *   0 to 2);
 * - two sample buffers, so the receiver is re-armed inside the ISR.
 */

#include "../monitor_config.h"

#if !MONITOR_SYNTHETIC

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// NOTE: Pico SDK 2.x pio.h leaves a parameter unused when parameter checks
// are off, which -Werror in the template build would turn into an error.
// The warning is silenced for the SDK headers only.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "hardware/dma.h"
#include "hardware/gpio.h"
#include "hardware/pio.h"
#include "hardware/structs/io_bank0.h"
#include "hardware/structs/timer.h"
#include "hardware/sync.h"
#include "rmii_ethernet_phy_rx.pio.h"
#pragma GCC diagnostic pop

#include "rmii_capture_hw.h"

// Receive buffers: 62400 samples at 50 MS/s (125 MHz / 2.5) cover 1.25 ms,
// enough for a maximum size frame at 10 Mbps. 16 samples per 32-bit word.
//
#define RX_SAMPLE_WORDS      (3900u)
#define RX_MIN_CAPTURE_WORDS (4u)
#define RX_PIO               (pio0)
#define RX_SM                (0u)
#define RX_FLUSH_DIBITS      (16u)
#define RX_DIBIT_BITS        (2u)
#define BUFFER0_READY        (1u)
#define BOTH_BUFFERS_READY   (3u)

// RXD1 must be the pin after RXD0 for the PIO program.
//
#define RMII_RXD1_PIN (IS18_RMII_RXD0_PIN + 1u)

// Bits of rmii_capture_hw_phy_diag_t.io_levels.
//
#define IO_LEVEL_CRS_DV (1u)
#define IO_LEVEL_RXD0   (2u)
#define IO_LEVEL_RXD1   (4u)

// MDIO frame layout (IEEE 802.3 clause 22).
//
#define MDIO_PREAMBLE_BITS     (32u)
#define MDIO_ADDRESS_BITS      (5u)
#define MDIO_REGISTER_BITS     (5u)
#define MDIO_DATA_BITS         (16u)
#define MDIO_PHY_ADDRESS_COUNT (32u)
#define MDIO_HALF_PERIOD_US    (1u)

// LAN8720A registers and values.
//
#define MDIO_REG_CONTROL          (0u)
#define MDIO_REG_STATUS           (1u)
#define MDIO_REG_ID1              (2u)
#define MDIO_REG_ID2              (3u)
#define MDIO_REG_ADVERTISE        (4u)
#define MDIO_REG_PARTNER          (5u)
#define MDIO_REG_SPECIAL          (31u)
#define MDIO_CONTROL_RESET        (0x8000u)
#define MDIO_CONTROL_ANEG_RESTART (0x1200u)
#define MDIO_CONTROL_ANEG_ENABLE  (0x1000u)
#define MDIO_CONTROL_CHECK_MASK   (0x7D00u)
#define MDIO_ADVERTISE_10M_ONLY   (0x0061u)
#define MDIO_ADVERTISE_MASK       (0x01FFu)
#define MDIO_STATUS_LINK          (0x0004u)
#define MDIO_ID_UNDRIVEN          (0xFFFFu)
#define MDIO_LAN8720_ID1          (0x0007u)
#define MDIO_LAN8720_ID2          (0xC0F0u)
#define MDIO_MODEL_MASK           (0xFFF0u)
#define MDIO_RESET_POLL_LIMIT     (1000u)

// GPIO interrupt status layout: eight pins per register, four bits each.
//
#define GPIO_EVENTS_PER_REGISTER (8u)
#define GPIO_EVENT_FIELD_BITS    (4u)
#define GPIO_EVENT_FIELD_MASK    (0xFu)

// The cast is safe: the SDK's event flags are small positive values.
//
#define CRS_DV_FALL_EVENT ((uint32_t) GPIO_IRQ_EDGE_FALL)

#define TIMER_HIGH_WORD_SHIFT (32u)

// One finished sample buffer.
//
typedef struct
{
    uint32_t bytes;
    uint64_t timestamp_us;
    uint32_t order;
} sample_slot_t;

// WARNING: The ISR shares the data below with task-side code on the same
// core. Task-side code masks interrupts before touching it.
//
// NOTE: clang-format cannot align names after a trailing volatile
// (rule 3.2.a), so this block is aligned by hand.
// clang-format off
static uint32_t               g_samples[RMII_HW_BUFFER_COUNT][RX_SAMPLE_WORDS];
static sample_slot_t volatile g_slots[RMII_HW_BUFFER_COUNT];
static uint32_t volatile      g_ready_mask       = 0u; // Bit n: buffer n.
static uint32_t volatile      g_active_buffer    = 0u;
static bool volatile          gb_armed           = false;
static uint32_t volatile      g_completion_order = 0u;
static uint32_t volatile      g_isr_count        = 0u;
static uint32_t volatile      g_overrun_count    = 0u;
static uint32_t volatile      g_dma_full_count   = 0u;
static uint volatile          g_pio_offset       = 0u;
static int volatile           g_dma_channel      = -1;
static uint32_t               g_phy_address      = 0u;
// clang-format on

// NOTE: Written only by rmii_capture_hw_rx_start() before the interrupt is
// enabled and never changed afterwards, so it need not be volatile.
//
static dma_channel_config g_dma_config;

static void     delay_us(uint32_t microseconds);
static void     mdio_clock_out(uint32_t bit);
static uint32_t mdio_clock_in(void);
static void     mdio_send_bits(uint32_t value, uint32_t bit_count);
static void     mdio_send_header(uint32_t address, uint32_t reg, bool b_read);
static uint16_t mdio_read(uint32_t address, uint32_t reg);
static void     mdio_write(uint32_t address, uint32_t reg, uint16_t value);
static bool     phy_find(void);
static bool     phy_reset(void);
static bool     phy_is_resetting(void);
static bool     phy_configure(void);
static uint16_t read_io_levels(void);
static void     rx_configure(void);
static void     arm_buffer(uint32_t buffer);
static uint32_t select_oldest_buffer(uint32_t ready_mask);
static bool     crs_dv_fell(void);
static void     rx_stop(void);
static void     complete_buffer(uint64_t timestamp_us);

/*!
 * @brief Find and configure the LAN8720 PHY.
 *
 * @par
 * Scans MDIO addresses 0 to 31 for the LAN8720 identity (the silicon
 * revision is ignored), resets the PHY, advertises 10 Mbps only and restarts
 * auto-negotiation, reading each step back.
 *
 * @param[out] p_phy_address Receives the PHY address on success; may be NULL.
 *
 * @return False if the PHY is absent or has the wrong identity, does not
 *         acknowledge, does not finish its reset, or reads back a wrong mode.
 */
bool
rmii_capture_hw_phy_init (uint32_t * p_phy_address)
{
    bool b_ok = false;

    gpio_init(IS18_RMII_MDIO_PIN);
    gpio_init(IS18_RMII_MDC_PIN);
    gpio_set_dir(IS18_RMII_MDC_PIN, GPIO_OUT);
    gpio_set_dir(IS18_RMII_MDIO_PIN, GPIO_IN);

    if (phy_find())
    {
        b_ok = phy_reset() && phy_configure();
    }

    if (b_ok && (NULL != p_phy_address))
    {
        *p_phy_address = g_phy_address;
    }

    return (b_ok);
}

/*!
 * @brief Report whether the PHY has an Ethernet link.
 *
 * @return True if the link is up.
 */
bool
rmii_capture_hw_is_link_up (void)
{
    // The link status bit latches low: the first read clears the latch and
    // its value is not needed.
    (void) mdio_read(g_phy_address, MDIO_REG_STATUS);

    uint16_t const status = mdio_read(g_phy_address, MDIO_REG_STATUS);

    return (0u != (status & MDIO_STATUS_LINK));
}

/*!
 * @brief Read the PHY registers and pin levels for the health report.
 *
 * @par
 * Same task and core owner as the other MDIO calls. The pin levels are
 * instantaneous; they do not test the clock.
 *
 * @param[out] p_diag Receives the diagnostics; ignored if NULL.
 */
void
rmii_capture_hw_read_phy_diag (rmii_capture_hw_phy_diag_t * p_diag)
{
    if (NULL != p_diag)
    {
        p_diag->id1     = mdio_read(g_phy_address, MDIO_REG_ID1);
        p_diag->id2     = mdio_read(g_phy_address, MDIO_REG_ID2);
        p_diag->control = mdio_read(g_phy_address, MDIO_REG_CONTROL);

        // The status register latches low: the first read clears the latch
        // and its value is not needed.
        (void) mdio_read(g_phy_address, MDIO_REG_STATUS);
        p_diag->status    = mdio_read(g_phy_address, MDIO_REG_STATUS);
        p_diag->advertise = mdio_read(g_phy_address, MDIO_REG_ADVERTISE);
        p_diag->partner   = mdio_read(g_phy_address, MDIO_REG_PARTNER);
        p_diag->special   = mdio_read(g_phy_address, MDIO_REG_SPECIAL);
        p_diag->io_levels = read_io_levels();
    }
}

/*!
 * @brief Start the receiver: load the PIO program, claim the state machine
 *        and a DMA channel, enable the CRS_DV interrupt for this core only
 *        and arm buffer 0.
 *
 * @return True if the receiver started.
 */
bool
rmii_capture_hw_rx_start (void)
{
    bool b_started = false;

    if (pio_can_add_program(RX_PIO, &rmii_ethernet_phy_rx_data_program)
        && !pio_sm_is_claimed(RX_PIO, RX_SM))
    {
        pio_sm_claim(RX_PIO, RX_SM);

        // The cast is safe: pio_can_add_program() succeeded, so the offset
        // returned is valid and not negative.
        g_pio_offset =
            (uint) pio_add_program(RX_PIO, &rmii_ethernet_phy_rx_data_program);
        g_dma_channel = dma_claim_unused_channel(false);

        if (g_dma_channel < 0)
        {
            pio_remove_program(RX_PIO, &rmii_ethernet_phy_rx_data_program,
                               g_pio_offset);
            pio_sm_unclaim(RX_PIO, RX_SM);
        }
        else
        {
            rx_configure();
            b_started = true;
        }
    }

    return (b_started);
}

/*!
 * @brief Give the NVIC number of the GPIO bank interrupt (IO_IRQ_BANK0).
 *
 * @return The interrupt number.
 */
uint32_t
rmii_capture_hw_irq_number (void)
{
    // The cast is safe: IO_IRQ_BANK0 is a small, non-negative enum value.
    return ((uint32_t) IO_IRQ_BANK0);
}

/*!
 * @brief Task side: get the oldest finished capture.
 *
 * @param[out] p_capture Receives the capture.
 *
 * @return False if no capture is waiting or p_capture is NULL.
 */
bool
rmii_capture_hw_next_capture (rmii_capture_hw_capture_t * p_capture)
{
    bool b_found = false;

    if (NULL != p_capture)
    {
        uint32_t const saved = save_and_disable_interrupts();
        uint32_t const mask  = g_ready_mask;

        if (0u != mask)
        {
            uint32_t const buffer = select_oldest_buffer(mask);

            // The cast is safe: buffer is 0 or 1.
            p_capture->buffer       = (uint8_t) buffer;
            p_capture->p_samples    = g_samples[buffer];
            p_capture->word_count   = g_slots[buffer].bytes / sizeof(uint32_t);
            p_capture->timestamp_us = g_slots[buffer].timestamp_us;
            b_found                 = true;
        }

        restore_interrupts(saved);

        // A capture too short to hold a frame is reported without samples.
        if (b_found && (p_capture->word_count < RX_MIN_CAPTURE_WORDS))
        {
            p_capture->word_count = 0u;
        }
    }

    return (b_found);
}

/*!
 * @brief Task side: decoding of a buffer is done. Re-arms the receiver if it
 *        had to pause because both buffers were full.
 *
 * @param[in] buffer The buffer index from rmii_capture_hw_next_capture().
 */
void
rmii_capture_hw_release (uint8_t buffer)
{
    if (buffer < RMII_HW_BUFFER_COUNT)
    {
        uint32_t const saved      = save_and_disable_interrupts();
        uint32_t const buffer_bit = (1u << buffer);

        if (0u != (g_ready_mask & buffer_bit))
        {
            g_ready_mask &= ~buffer_bit;

            if (!gb_armed)
            {
                arm_buffer(buffer);
            }
        }

        restore_interrupts(saved);
    }
}

/*!
 * @brief Read the free-running 64-bit microsecond timer.
 *
 * @return Microseconds since boot.
 */
uint64_t
rmii_capture_hw_time_us (void)
{
    uint32_t high_first = 0u;
    uint32_t low        = 0u;
    uint32_t high       = 0u;

    // Read the raw timer without latching; retry if the high word changed
    // while the low word was read.
    do
    {
        high_first = timer_hw->timerawh;
        low        = timer_hw->timerawl;
        high       = timer_hw->timerawh;
    } while (high != high_first);

    // The cast widens the high word before shifting; no bits are lost.
    return ((((uint64_t) high) << TIMER_HIGH_WORD_SHIFT) | low);
}

/*!
 * @brief Count CRS_DV interrupts that ended a capture.
 *
 * @return The count.
 */
uint32_t
rmii_capture_hw_isr_count (void)
{
    return (g_isr_count);
}

/*!
 * @brief Count the times the receiver paused because both buffers were full.
 *
 * @return The count.
 */
uint32_t
rmii_capture_hw_overrun_count (void)
{
    return (g_overrun_count);
}

/*!
 * @brief Count the times the DMA buffer filled before the end-of-frame
 *        interrupt.
 *
 * @par
 * This means a possibly truncated frame, or trailing idle samples while
 * interrupt entry was delayed. It is not a lost-frame count.
 *
 * @return The count.
 */
uint32_t
rmii_capture_hw_dma_full_count (void)
{
    return (g_dma_full_count);
}

/*!
 * @brief Interrupt body for the CRS_DV falling edge (end of frame).
 *
 * @par
 * Called from the registered ISR in task_producer.c. Re-arms the receiver
 * into the other buffer when that buffer is free.
 *
 * @return True when a capture finished and the task must be woken.
 */
bool
rmii_capture_hw_isr (void)
{
    bool b_wake_task = false;

    if (crs_dv_fell())
    {
        gpio_acknowledge_irq(IS18_RMII_CRS_DV_PIN, GPIO_IRQ_EDGE_FALL);

        // Take the frame-end timestamp before any other work.
        uint64_t const timestamp_us = rmii_capture_hw_time_us();

        if (gb_armed)
        {
            rx_stop();
            complete_buffer(timestamp_us);
            b_wake_task = true;
        }
    }

    return (b_wake_task);
}

/*!
 * @brief Busy-wait for a number of microseconds.
 *
 * @param[in] microseconds The delay.
 */
static void
delay_us (uint32_t microseconds)
{
    uint64_t const end_us = rmii_capture_hw_time_us() + microseconds;

    while (rmii_capture_hw_time_us() < end_us)
    {
        // NOTE: Inline assembly is kept to this driver module (rule 1.1.c).
        __asm volatile("nop");
    }
}

/*!
 * @brief Drive one MDIO bit; the PHY latches it on the rising MDC edge.
 *
 * @param[in] bit The bit value, 0 or 1.
 */
static void
mdio_clock_out (uint32_t bit)
{
    gpio_put(IS18_RMII_MDC_PIN, false);
    gpio_put(IS18_RMII_MDIO_PIN, (0u != bit));

    // Data setup time before the PHY's rising-edge latch.
    delay_us(MDIO_HALF_PERIOD_US);
    gpio_put(IS18_RMII_MDC_PIN, true);
    delay_us(MDIO_HALF_PERIOD_US);
}

/*!
 * @brief Read one MDIO bit driven by the PHY.
 *
 * @return The bit value, 0 or 1.
 */
static uint32_t
mdio_clock_in (void)
{
    uint32_t bit = 0u;

    gpio_put(IS18_RMII_MDC_PIN, false);
    delay_us(MDIO_HALF_PERIOD_US);

    // NOTE: LAN8720A SMI output can change 0 to 300 ns after the rising MDC
    // edge. Read the bit already driven during this low phase, before
    // advancing it. Sampling after the following high-phase delay loses D15
    // and reads idle as D0: for example, ID 0007:c0f1 becomes 000f:81e3.
    if (gpio_get(IS18_RMII_MDIO_PIN))
    {
        bit = 1u;
    }

    gpio_put(IS18_RMII_MDC_PIN, true);
    delay_us(MDIO_HALF_PERIOD_US);

    return (bit);
}

/*!
 * @brief Send bits on MDIO, most significant bit first.
 *
 * @param[in] value     The bits to send, in the low bit_count bits.
 * @param[in] bit_count The number of bits to send.
 */
static void
mdio_send_bits (uint32_t value, uint32_t bit_count)
{
    for (uint32_t index = 0u; index < bit_count; ++index)
    {
        mdio_clock_out((value >> ((bit_count - 1u) - index)) & 1u);
    }
}

/*!
 * @brief Send the MDIO preamble, start, opcode, PHY address and register.
 *
 * @param[in] address The PHY address.
 * @param[in] reg     The register number.
 * @param[in] b_read  True for a read, false for a write.
 */
static void
mdio_send_header (uint32_t address, uint32_t reg, bool b_read)
{
    gpio_set_dir(IS18_RMII_MDIO_PIN, GPIO_OUT);

    for (uint32_t index = 0u; index < MDIO_PREAMBLE_BITS; ++index)
    {
        mdio_clock_out(1u);
    }

    // Start of frame is 01; the opcode is 10 for a read and 01 for a write.
    mdio_clock_out(0u);
    mdio_clock_out(1u);
    mdio_clock_out(b_read ? 1u : 0u);
    mdio_clock_out(b_read ? 0u : 1u);
    mdio_send_bits(address, MDIO_ADDRESS_BITS);
    mdio_send_bits(reg, MDIO_REGISTER_BITS);
}

/*!
 * @brief Read a PHY register.
 *
 * @param[in] address The PHY address.
 * @param[in] reg     The register number.
 *
 * @return The register value, or 0xFFFF if the PHY did not acknowledge.
 */
static uint16_t
mdio_read (uint32_t address, uint32_t reg)
{
    uint32_t data = 0u;

    mdio_send_header(address, reg, true);

    // Turnaround: release the bus, then expect Z followed by the PHY's 0.
    gpio_set_dir(IS18_RMII_MDIO_PIN, GPIO_IN);
    mdio_clock_out(0u);

    bool const b_acknowledged = (0u == mdio_clock_in());

    // Always clock all 16 data bits, even without an acknowledgment, so the
    // bus is released and the next transaction stays aligned.
    for (uint32_t index = 0u; index < MDIO_DATA_BITS; ++index)
    {
        data = (data << 1u) | mdio_clock_in();
    }

    // The cast is safe: exactly 16 bits were shifted in.
    return (b_acknowledged ? (uint16_t) data : MDIO_ID_UNDRIVEN);
}

/*!
 * @brief Write a PHY register.
 *
 * @param[in] address The PHY address.
 * @param[in] reg     The register number.
 * @param[in] value   The value to write.
 */
static void
mdio_write (uint32_t address, uint32_t reg, uint16_t value)
{
    mdio_send_header(address, reg, false);

    // Turnaround: 10.
    mdio_clock_out(1u);
    mdio_clock_out(0u);
    mdio_send_bits(value, MDIO_DATA_BITS);
    gpio_set_dir(IS18_RMII_MDIO_PIN, GPIO_IN);
}

/*!
 * @brief Scan all MDIO addresses for a LAN8720.
 *
 * @return True if found; the address is kept in g_phy_address.
 */
static bool
phy_find (void)
{
    bool b_found = false;

    for (uint32_t address = 0u; (address < MDIO_PHY_ADDRESS_COUNT) && !b_found;
         ++address)
    {
        uint16_t const id1 = mdio_read(address, MDIO_REG_ID1);
        uint16_t const id2 = mdio_read(address, MDIO_REG_ID2);

        // The low nibble of ID2 is the silicon revision, which is ignored.
        if ((MDIO_LAN8720_ID1 == id1)
            && (MDIO_LAN8720_ID2 == (id2 & MDIO_MODEL_MASK)))
        {
            g_phy_address = address;
            b_found       = true;
        }
    }

    return (b_found);
}

/*!
 * @brief Reset the PHY through its control register.
 *
 * @return True if the reset finished within the poll limit.
 */
static bool
phy_reset (void)
{
    uint32_t polls = 0u;

    // NOTE: A software reset replaces the nRST pin, which the module does
    // not expose.
    mdio_write(g_phy_address, MDIO_REG_CONTROL, MDIO_CONTROL_RESET);

    while (phy_is_resetting() && (polls < MDIO_RESET_POLL_LIMIT))
    {
        ++polls;
    }

    return (polls < MDIO_RESET_POLL_LIMIT);
}

/*!
 * @brief Report whether the PHY reset bit is still set.
 *
 * @return True while the PHY is resetting.
 */
static bool
phy_is_resetting (void)
{
    uint16_t const control = mdio_read(g_phy_address, MDIO_REG_CONTROL);

    return (0u != (control & MDIO_CONTROL_RESET));
}

/*!
 * @brief Advertise 10 Mbps only and restart auto-negotiation.
 *
 * @return True if both settings read back correctly.
 */
static bool
phy_configure (void)
{
    bool b_ok = false;

    // NOTE: The decoder timing supports 10 Mbps only. CRS_DV can toggle
    // while receive data drains at either speed (LAN8720A datasheet,
    // section 3.4.1.1); the first-fall end-of-frame approach remains a
    // hardware qualification limitation.
    mdio_write(g_phy_address, MDIO_REG_ADVERTISE, MDIO_ADVERTISE_10M_ONLY);

    if (MDIO_ADVERTISE_10M_ONLY
        == (mdio_read(g_phy_address, MDIO_REG_ADVERTISE) & MDIO_ADVERTISE_MASK))
    {
        mdio_write(g_phy_address, MDIO_REG_CONTROL, MDIO_CONTROL_ANEG_RESTART);

        // Ignore the self-clearing restart bit. Check that auto-negotiation
        // is on and that loopback, forced speed, power-down, isolate and
        // forced duplex are all off.
        b_ok = (MDIO_CONTROL_ANEG_ENABLE
                == (mdio_read(g_phy_address, MDIO_REG_CONTROL)
                    & MDIO_CONTROL_CHECK_MASK));
    }

    return (b_ok);
}

/*!
 * @brief Read the instantaneous levels of CRS_DV, RXD0 and RXD1.
 *
 * @return The levels as IO_LEVEL_* bits.
 */
static uint16_t
read_io_levels (void)
{
    uint32_t levels = 0u;

    if (gpio_get(IS18_RMII_CRS_DV_PIN))
    {
        levels |= IO_LEVEL_CRS_DV;
    }

    if (gpio_get(IS18_RMII_RXD0_PIN))
    {
        levels |= IO_LEVEL_RXD0;
    }

    if (gpio_get(RMII_RXD1_PIN))
    {
        levels |= IO_LEVEL_RXD1;
    }

    // The cast is safe: only the three low bits can be set.
    return ((uint16_t) levels);
}

/*!
 * @brief Configure DMA and PIO for reception, arm buffer 0 and enable the
 *        CRS_DV falling-edge interrupt.
 */
static void
rx_configure (void)
{
    // The casts are safe: rmii_capture_hw_rx_start() checked that the
    // channel number is not negative.
    g_dma_config = dma_channel_get_default_config((uint) g_dma_channel);
    channel_config_set_read_increment(&g_dma_config, false);
    channel_config_set_write_increment(&g_dma_config, true);
    channel_config_set_dreq(&g_dma_config, pio_get_dreq(RX_PIO, RX_SM, false));
    channel_config_set_transfer_data_size(&g_dma_config, DMA_SIZE_32);

    // Set pins, shifting, FIFO join and the clock divider (clk_sys to
    // 50 MHz). This also starts the state machine, so stop it until
    // arm_buffer().
    rmii_ethernet_phy_rx_init(RX_PIO, RX_SM, g_pio_offset, IS18_RMII_RXD0_PIN,
                              IS18_RMII_CRS_DV_PIN);
    pio_sm_set_enabled(RX_PIO, RX_SM, false);

    g_ready_mask = 0u;

    uint32_t const saved = save_and_disable_interrupts();

    arm_buffer(0u);

    // NOTE: gpio_set_irq_enabled() writes the INTE register of the calling
    // core, so running this on core 1 keeps CRS_DV away from core 0.
    gpio_set_irq_enabled(IS18_RMII_CRS_DV_PIN, GPIO_IRQ_EDGE_FALL, true);
    restore_interrupts(saved);
}

/*!
 * @brief Restart the sampler at the start of its program (wait for idle,
 *        then carrier) and point the DMA at one buffer.
 *
 * @par
 * Interrupts must be masked, or the caller must be the ISR.
 *
 * @param[in] buffer The buffer index, 0 or 1.
 */
static void
arm_buffer (uint32_t buffer)
{
    pio_sm_set_enabled(RX_PIO, RX_SM, false);
    pio_sm_clear_fifos(RX_PIO, RX_SM);
    pio_sm_restart(RX_PIO, RX_SM);
    pio_sm_exec(RX_PIO, RX_SM, pio_encode_jmp(g_pio_offset));

    // The cast is safe: the channel was claimed, so it is not negative.
    dma_channel_configure((uint) g_dma_channel, &g_dma_config,
                          g_samples[buffer], &RX_PIO->rxf[RX_SM],
                          RX_SAMPLE_WORDS, true);
    g_active_buffer = buffer;
    gb_armed        = true;
    pio_sm_set_enabled(RX_PIO, RX_SM, true);
}

/*!
 * @brief Choose the buffer that finished first.
 *
 * @param[in] ready_mask The ready bits, not 0.
 *
 * @return The buffer index, 0 or 1.
 */
static uint32_t
select_oldest_buffer (uint32_t ready_mask)
{
    uint32_t buffer = 1u;

    if (BOTH_BUFFERS_READY == ready_mask)
    {
        // At most two completions are pending. Serial-number arithmetic keeps
        // their order correct when the 32-bit completion count wraps. The
        // cast reads the unsigned difference as signed, which is intended.
        int32_t const age = (int32_t) (g_slots[0].order - g_slots[1].order);

        if (age < 0)
        {
            buffer = 0u;
        }
    }
    else if (BUFFER0_READY == ready_mask)
    {
        buffer = 0u;
    }
    else
    {
        // Only buffer 1 is ready.
    }

    return (buffer);
}

/*!
 * @brief Check this core's interrupt status for a CRS_DV falling edge.
 *
 * @return True if a falling edge is pending.
 */
static bool
crs_dv_fell (void)
{
    uint32_t const                 pin = IS18_RMII_CRS_DV_PIN;
    io_bank0_irq_ctrl_hw_t * const p_irq_ctrl =
        (0u == get_core_num()) ? &io_bank0_hw->proc0_irq_ctrl
                               : &io_bank0_hw->proc1_irq_ctrl;
    uint32_t const events =
        (p_irq_ctrl->ints[pin / GPIO_EVENTS_PER_REGISTER]
         >> (GPIO_EVENT_FIELD_BITS * (pin % GPIO_EVENTS_PER_REGISTER)))
        & GPIO_EVENT_FIELD_MASK;

    return (0u != (events & CRS_DV_FALL_EVENT));
}

/*!
 * @brief Stop the sampler and the DMA at the end of a frame.
 */
static void
rx_stop (void)
{
    pio_sm_set_enabled(RX_PIO, RX_SM, false);

    // Finish the partial shift word with zeros. A plain PUSH would leave the
    // final dibits in the high bits (the shift register shifts right),
    // inserting a gap in the decoded frame. Sixteen injected null dibits
    // guarantee one aligned autopush while DMA still drains the RX FIFO.
    // The CRC ignores trailing zeros.
    // WARNING: Timing and FIFO behavior still require hardware
    // qualification.
    if (0u != dma_hw->ch[g_dma_channel].transfer_count)
    {
        for (uint32_t dibit = 0u; dibit < RX_FLUSH_DIBITS; ++dibit)
        {
            pio_sm_exec(RX_PIO, RX_SM, pio_encode_in(pio_null, RX_DIBIT_BITS));
        }
    }
    else
    {
        ++g_dma_full_count;
    }

    // The cast is safe: the channel was claimed, so it is not negative.
    dma_channel_abort((uint) g_dma_channel);
}

/*!
 * @brief Record a finished buffer and re-arm into the other buffer if it is
 *        free.
 *
 * @param[in] timestamp_us The frame end time.
 */
static void
complete_buffer (uint64_t timestamp_us)
{
    uint32_t const buffer = g_active_buffer;

    // The casts turn addresses into integers to compute the byte count.
    uintptr_t const write_addr =
        (uintptr_t) dma_hw->ch[g_dma_channel].write_addr;
    uintptr_t const start = (uintptr_t) g_samples[buffer];
    uintptr_t const end   = start + sizeof(g_samples[buffer]);
    uint32_t        bytes = 0u;

    ++g_isr_count;

    if ((write_addr > start) && (write_addr <= end))
    {
        // The cast is safe: the difference is at most one buffer's size.
        bytes = (uint32_t) (write_addr - start);
    }

    g_completion_order++;
    g_slots[buffer].bytes        = bytes;
    g_slots[buffer].timestamp_us = timestamp_us;
    g_slots[buffer].order        = g_completion_order;
    g_ready_mask |= (1u << buffer);

    uint32_t const other = buffer ^ 1u;

    if (0u == (g_ready_mask & (1u << other)))
    {
        // NOTE: The interrupt entry delay still adds to the blind time.
        arm_buffer(other);
    }
    else
    {
        // Both buffers wait for decoding; rmii_capture_hw_release() re-arms.
        gb_armed = false;
        ++g_overrun_count;
    }
}

#endif /* !MONITOR_SYNTHETIC */

/*** end of file ***/
