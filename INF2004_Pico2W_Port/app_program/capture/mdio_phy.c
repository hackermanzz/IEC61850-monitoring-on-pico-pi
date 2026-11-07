/** @file mdio_phy.c
 * @brief Clause 22 management for the confirmed LAN8720 wires.
 *
 * MDC clocks management bits; MDIO carries management commands and replies.
 * Neither wire carries Ethernet packets. MDIO is driven low or released so
 * the PHY can safely take ownership during a read. One task owns this module.
 */
#include "mdio_phy.h"

#include <stddef.h>        /* NULL validates caller-owned outputs. */
#include "hardware/gpio.h" /* GPIO latch, direction and input access. */
#include "pico/time.h"     /* Busy waits work before the scheduler. */

#ifdef PICO_ON_DEVICE
#include "pico/binary_info.h" /* Inspect actual pin use with picotool. */
#endif

#define MDIO_PIN                  2u
#define MDC_PIN                   3u
#define MDIO_HALF_PERIOD_US       1u
#define MDIO_WRITE_HALF_PERIOD_US 10u
#define MDIO_PREAMBLE_BITS        32u
#define MDIO_START_BITS           2u
#define MDIO_START_VALUE          1u
#define MDIO_OPCODE_BITS          2u
#define MDIO_READ_OPCODE          2u
#define MDIO_ADDRESS_BITS         5u
#define MDIO_DATA_BITS            16u
#define MDIO_ID1_ADDRESS          2u
#define MDIO_ID2_ADDRESS          3u
#define MDIO_LAN8720_ID1          0x0007u
#define MDIO_LAN8720_ID2_MASK     0xfff0u
#define MDIO_LAN8720_ID2          0xc0f0u

static bool     gb_initialized = false;
static bool     gb_verify_release;
static bool     gb_write_line_ok;
static uint32_t g_half_period_us = MDIO_HALF_PERIOD_US;

#ifdef PICO_ON_DEVICE
bi_decl(bi_1pin_with_name(MDIO_PIN, "LAN8720 MDIO (released or low)"));
bi_decl(bi_1pin_with_name(MDC_PIN, "LAN8720 MDC (management clock)"));
#endif

/* Private wire primitives; one owner serializes complete transactions. */
static void mdio_phy_write_bit(bool b_is_high);
static bool mdio_phy_read_bit(void);
static void mdio_phy_send_bits(uint32_t value, uint32_t bit_count);
static void mdio_phy_idle(void);

void
mdio_phy_init (void)
{
    gpio_init(MDIO_PIN);
    gpio_set_dir(MDIO_PIN, GPIO_IN);
    gpio_pull_up(MDIO_PIN);

    gpio_init(MDC_PIN);
    gpio_put(MDC_PIN, true);
    gpio_set_dir(MDC_PIN, GPIO_OUT);
    gb_initialized = true;
    mdio_phy_idle();
}

bool
mdio_phy_read (uint8_t phy_addr, uint8_t reg_addr, uint16_t * p_value)
{
    bool     b_acknowledged = false;
    uint32_t bit_index      = 0u;
    uint16_t value          = 0u;

    if ((gb_initialized) && (NULL != p_value)
        && (MDIO_PHY_ADDRESS_COUNT > phy_addr)
        && (MDIO_PHY_ADDRESS_COUNT > reg_addr))
    {
        mdio_phy_send_bits(UINT32_MAX, MDIO_PREAMBLE_BITS);
        mdio_phy_send_bits(MDIO_START_VALUE, MDIO_START_BITS);
        mdio_phy_send_bits(MDIO_READ_OPCODE, MDIO_OPCODE_BITS);
        mdio_phy_send_bits(phy_addr, MDIO_ADDRESS_BITS);
        mdio_phy_send_bits(reg_addr, MDIO_ADDRESS_BITS);

        /* Turnaround is Z then zero. Never drive zero for the PHY ACK. */
        (void) mdio_phy_read_bit();
        b_acknowledged = !mdio_phy_read_bit();

        /* Finish clocking even without ACK, then release ownership. */
        for (bit_index = 0u; MDIO_DATA_BITS > bit_index; bit_index++)
        {
            /* The shift retains exactly the 16 wire bits, MSB first. */
            value = (uint16_t) ((uint32_t) value << 1u);
            if (mdio_phy_read_bit())
            {
                value |= 1u;
            }
        }

        /* An idle clock lets the PHY release its final data bit. */
        (void) mdio_phy_read_bit();
        mdio_phy_idle();
        if (b_acknowledged)
        {
            *p_value = value;
        }
    }

    return b_acknowledged;
}

bool
mdio_phy_write (uint8_t phy_addr, uint8_t reg_addr, uint16_t value)
{
    bool b_valid = gb_initialized && (32u > phy_addr) && (32u > reg_addr);

    if (b_valid)
    {
        /* Check that released ones reach high before their rising edge.
         * Slow writes allow more pull-up settling; no PHY write ACK exists.
         */
        gb_verify_release = true;
        gb_write_line_ok  = true;
        g_half_period_us  = MDIO_WRITE_HALF_PERIOD_US;
        mdio_phy_send_bits(UINT32_MAX, MDIO_PREAMBLE_BITS);
        mdio_phy_send_bits(MDIO_START_VALUE, MDIO_START_BITS);
        mdio_phy_send_bits(1u, MDIO_OPCODE_BITS); /* Write opcode is 01. */
        mdio_phy_send_bits(phy_addr, MDIO_ADDRESS_BITS);
        mdio_phy_send_bits(reg_addr, MDIO_ADDRESS_BITS);
        mdio_phy_send_bits(2u, 2u); /* Station owns turnaround: 10. */
        mdio_phy_send_bits(value, MDIO_DATA_BITS);
        (void) mdio_phy_read_bit();
        mdio_phy_idle();
        b_valid           = gb_write_line_ok;
        gb_verify_release = false;
        g_half_period_us  = MDIO_HALF_PERIOD_US;
    }
    return b_valid;
}

bool
mdio_phy_identify (uint8_t phy_addr, mdio_phy_id_t * p_identity)
{
    bool          b_found  = false;
    mdio_phy_id_t identity = {0u, 0u, 0u, false};

    if (NULL != p_identity)
    {
        identity.address = phy_addr;
        if (mdio_phy_read(phy_addr, MDIO_ID1_ADDRESS, &identity.id1))
        {
            b_found = mdio_phy_read(phy_addr, MDIO_ID2_ADDRESS, &identity.id2);
        }

        if (b_found)
        {
            identity.b_is_lan8720 =
                (MDIO_LAN8720_ID1 == identity.id1)
                && (MDIO_LAN8720_ID2 == (identity.id2 & MDIO_LAN8720_ID2_MASK));
            *p_identity = identity;
        }
    }

    return b_found;
}

/** @brief Send one bit with a full low setup and high hold interval. */
static void
mdio_phy_write_bit (bool b_is_high)
{
    gpio_put(MDC_PIN, false);
    if (b_is_high)
    {
        gpio_set_dir(MDIO_PIN, GPIO_IN);
    }
    else
    {
        /* Set the latch before enabling output to avoid a high glitch. */
        gpio_put(MDIO_PIN, false);
        gpio_set_dir(MDIO_PIN, GPIO_OUT);
    }

    busy_wait_us_32(g_half_period_us);
    if (gb_verify_release && b_is_high && (!gpio_get(MDIO_PIN)))
    {
        gb_write_line_ok = false;
    }
    gpio_put(MDC_PIN, true);
    busy_wait_us_32(g_half_period_us);
}

/** @brief Sample the settled low phase before advancing the rising edge. */
static bool
mdio_phy_read_bit (void)
{
    bool b_is_high = false;

    gpio_set_dir(MDIO_PIN, GPIO_IN);
    gpio_put(MDC_PIN, false);
    busy_wait_us_32(g_half_period_us);
    b_is_high = gpio_get(MDIO_PIN);
    gpio_put(MDC_PIN, true);
    busy_wait_us_32(g_half_period_us);

    return b_is_high;
}

/** @brief Send a field most-significant bit first; counts are private. */
static void
mdio_phy_send_bits (uint32_t value, uint32_t bit_count)
{
    uint32_t remaining = bit_count;

    /* Bound the shift even if a future private call supplies a bad count. */
    if (MDIO_PREAMBLE_BITS >= bit_count)
    {
        while (0u < remaining)
        {
            remaining--;
            mdio_phy_write_bit(0u != ((value >> remaining) & 1u));
        }
    }
}

/** @brief Release MDIO and leave MDC high between transactions. */
static void
mdio_phy_idle (void)
{
    gpio_set_dir(MDIO_PIN, GPIO_IN);
    gpio_put(MDC_PIN, true);
    busy_wait_us_32(g_half_period_us);
}

/*** end of file ***/
