/** @file sd_spi.c
 * @brief SPI-mode SD block I/O. Card data uses DMA; control stays with S1.
 * No capture-channel reuse, DMA IRQ handler, formatting or unbounded waits.
 */
#include "sd_spi.h"
#include <stddef.h>
#include <stdatomic.h>
#include "hardware/dma.h"
#include "hardware/gpio.h"
#include "hardware/spi.h"
#include "hardware/regs/dma.h"
#include "hardware/sync.h"
#include "pico/time.h"
#include "tk/tkernel.h"
#include "sd_crc.h"

#ifndef SD_PINS_CONFIGURED
#define SD_PINS_CONFIGURED (0)
#endif
#define SD_SPI_CLOCK_PIN       (10u)
#define SD_SPI_MOSI_PIN        (11u)
#define SD_SPI_MISO_PIN        (12u)
#define SD_SPI_DAT1_PIN        (13u)
#define SD_SPI_DAT2_PIN        (14u)
#define SD_SPI_CS_PIN          (15u)
#define SD_SPI_SECTOR_BYTES    (512u)
#define SD_SPI_BYTE_TIMEOUT_US (2000u)
#define SD_SPI_DATA_TIMEOUT_US (250000u)
#define SD_SPI_BUSY_TIMEOUT_US (1000000u)

/* A runtime read keeps the complete driver/filesystem in disabled builds so
 * their full reservations are still budgeted. No setter can enable it later.
 * The proposed SPI mapping must be explicitly selected by the build runner.
 */
static const volatile bool gb_configured = (0 != SD_PINS_CONFIGURED);
static atomic_uint         g_error       = SD_SPI_DISABLED;
static atomic_uint         g_timeouts;
static atomic_uint         g_timeout_context;
static uint32_t            g_command;
static int                 g_tx    = -1;
static int                 g_rx    = -1;
static uint8_t             g_dummy = 0xffu;
static uint8_t             g_discard;
static uint32_t            g_sector_count;
static bool                gb_block_addressed;
static bool                gb_ready;
static bool                gb_io_started;

static bool    sd_spi_byte(uint8_t output, uint8_t * p_input);
static bool    sd_spi_wait_ready(uint32_t timeout_us);
static uint8_t sd_spi_command(uint8_t command, uint32_t argument);
static void    sd_spi_deselect(void);

bool
sd_spi_configured (void)
{
    return gb_configured;
}

sd_spi_error_t
sd_spi_error (void)
{
    return (sd_spi_error_t) atomic_load(&g_error);
}

static bool
sd_spi_fail (sd_spi_error_t error)
{
    if ((SD_SPI_PROTOCOL != error) || (SD_SPI_OK == atomic_load(&g_error)))
    {
        atomic_store(&g_error, (uint32_t) error);
    }
    if (gb_io_started)
    {
        gpio_put(SD_SPI_CS_PIN, true);
    }
    gb_ready = false;
    return false;
}

uint32_t
sd_spi_timeout_count (void)
{
    return atomic_load(&g_timeouts);
}

uint32_t
sd_spi_timeout_context (void)
{
    return atomic_load(&g_timeout_context);
}

static bool
sd_spi_timeout (uint32_t phase)
{
    /* Retain the last timeout across remounts, even when current error clears.
     * Low byte is command; high byte is phase. Only S1 writes command state.
     */
    if (SD_SPI_TIMEOUT != atomic_load(&g_error))
    {
        atomic_store(&g_timeout_context, (phase << 8u) | g_command);
        atomic_fetch_add(&g_timeouts, 1u);
    }
    return sd_spi_fail(SD_SPI_TIMEOUT);
}

static bool
sd_spi_byte (uint8_t output, uint8_t * p_input)
{
    uint64_t deadline = time_us_64() + SD_SPI_BYTE_TIMEOUT_US;
    while (!spi_is_writable(spi1))
    {
        /* S1 can be preempted after the first FIFO check. Check hardware
         * again AFTER reading time: an already completed byte is not a fault.
         * Keep interrupts/preemption enabled for capture, alarm and analysis.
         */
        if ((time_us_64() >= deadline) && (!spi_is_writable(spi1)))
        {
            return sd_spi_timeout(SD_SPI_TIMEOUT_TX);
        }
    }
    spi_get_hw(spi1)->dr = output;
    /* A preemption before the write must not spend the receive budget before
     * a byte was even launched. Each FIFO phase gets its own bounded wait.
     */
    deadline = time_us_64() + SD_SPI_BYTE_TIMEOUT_US;
    while (!spi_is_readable(spi1))
    {
        if ((time_us_64() >= deadline) && (!spi_is_readable(spi1)))
        {
            return sd_spi_timeout(SD_SPI_TIMEOUT_RX);
        }
    }
    *p_input = (uint8_t) spi_get_hw(spi1)->dr;
    return true;
}

static void
sd_spi_deselect (void)
{
    uint8_t unused = 0u;
    gpio_put(SD_SPI_CS_PIN, true);
    (void) sd_spi_byte(0xffu, &unused);
}

static bool
sd_spi_wait_ready (uint32_t timeout_us)
{
    uint64_t deadline = time_us_64() + timeout_us;
    uint8_t  value    = 0u;
    do
    {
        if (!sd_spi_byte(0xffu, &value))
        {
            return false;
        }
        if (0xffu == value)
        {
            return true;
        }
        /* Card internal programming needs no continuous CPU polling.
         * S1 sleeps; alarm/analysis/supervision are always higher priority.
         */
        if (time_us_64() >= deadline)
        {
            return sd_spi_timeout(SD_SPI_TIMEOUT_BUSY);
        }
        (void) tk_dly_tsk(1u);
    } while (true);
}

static uint8_t
sd_spi_command (uint8_t command, uint32_t argument)
{
    uint8_t bytes[6] = {
        (uint8_t) (0x40u | command), (uint8_t) (argument >> 24u),
        (uint8_t) (argument >> 16u), (uint8_t) (argument >> 8u),
        (uint8_t) argument,          0u};
    uint8_t value = 0xffu;
    g_command     = command;
    sd_spi_deselect();
    gpio_put(SD_SPI_CS_PIN, false);
    if (!sd_spi_wait_ready(SD_SPI_BUSY_TIMEOUT_US))
    {
        return 0xffu;
    }
    bytes[5] = sd_crc7(bytes, 5u);
    for (size_t index = 0u; sizeof(bytes) > index; index++)
    {
        if (!sd_spi_byte(bytes[index], &value))
        {
            return 0xffu;
        }
    }
    for (uint32_t attempt = 0u; 10u > attempt; attempt++)
    {
        if (!sd_spi_byte(0xffu, &value))
        {
            return 0xffu;
        }
        if (0u == (value & 0x80u))
        {
            return value;
        }
    }
    (void) sd_spi_fail(SD_SPI_PROTOCOL);
    return 0xffu;
}

static void
sd_spi_abort (void)
{
    /* RP2350-E5: disable EN before abort, as in the capture driver. These
     * channels are independently claimed; capture's channel/IRQ1 is untouched.
     */
    hw_clear_bits(&dma_channel_hw_addr((uint32_t) g_tx)->al1_ctrl,
                  DMA_CH0_CTRL_TRIG_EN_BITS);
    hw_clear_bits(&dma_channel_hw_addr((uint32_t) g_rx)->al1_ctrl,
                  DMA_CH0_CTRL_TRIG_EN_BITS);
    dma_channel_abort((uint32_t) g_tx);
    dma_channel_abort((uint32_t) g_rx);
}

static bool
sd_spi_dma_busy (void)
{
    return dma_channel_is_busy((uint32_t) g_rx)
        || dma_channel_is_busy((uint32_t) g_tx) || spi_is_busy(spi1);
}

static bool
sd_spi_transfer (uint8_t * p_read, const uint8_t * p_write, uint32_t length)
{
    dma_channel_config tx = dma_channel_get_default_config((uint32_t) g_tx);
    dma_channel_config rx = dma_channel_get_default_config((uint32_t) g_rx);
    uint64_t           deadline = time_us_64() + SD_SPI_DATA_TIMEOUT_US;
    channel_config_set_transfer_data_size(&tx, DMA_SIZE_8);
    channel_config_set_read_increment(&tx, NULL != p_write);
    channel_config_set_write_increment(&tx, false);
    channel_config_set_dreq(&tx, spi_get_dreq(spi1, true));
    channel_config_set_transfer_data_size(&rx, DMA_SIZE_8);
    channel_config_set_read_increment(&rx, false);
    channel_config_set_write_increment(&rx, NULL != p_read);
    channel_config_set_dreq(&rx, spi_get_dreq(spi1, false));
    dma_channel_configure((uint32_t) g_rx, &rx,
                          (NULL != p_read) ? p_read : &g_discard,
                          &spi_get_hw(spi1)->dr, length, false);
    dma_channel_configure((uint32_t) g_tx, &tx, &spi_get_hw(spi1)->dr,
                          (NULL != p_write) ? p_write : &g_dummy, length,
                          false);
    dma_start_channel_mask((1u << g_tx) | (1u << g_rx));
    while (sd_spi_dma_busy())
    {
        if ((time_us_64() >= deadline) && sd_spi_dma_busy())
        {
            sd_spi_abort();
            return sd_spi_timeout(SD_SPI_TIMEOUT_DMA);
        }
    }
    uint32_t errors = (dma_channel_hw_addr((uint32_t) g_tx)->ctrl_trig
                       | dma_channel_hw_addr((uint32_t) g_rx)->ctrl_trig)
                    & (DMA_CH0_CTRL_TRIG_READ_ERROR_BITS
                       | DMA_CH0_CTRL_TRIG_WRITE_ERROR_BITS);
    if (0u != errors)
    {
        return sd_spi_fail(SD_SPI_RESOURCE);
    }
    return true;
}

static bool
sd_spi_receive (uint8_t * p_data, uint32_t length)
{
    uint8_t  token    = 0xffu;
    uint8_t  high     = 0u;
    uint8_t  low      = 0u;
    uint64_t deadline = time_us_64() + SD_SPI_DATA_TIMEOUT_US;
    do
    {
        if (!sd_spi_byte(0xffu, &token))
        {
            return false;
        }
        if (0xfeu == token)
        {
            if ((!sd_spi_transfer(p_data, NULL, length))
                || (!sd_spi_byte(0xffu, &high)) || (!sd_spi_byte(0xffu, &low)))
            {
                return false;
            }
            if (sd_crc16(p_data, length) != ((uint16_t) high << 8u | low))
            {
                return sd_spi_fail(SD_SPI_CRC);
            }
            return true;
        }
        if (0xffu != token)
        {
            return sd_spi_fail(SD_SPI_PROTOCOL);
        }
    } while (time_us_64() < deadline);
    return sd_spi_timeout(SD_SPI_TIMEOUT_TOKEN);
}

bool
sd_spi_initialize (void)
{
    uint8_t  value       = 0u;
    uint8_t  response[4] = {0};
    uint8_t  csd[16]     = {0};
    uint64_t sectors     = 0u;
    uint64_t deadline    = 0u;
    bool     version2    = false;
    gb_ready             = false;
    if (!sd_spi_configured())
    {
        return sd_spi_fail(SD_SPI_DISABLED);
    }
    if (0 > g_tx)
    {
        g_tx = dma_claim_unused_channel(false);
        g_rx = dma_claim_unused_channel(false);
        if ((0 > g_tx) || (0 > g_rx))
        {
            if (0 <= g_tx)
            {
                dma_channel_unclaim((uint32_t) g_tx);
            }
            if (0 <= g_rx)
            {
                dma_channel_unclaim((uint32_t) g_rx);
            }
            g_tx = -1;
            g_rx = -1;
            return sd_spi_fail(SD_SPI_RESOURCE);
        }
        dma_channel_set_irq0_enabled((uint32_t) g_tx, false);
        dma_channel_set_irq0_enabled((uint32_t) g_rx, false);
        dma_channel_set_irq1_enabled((uint32_t) g_tx, false);
        dma_channel_set_irq1_enabled((uint32_t) g_rx, false);
    }
    spi_init(spi1, 400000u);
    spi_set_format(spi1, 8u, SPI_CPOL_0, SPI_CPHA_0, SPI_MSB_FIRST);
    gpio_set_function(SD_SPI_CLOCK_PIN, GPIO_FUNC_SPI);
    gpio_set_function(SD_SPI_MOSI_PIN, GPIO_FUNC_SPI);
    gpio_set_function(SD_SPI_MISO_PIN, GPIO_FUNC_SPI);
    gpio_pull_up(SD_SPI_MISO_PIN);
    /* Maker Pi Pico datasheet: unused SD data pins need pull-ups in SPI mode.
     * These pins remain part of the onboard socket and cannot be repurposed.
     * This code runs only after the configured-carrier gate above succeeds.
     */
    gpio_init(SD_SPI_DAT1_PIN);
    gpio_set_dir(SD_SPI_DAT1_PIN, GPIO_IN);
    gpio_pull_up(SD_SPI_DAT1_PIN);
    gpio_init(SD_SPI_DAT2_PIN);
    gpio_set_dir(SD_SPI_DAT2_PIN, GPIO_IN);
    gpio_pull_up(SD_SPI_DAT2_PIN);
    gpio_init(SD_SPI_CS_PIN);
    gpio_put(SD_SPI_CS_PIN, true);
    gpio_set_dir(SD_SPI_CS_PIN, GPIO_OUT);
    gb_io_started = true;
    atomic_store(&g_error, SD_SPI_OK);
    for (uint32_t count = 0u; 10u > count; count++)
    {
        if (!sd_spi_byte(0xffu, &value))
        {
            return false;
        }
    }
    if (1u != sd_spi_command(0u, 0u))
    {
        sd_spi_deselect();
        return sd_spi_fail(SD_SPI_PROTOCOL);
    }
    value = sd_spi_command(8u, 0x1aau);
    if (1u == value)
    {
        for (size_t index = 0u; 4u > index; index++)
        {
            if (!sd_spi_byte(0xffu, &response[index]))
            {
                return false;
            }
        }
        if ((1u != response[2]) || (0xaau != response[3]))
        {
            sd_spi_deselect();
            return sd_spi_fail(SD_SPI_PROTOCOL);
        }
        version2 = true;
    }
    else if (5u != value)
    {
        sd_spi_deselect();
        return sd_spi_fail(SD_SPI_PROTOCOL);
    }
    deadline = time_us_64() + 1500000u;
    do
    {
        value = sd_spi_command(55u, 0u);
        if (1u >= value)
        {
            value = sd_spi_command(41u, version2 ? 0x40000000u : 0u);
        }
        if (0u == value)
        {
            break;
        }
        if (1u != value)
        {
            break;
        }
        (void) tk_dly_tsk(10u);
    } while (time_us_64() < deadline);
    if ((0u != value) || (0u != sd_spi_command(58u, 0u)))
    {
        sd_spi_deselect();
        return sd_spi_fail(SD_SPI_PROTOCOL);
    }
    for (size_t index = 0u; 4u > index; index++)
    {
        if (!sd_spi_byte(0xffu, &response[index]))
        {
            return false;
        }
    }
    gb_block_addressed = version2 && (0u != (response[0] & 0x40u));
    if ((0u == (response[0] & 0x80u))
        || ((!gb_block_addressed) && (0u != sd_spi_command(16u, 512u)))
        || (0u != sd_spi_command(59u, 1u)) || (0u != sd_spi_command(9u, 0u))
        || (!sd_spi_receive(csd, 16u)))
    {
        sd_spi_deselect();
        return sd_spi_fail(SD_SPI_PROTOCOL);
    }
    if (1u == (csd[0] >> 6u))
    {
        sectors = (((uint64_t) (csd[7] & 0x3fu) << 16u)
                   | ((uint64_t) csd[8] << 8u) | csd[9])
                + 1u;
        sectors *= 1024u;
    }
    else if (0u == (csd[0] >> 6u))
    {
        uint32_t size = ((uint32_t) (csd[6] & 3u) << 10u)
                      | ((uint32_t) csd[7] << 2u) | (csd[8] >> 6u);
        uint32_t shift =
            (((csd[9] & 3u) << 1u) | (csd[10] >> 7u)) + 2u + (csd[5] & 15u);
        sectors = ((uint64_t) size + 1u) << shift;
        sectors >>= 9u;
    }
    sd_spi_deselect();
    if ((0u == sectors) || (UINT32_MAX < sectors)
        || ((!gb_block_addressed) && ((UINT32_MAX / 512u + 1u) < sectors)))
    {
        return sd_spi_fail(SD_SPI_RANGE);
    }
    g_sector_count = (uint32_t) sectors;
    spi_set_baudrate(spi1, 8000000u);
    gb_ready = true;
    atomic_store(&g_error, SD_SPI_OK);
    return true;
}

uint32_t
sd_spi_sectors (void)
{
    return gb_ready ? g_sector_count : 0u;
}

bool
sd_spi_read (uint8_t * p_data, uint32_t sector, uint32_t count)
{
    if ((!gb_ready) || (NULL == p_data) || (0u == count)
        || (sector >= g_sector_count) || (count > g_sector_count - sector))
    {
        return sd_spi_fail(SD_SPI_RANGE);
    }
    for (uint32_t index = 0u; count > index; index++)
    {
        uint32_t address = sector + index;
        if (!gb_block_addressed)
        {
            address *= 512u;
        }
        if ((0u != sd_spi_command(17u, address))
            || (!sd_spi_receive(&p_data[index * 512u], 512u)))
        {
            sd_spi_deselect();
            return sd_spi_fail(SD_SPI_PROTOCOL);
        }
    }
    sd_spi_deselect();
    return true;
}

bool
sd_spi_write (const uint8_t * p_data, uint32_t sector, uint32_t count)
{
    uint8_t value = 0u;
    if ((!gb_ready) || (NULL == p_data) || (0u == count)
        || (sector >= g_sector_count) || (count > g_sector_count - sector))
    {
        return sd_spi_fail(SD_SPI_RANGE);
    }
    for (uint32_t index = 0u; count > index; index++)
    {
        uint32_t        address = sector + index;
        const uint8_t * p_block = &p_data[index * 512u];
        uint16_t        crc     = sd_crc16(p_block, 512u);
        if (!gb_block_addressed)
        {
            address *= 512u;
        }
        if ((0u != sd_spi_command(24u, address))
            || (!sd_spi_byte(0xfeu, &value))
            || (!sd_spi_transfer(NULL, p_block, 512u))
            || (!sd_spi_byte((uint8_t) (crc >> 8u), &value))
            || (!sd_spi_byte((uint8_t) crc, &value))
            || (!sd_spi_byte(0xffu, &value)) || (5u != (value & 0x1fu))
            || (!sd_spi_wait_ready(SD_SPI_BUSY_TIMEOUT_US)))
        {
            sd_spi_deselect();
            return sd_spi_fail(SD_SPI_PROTOCOL);
        }
    }
    sd_spi_deselect();
    return true;
}

bool
sd_spi_sync (void)
{
    bool ready = false;
    if (gb_ready)
    {
        gpio_put(SD_SPI_CS_PIN, false);
        ready = sd_spi_wait_ready(SD_SPI_BUSY_TIMEOUT_US);
        sd_spi_deselect();
    }
    return ready;
}

/*** end of file ***/
