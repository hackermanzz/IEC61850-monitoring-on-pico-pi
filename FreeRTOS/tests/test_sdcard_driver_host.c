#include "sdcard.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "hardware/gpio.h"
#include "pico/stdlib.h"
#define TEST_SCK_PIN (18U)
#define TEST_MOSI_PIN (19U)
#define TEST_MISO_PIN (16U)
#define TEST_CS_PIN (17U)
#define TEST_CRS_DV_PIN (13U)
#define TEST_INIT_BAUD (400000U)
#define TEST_TRANSFER_BAUD (10000000U)
#define TEST_TIME_STEP_US (500000U)
#define TEST_SECTOR_BYTES (512U)
spi_inst_t          g_test_spi0 = {0};
spi_inst_t          g_test_spi1 = {1};
static unsigned int g_spi_init_calls;
static uint64_t     g_now_us;
unsigned int
spi_get_index (spi_inst_t * spi)
{
    return spi->index;
}
unsigned int
spi_init (spi_inst_t * spi, unsigned int baud)
{
    (void) spi;
    ++g_spi_init_calls;
    return baud;
}
unsigned int
spi_set_baudrate (spi_inst_t * spi, unsigned int baud)
{
    (void) spi;
    return baud;
}
void
spi_set_format (spi_inst_t * spi, unsigned int bits, unsigned int polarity,
                unsigned int phase, unsigned int order)
{
    (void) spi;
    (void) bits;
    (void) polarity;
    (void) phase;
    (void) order;
}
void
spi_deinit (spi_inst_t * spi)
{
    (void) spi;
}
int
spi_write_read_blocking (spi_inst_t * spi, const uint8_t * source,
                         uint8_t * destination, size_t length)
{
    (void) spi;
    (void) source;
    memset(destination, UINT8_MAX, length);
    return (int) length;
}
int
spi_write_blocking (spi_inst_t * spi, const uint8_t * source, size_t length)
{
    (void) spi;
    (void) source;
    return (int) length;
}
int
spi_read_blocking (spi_inst_t * spi, uint8_t filler, uint8_t * destination,
                   size_t length)
{
    (void) spi;
    memset(destination, filler, length);
    return (int) length;
}
void
gpio_init (unsigned int pin)
{
    (void) pin;
}
void
gpio_set_dir (unsigned int pin, bool output)
{
    (void) pin;
    (void) output;
}
void
gpio_put (unsigned int pin, bool high)
{
    (void) pin;
    (void) high;
}
void
gpio_set_function (unsigned int pin, unsigned int function)
{
    (void) pin;
    (void) function;
}
uint64_t
time_us_64 (void)
{
    g_now_us += TEST_TIME_STEP_US;
    return g_now_us;
}
void
sleep_ms (uint32_t milliseconds)
{
    (void) milliseconds;
}
int
main (void)
{
    sd_card_config_t config                    = {spi0,
                                                  TEST_SCK_PIN,
                                                  TEST_MOSI_PIN,
                                                  TEST_MISO_PIN,
                                                  TEST_CRS_DV_PIN,
                                                  TEST_INIT_BAUD,
                                                  TEST_TRANSFER_BAUD};
    uint8_t          sector[TEST_SECTOR_BYTES] = {0};
    assert(sd_card_init(&config) == SD_CARD_INVALID_ARGUMENT);
    assert(g_spi_init_calls == 0U);
    config.cs_gpio = TEST_CS_PIN;
    /* No card is attached: valid bus configuration must time out safely. */
    assert(sd_card_init(&config) == SD_CARD_TIMEOUT);
    assert(g_spi_init_calls == 1U);
    assert(!sd_card_is_ready());
    assert(sd_card_read_sector(0U, sector) == SD_CARD_NOT_READY);
    assert(sd_card_init(NULL) == SD_CARD_INVALID_ARGUMENT);
    puts("SD card driver host tests passed");
    return 0;
}
