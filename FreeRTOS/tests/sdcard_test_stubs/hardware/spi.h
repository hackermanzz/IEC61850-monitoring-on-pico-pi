#ifndef SDCARD_TEST_SPI_H
#define SDCARD_TEST_SPI_H
#include <stddef.h>
#include <stdint.h>
typedef struct
{
    unsigned int index;
} spi_inst_t;
extern spi_inst_t g_test_spi0;
extern spi_inst_t g_test_spi1;
#define spi0 (&g_test_spi0)
#define spi1 (&g_test_spi1)
#define SPI_CPOL_0 (0U)
#define SPI_CPHA_0 (0U)
#define SPI_MSB_FIRST (0U)
unsigned int spi_get_index (spi_inst_t * spi);
unsigned int spi_init (spi_inst_t * spi, unsigned int baud);
unsigned int spi_set_baudrate (spi_inst_t * spi, unsigned int baud);
void spi_set_format (spi_inst_t * spi, unsigned int bits, unsigned int polarity,
                     unsigned int phase, unsigned int order);
void spi_deinit (spi_inst_t * spi);
int  spi_write_read_blocking (spi_inst_t * spi, const uint8_t * source,
                              uint8_t * destination, size_t length);
int  spi_write_blocking (spi_inst_t * spi, const uint8_t * source,
                         size_t length);
int  spi_read_blocking (spi_inst_t * spi, uint8_t filler, uint8_t * destination,
                        size_t length);
#endif
