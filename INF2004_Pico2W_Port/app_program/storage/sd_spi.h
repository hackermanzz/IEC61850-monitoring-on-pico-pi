/** @file sd_spi.h
 * @brief Single S1 task owns SPI1 and two separately claimed DMA channels.
 */
#ifndef SD_SPI_H
#define SD_SPI_H

#include <stdbool.h>
#include <stdint.h>

typedef enum
{
    SD_SPI_OK,
    SD_SPI_DISABLED,
    SD_SPI_RESOURCE,
    SD_SPI_TIMEOUT,
    SD_SPI_PROTOCOL,
    SD_SPI_CRC,
    SD_SPI_RANGE
} sd_spi_error_t;

/* Persisted timeout phases, retained even after a successful remount. */
#define SD_SPI_TIMEOUT_TX    (1u)
#define SD_SPI_TIMEOUT_RX    (2u)
#define SD_SPI_TIMEOUT_DMA   (3u)
#define SD_SPI_TIMEOUT_TOKEN (4u)
#define SD_SPI_TIMEOUT_BUSY  (5u)

uint32_t sd_spi_timeout_count(void);
uint32_t sd_spi_timeout_context(void);
bool     sd_spi_configured(void);
bool     sd_spi_initialize(void);
bool     sd_spi_read(uint8_t * p_data, uint32_t sector, uint32_t count);
bool     sd_spi_write(const uint8_t * p_data, uint32_t sector, uint32_t count);
bool     sd_spi_sync(void);
uint32_t sd_spi_sectors(void);
sd_spi_error_t sd_spi_error(void);

#endif /* SD_SPI_H */

/*** end of file ***/
