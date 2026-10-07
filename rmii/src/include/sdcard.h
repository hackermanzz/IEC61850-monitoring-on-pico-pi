#ifndef SD_CARD_H
#define SD_CARD_H

#include <stdbool.h>
#include <stdint.h>

#include "hardware/spi.h"

typedef enum
{
    SD_CARD_OK = 0,
    SD_CARD_INVALID_ARGUMENT,
    SD_CARD_NOT_READY,
    SD_CARD_TIMEOUT,
    SD_CARD_IO_ERROR,
    SD_CARD_UNSUPPORTED
} sd_card_status_t;

/* Pico W wiring uses SPI0 GP16/18/19; CS must be an external free GPIO. */
/* RMII/LED pins GP0-8/13/15 and Pico W internal pins GP23-25/29 are rejected.
 * All calls belong to one core; buffers must hold at least 512 bytes.
 * Transactions block with bounded card-response deadlines. */
typedef struct
{
    spi_inst_t * spi;
    uint32_t     sck_gpio;
    uint32_t     mosi_gpio;
    uint32_t     miso_gpio;
    uint32_t     cs_gpio;
    uint32_t     init_baud_hz;
    uint32_t     transfer_baud_hz;
} sd_card_config_t;

sd_card_status_t sd_card_init (const sd_card_config_t * config);
sd_card_status_t sd_card_read_sector (uint32_t lba, uint8_t * buffer);
sd_card_status_t sd_card_write_sector (uint32_t lba, const uint8_t * buffer);
sd_card_status_t sd_card_sync (void);
sd_card_status_t sd_card_sector_count (uint32_t * count);
bool             sd_card_is_ready (void);
void             sd_card_deinit (void);

#endif
