#include "ff.h"
#include "diskio.h"
#include "sdcard.h"
#include <assert.h>
#include <stdio.h>
#define TEST_SECTOR_COUNT (8U)
#define TEST_SECTOR_BYTES (512U)
#define TEST_TRANSFER_COUNT (2U)
static bool     g_ready = true;
static uint32_t g_read_calls;
static uint32_t g_write_calls;
bool
sd_card_is_ready (void)
{
    return g_ready;
}
sd_card_status_t
sd_card_sector_count (uint32_t * count)
{
    *count = TEST_SECTOR_COUNT;
    return SD_CARD_OK;
}
sd_card_status_t
sd_card_read_sector (uint32_t lba, uint8_t * buffer)
{
    assert(lba < TEST_SECTOR_COUNT);
    assert(buffer != NULL);
    ++g_read_calls;
    return SD_CARD_OK;
}
sd_card_status_t
sd_card_write_sector (uint32_t lba, const uint8_t * buffer)
{
    assert(lba < TEST_SECTOR_COUNT);
    assert(buffer != NULL);
    ++g_write_calls;
    return SD_CARD_OK;
}
sd_card_status_t
sd_card_sync (void)
{
    return SD_CARD_OK;
}
int
main (void)
{
    uint8_t buffer[TEST_TRANSFER_COUNT * TEST_SECTOR_BYTES] = {0};
    assert(disk_read(0U, buffer, TEST_SECTOR_COUNT - 1U, TEST_TRANSFER_COUNT) ==
           RES_PARERR);
    assert(disk_write(0U, buffer, TEST_SECTOR_COUNT - 1U,
                      TEST_TRANSFER_COUNT) == RES_PARERR);
    assert(g_read_calls == 0U && g_write_calls == 0U);
    assert(disk_write(0U, buffer, UINT32_MAX, TEST_TRANSFER_COUNT) ==
           RES_PARERR);
    assert(disk_write(0U, buffer, 0U, UINT32_MAX) == RES_PARERR);
    assert(g_write_calls == 0U);
    assert(disk_read(0U, buffer, TEST_SECTOR_COUNT - TEST_TRANSFER_COUNT,
                     TEST_TRANSFER_COUNT) == RES_OK);
    assert(disk_write(0U, buffer, TEST_SECTOR_COUNT - TEST_TRANSFER_COUNT,
                      TEST_TRANSFER_COUNT) == RES_OK);
    assert(g_read_calls == TEST_TRANSFER_COUNT);
    assert(g_write_calls == TEST_TRANSFER_COUNT);
    g_ready = false;
    assert(disk_write(0U, buffer, 0U, 1U) == RES_NOTRDY);
    puts("SD card disk I/O host tests passed");
    return 0;
}
