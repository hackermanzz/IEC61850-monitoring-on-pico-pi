#include <stdint.h>

#include "ff.h"
#include "diskio.h"
#include "sdcard.h"

#define SDCARD_DISK_DRIVE 0u
#define SDCARD_SECTOR_SIZE 512u

static DRESULT
sdcard_disk_check_request (BYTE physical_drive, const void * buffer,
                           LBA_t sector, UINT count)
{
    uint32_t sector_count = 0u;

    if (physical_drive != SDCARD_DISK_DRIVE || buffer == NULL || count == 0u ||
        count > UINT32_MAX / SDCARD_SECTOR_SIZE)
    {
        return RES_PARERR;
    }
    if (!sd_card_is_ready())
    {
        return RES_NOTRDY;
    }
    if (sd_card_sector_count(&sector_count) != SD_CARD_OK)
    {
        return RES_ERROR;
    }
    /* Validate the whole range before a write can partially change the card. */
    if (count > sector_count || sector > sector_count - count)
    {
        return RES_PARERR;
    }
    return RES_OK;
}

DSTATUS
disk_initialize(BYTE physical_drive)
{
    if (physical_drive != SDCARD_DISK_DRIVE)
    {
        return STA_NOINIT;
    }

    return sd_card_is_ready() ? 0u : STA_NOINIT;
}

DSTATUS
disk_status(BYTE physical_drive)
{
    if (physical_drive != SDCARD_DISK_DRIVE)
    {
        return STA_NOINIT;
    }

    return sd_card_is_ready() ? 0u : STA_NOINIT;
}

DRESULT
disk_read(BYTE physical_drive, BYTE * buffer, LBA_t sector, UINT count)
{
    uint32_t current_sector = (uint32_t) sector;
    UINT     sector_index   = 0u;
    DRESULT  result =
        sdcard_disk_check_request(physical_drive, buffer, sector, count);

    if (result != RES_OK)
    {
        return result;
    }

    for (sector_index = 0u; sector_index < count; ++sector_index)
    {
        if (sd_card_read_sector(current_sector,
                                &buffer[sector_index * SDCARD_SECTOR_SIZE]) !=
            SD_CARD_OK)
        {
            return RES_ERROR;
        }
        ++current_sector;
    }

    return RES_OK;
}

DRESULT
disk_write(BYTE physical_drive, const BYTE * buffer, LBA_t sector, UINT count)
{
    uint32_t current_sector = (uint32_t) sector;
    UINT     sector_index   = 0u;
    DRESULT  result =
        sdcard_disk_check_request(physical_drive, buffer, sector, count);

    if (result != RES_OK)
    {
        return result;
    }

    for (sector_index = 0u; sector_index < count; ++sector_index)
    {
        if (sd_card_write_sector(current_sector,
                                 &buffer[sector_index * SDCARD_SECTOR_SIZE]) !=
            SD_CARD_OK)
        {
            return RES_ERROR;
        }
        ++current_sector;
    }

    return RES_OK;
}

DRESULT
disk_ioctl(BYTE physical_drive, BYTE command, void * buffer)
{
    uint32_t sector_count = 0u;

    if (physical_drive != SDCARD_DISK_DRIVE)
    {
        return RES_PARERR;
    }
    if (!sd_card_is_ready())
    {
        return RES_NOTRDY;
    }

    switch (command)
    {
        case CTRL_SYNC:
            return sd_card_sync() == SD_CARD_OK ? RES_OK : RES_ERROR;

        case GET_SECTOR_COUNT:
            if (buffer == NULL ||
                sd_card_sector_count(&sector_count) != SD_CARD_OK)
            {
                return buffer == NULL ? RES_PARERR : RES_ERROR;
            }
            *(LBA_t *) buffer = (LBA_t) sector_count;
            return RES_OK;

        case GET_SECTOR_SIZE:
            if (buffer == NULL)
            {
                return RES_PARERR;
            }
            *(WORD *) buffer = (WORD) SDCARD_SECTOR_SIZE;
            return RES_OK;

        case GET_BLOCK_SIZE:
            if (buffer == NULL)
            {
                return RES_PARERR;
            }
            *(DWORD *) buffer = 1u;
            return RES_OK;

        default:
            return RES_PARERR;
    }
}
