/** @file sd_diskio.c
 * @brief No formatting/trim operation: only read,write and completion.
 */
#include "sd_diskio.h"
#include <stddef.h>
#include "sd_spi.h"

DSTATUS
disk_status(BYTE drive)
{
    return ((0u == drive) && (0u < sd_spi_sectors())) ? 0u : STA_NOINIT;
}

DSTATUS
disk_initialize(BYTE drive)
{
    return ((0u == drive) && sd_spi_initialize()) ? 0u : STA_NOINIT;
}

DRESULT
disk_read(BYTE drive, BYTE * p_buffer, LBA_t sector, UINT count)
{
    if ((0u != drive) || (0u == count))
    {
        return RES_PARERR;
    }
    return sd_spi_read(p_buffer, sector, count) ? RES_OK : RES_ERROR;
}

DRESULT
disk_write(BYTE drive, const BYTE * p_buffer, LBA_t sector, UINT count)
{
    if ((0u != drive) || (0u == count))
    {
        return RES_PARERR;
    }
    return sd_spi_write(p_buffer, sector, count) ? RES_OK : RES_ERROR;
}

DRESULT
disk_ioctl(BYTE drive, BYTE command, void * p_buffer)
{
    if (0u != drive)
    {
        return RES_PARERR;
    }
    if (CTRL_SYNC == command)
    {
        return sd_spi_sync() ? RES_OK : RES_ERROR;
    }
    if (NULL == p_buffer)
    {
        return RES_PARERR;
    }
    if (GET_SECTOR_COUNT == command)
    {
        *(LBA_t *) p_buffer = sd_spi_sectors();
    }
    else if (GET_SECTOR_SIZE == command)
    {
        *(WORD *) p_buffer = 512u;
    }
    else if (GET_BLOCK_SIZE == command)
    {
        *(DWORD *) p_buffer = 1u;
    }
    else
    {
        return RES_PARERR;
    }
    return RES_OK;
}

/*** end of file ***/
