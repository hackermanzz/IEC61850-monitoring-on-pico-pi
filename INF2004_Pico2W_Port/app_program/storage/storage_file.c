/** @file storage_file.c
 * @brief S1 owns FatFs and BIN/LOG pairs. Existing NOOBS content is never
 * replaced.
 */
#include "storage_file.h"
#include <string.h>
#include "ff.h"
#include "storage_log.h"

static FATFS    g_volume;
static FIL      g_file;
static char     g_name[] = "IECLOG/I0000000.BIN";
static uint32_t g_next_name;
static uint32_t g_error;
static bool     gb_open;

bool
storage_file_mount (void)
{
    FRESULT result = f_mount(&g_volume, "", 1u);
    FILINFO info   = {0};
    if ((FR_OK == result) && (FS_FAT16 != g_volume.fs_type)
        && (FS_FAT32 != g_volume.fs_type))
    {
        /* Mount reads only. Reject FAT12 before any directory/file write. */
        result = FR_NO_FILESYSTEM;
    }
    if (FR_OK == result)
    {
        result = f_stat("IECLOG", &info);
        if (FR_NO_FILE == result)
        {
            result = f_mkdir("IECLOG");
        }
        else if ((FR_OK == result) && (0u == (info.fattrib & AM_DIR)))
        {
            result = FR_DENIED;
        }
    }
    g_error = (uint32_t) result;
    if (FR_OK != result)
    {
        (void) f_mount(NULL, "", 0u);
    }
    return FR_OK == result;
}

bool
storage_file_begin (void)
{
    static const char digits[] = "0123456789ABCDEF";
    FRESULT           result   = FR_EXIST;
    FILINFO           info     = {0};
    if (gb_open)
    {
        g_error = FR_LOCKED;
        return false;
    }
    /* Each attempt is exclusive. Exhaustion is reported,not permission to
     * truncate/append to an existing file. A later retry continues the names.
     */
    for (uint32_t attempt = 0u; 64u > attempt; attempt++)
    {
        if (0x0fffffffu < g_next_name)
        {
            break;
        }
        for (uint32_t digit = 0u; 7u > digit; digit++)
        {
            g_name[14u - digit] = digits[(g_next_name >> (4u * digit)) & 15u];
        }
        g_next_name++;
        /* A surviving LOG also reserves the basename. Check before creating
         * BIN; neither member of an existing pair may be replaced.
         */
        memcpy(g_name + 16u, "LOG", 3u);
        result = f_stat(g_name, &info);
        memcpy(g_name + 16u, "BIN", 3u);
        if (FR_OK == result)
        {
            result = FR_EXIST;
        }
        else if (FR_NO_FILE == result)
        {
            result = f_open(&g_file, g_name, FA_WRITE | FA_CREATE_NEW);
        }
        if (FR_EXIST != result)
        {
            break;
        }
    }
    g_error = (uint32_t) result;
    gb_open = FR_OK == result;
    return gb_open;
}

bool
storage_file_write (const uint8_t * p_data, uint32_t length)
{
    UINT    written = 0u;
    FRESULT result  = gb_open ? f_write(&g_file, p_data, length, &written)
                              : FR_INVALID_OBJECT;
    if ((FR_OK == result) && (written != length))
    {
        result = FR_DENIED;
    }
    g_error = (uint32_t) result;
    return FR_OK == result;
}

bool
storage_file_commit (void)
{
    FRESULT result = gb_open ? f_sync(&g_file) : FR_INVALID_OBJECT;
    FRESULT closed = gb_open ? f_close(&g_file) : FR_INVALID_OBJECT;
    gb_open        = false;
    if (FR_OK == result)
    {
        result = closed;
    }
    if (FR_OK == result)
    {
        /* Reuse the closed BIN handle for bounded readback/log generation.
         * S1 owns both files; no evidence pointer or extra queue is introduced.
         */
        char log_name[sizeof(g_name)];
        memcpy(log_name, g_name, sizeof(log_name));
        memcpy(log_name + 16u, "LOG", 3u);
        result = f_open(&g_file, g_name, FA_READ);
        if (FR_OK == result)
        {
            result = storage_log_create(&g_file, g_name, log_name);
            closed = f_close(&g_file);
            if (FR_OK == result)
            {
                result = closed;
            }
        }
    }
    g_error = (uint32_t) result;
    /* ACK only after BIN and its LOG companion are both synced and closed. */
    return FR_OK == result;
}

void
storage_file_abort (void)
{
    if (gb_open)
    {
        /* Keep a partial NEW file for inspection;never delete card content. */
        (void) f_close(&g_file);
        gb_open = false;
    }
}

uint32_t
storage_file_error (void)
{
    return g_error;
}

/*** end of file ***/
