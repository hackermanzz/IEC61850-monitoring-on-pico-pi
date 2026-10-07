#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ff.h"
#include "sdcard.h"
#include "sdcard_fs.h"

#define SDCARD_FATFS_DRIVE "0:"
#define SDCARD_PATH_ASCII_MINIMUM 0x20u
#define SDCARD_PATH_ASCII_MAXIMUM 0x7eu
#define SDCARD_PATH_SINGLE_DOT_LENGTH 1u
#define SDCARD_PATH_PARENT_DOT_LENGTH 2u

static FATFS g_filesystem;
static bool  g_is_mounted = false;

static bool
sdcard_fs_path_is_valid (const char * path)
{
    size_t path_length    = 0u;
    size_t segment_length = 0u;
    size_t index          = 0u;

    if (path == NULL || path[0] == '\0' || path[0] == '/')
    {
        return false;
    }

    while (path[path_length] != '\0')
    {
        const unsigned char character = (unsigned char) path[path_length];

        if (path_length >= SDCARD_FS_PATH_MAX ||
            character < SDCARD_PATH_ASCII_MINIMUM ||
            character > SDCARD_PATH_ASCII_MAXIMUM || character == ':' ||
            character == '\\' || character == '*' || character == '?' ||
            character == '"' || character == '<' || character == '>' ||
            character == '|')
        {
            return false;
        }
        ++path_length;
    }
    if (path_length == 0u || path_length > SDCARD_FS_PATH_MAX ||
        path[path_length - 1u] == '/')
    {
        return false;
    }

    for (index = 0u; index <= path_length; ++index)
    {
        if (path[index] == '/' || path[index] == '\0')
        {
            if (segment_length == 0u ||
                (segment_length == SDCARD_PATH_SINGLE_DOT_LENGTH &&
                 path[index - SDCARD_PATH_SINGLE_DOT_LENGTH] == '.') ||
                (segment_length == SDCARD_PATH_PARENT_DOT_LENGTH &&
                 path[index - SDCARD_PATH_PARENT_DOT_LENGTH] == '.' &&
                 path[index - 1u] == '.'))
            {
                return false;
            }
            segment_length = 0u;
        }
        else
        {
            ++segment_length;
        }
    }

    return true;
}

static sdcard_fs_result_t
sdcard_fs_map_result (FRESULT result)
{
    switch (result)
    {
        case FR_OK:
            return SDCARD_FS_OK;
        case FR_NO_FILE:
        case FR_NO_PATH:
            return SDCARD_FS_NOT_FOUND;
        case FR_EXIST:
            return SDCARD_FS_ALREADY_EXISTS;
        case FR_INVALID_NAME:
        case FR_INVALID_DRIVE:
            return SDCARD_FS_INVALID_PATH;
        case FR_NOT_READY:
        case FR_NOT_ENABLED:
            return SDCARD_FS_NOT_MOUNTED;
        case FR_NO_FILESYSTEM:
            return SDCARD_FS_NO_FILESYSTEM;
        default:
            return SDCARD_FS_IO_ERROR;
    }
}

static sdcard_fs_result_t
sdcard_fs_check_path (const char * path)
{
    if (!sdcard_fs_path_is_valid(path))
    {
        return SDCARD_FS_INVALID_PATH;
    }
    if (!sdcard_fs_is_mounted())
    {
        return SDCARD_FS_NOT_MOUNTED;
    }

    return SDCARD_FS_OK;
}

sdcard_fs_result_t
sdcard_fs_mount (void)
{
    FRESULT result = FR_OK;

    if (!sd_card_is_ready())
    {
        g_is_mounted = false;
        (void) f_mount(NULL, SDCARD_FATFS_DRIVE, 0u);
        return SDCARD_FS_NOT_MOUNTED;
    }
    g_is_mounted = false;
    result       = f_mount(&g_filesystem, SDCARD_FATFS_DRIVE, 1u);
    if (result != FR_OK)
    {
        return sdcard_fs_map_result(result);
    }
    g_is_mounted = true;
    return SDCARD_FS_OK;
}

sdcard_fs_result_t
sdcard_fs_unmount (void)
{
    FRESULT result = FR_OK;

    if (!sdcard_fs_is_mounted())
    {
        return SDCARD_FS_NOT_MOUNTED;
    }

    if (sd_card_sync() != SD_CARD_OK)
    {
        return SDCARD_FS_IO_ERROR;
    }
    result = f_mount(NULL, SDCARD_FATFS_DRIVE, 0u);
    if (result != FR_OK)
    {
        return sdcard_fs_map_result(result);
    }
    g_is_mounted = false;
    return SDCARD_FS_OK;
}

bool
sdcard_fs_is_mounted (void)
{
    return g_is_mounted && sd_card_is_ready();
}

sdcard_fs_result_t
sdcard_fs_create (const char * path)
{
    FIL                file       = {0};
    FRESULT            result     = FR_OK;
    sdcard_fs_result_t api_result = sdcard_fs_check_path(path);

    if (api_result != SDCARD_FS_OK)
    {
        return api_result;
    }

    result = f_open(&file, path, FA_CREATE_NEW | FA_WRITE);
    if (result != FR_OK)
    {
        return sdcard_fs_map_result(result);
    }
    result = f_sync(&file);
    if (f_close(&file) != FR_OK && result == FR_OK)
    {
        result = FR_DISK_ERR;
    }

    return sdcard_fs_map_result(result);
}

sdcard_fs_result_t
sdcard_fs_read (const char * path, uint32_t offset, void * buffer,
                uint32_t capacity, uint32_t * bytes_read)
{
    FIL                file        = {0};
    FRESULT            result      = FR_OK;
    UINT               transferred = 0u;
    sdcard_fs_result_t api_result  = sdcard_fs_check_path(path);

    if (bytes_read == NULL)
    {
        return SDCARD_FS_INVALID_ARGUMENT;
    }
    *bytes_read = 0u;
    if (capacity > 0u && buffer == NULL)
    {
        return SDCARD_FS_INVALID_ARGUMENT;
    }
    if (api_result != SDCARD_FS_OK)
    {
        return api_result;
    }

    result = f_open(&file, path, FA_READ);
    if (result != FR_OK)
    {
        return sdcard_fs_map_result(result);
    }
    if (offset > f_size(&file))
    {
        (void) f_close(&file);
        return SDCARD_FS_OFFSET_OUT_OF_RANGE;
    }
    result = f_lseek(&file, offset);
    if (result == FR_OK && capacity > 0u)
    {
        result = f_read(&file, buffer, (UINT) capacity, &transferred);
    }
    if (f_close(&file) != FR_OK && result == FR_OK)
    {
        result = FR_DISK_ERR;
    }
    if (result != FR_OK)
    {
        return sdcard_fs_map_result(result);
    }

    *bytes_read = (uint32_t) transferred;
    return SDCARD_FS_OK;
}

sdcard_fs_result_t
sdcard_fs_update (const char * path, uint32_t offset, const void * data,
                  uint32_t length, uint32_t * bytes_written)
{
    FIL                file        = {0};
    FRESULT            result      = FR_OK;
    UINT               transferred = 0u;
    sdcard_fs_result_t api_result  = sdcard_fs_check_path(path);

    if (bytes_written == NULL)
    {
        return SDCARD_FS_INVALID_ARGUMENT;
    }
    *bytes_written = 0u;
    if ((length > 0u && data == NULL) || length > UINT32_MAX - offset)
    {
        return SDCARD_FS_INVALID_ARGUMENT;
    }
    if (api_result != SDCARD_FS_OK)
    {
        return api_result;
    }

    result = f_open(&file, path, FA_WRITE | FA_OPEN_EXISTING);
    if (result != FR_OK)
    {
        return sdcard_fs_map_result(result);
    }
    if (offset > f_size(&file))
    {
        (void) f_close(&file);
        return SDCARD_FS_OFFSET_OUT_OF_RANGE;
    }
    result = f_lseek(&file, offset);
    if (result == FR_OK && length > 0u)
    {
        result = f_write(&file, data, (UINT) length, &transferred);
    }
    if (result == FR_OK && transferred == length)
    {
        result = f_sync(&file);
    }
    if (f_close(&file) != FR_OK && result == FR_OK)
    {
        result = FR_DISK_ERR;
    }
    if (result != FR_OK)
    {
        *bytes_written = (uint32_t) transferred;
        return sdcard_fs_map_result(result);
    }
    if (transferred != length)
    {
        *bytes_written = (uint32_t) transferred;
        return SDCARD_FS_IO_ERROR;
    }

    *bytes_written = (uint32_t) transferred;
    return SDCARD_FS_OK;
}

sdcard_fs_result_t
sdcard_fs_delete (const char * path)
{
    FILINFO            info       = {0};
    FRESULT            result     = FR_OK;
    sdcard_fs_result_t api_result = sdcard_fs_check_path(path);

    if (api_result != SDCARD_FS_OK)
    {
        return api_result;
    }

    result = f_stat(path, &info);
    if (result != FR_OK)
    {
        return sdcard_fs_map_result(result);
    }
    if ((info.fattrib & AM_DIR) != 0u)
    {
        return SDCARD_FS_INVALID_PATH;
    }

    result = f_unlink(path);
    if (result != FR_OK)
    {
        return sdcard_fs_map_result(result);
    }

    return sd_card_sync() == SD_CARD_OK ? SDCARD_FS_OK : SDCARD_FS_IO_ERROR;
}

sdcard_fs_result_t
sdcard_fs_stat (const char * path, sdcard_fs_file_info_t * file_info)
{
    FILINFO            info       = {0};
    FRESULT            result     = FR_OK;
    sdcard_fs_result_t api_result = sdcard_fs_check_path(path);

    if (file_info == NULL)
    {
        return SDCARD_FS_INVALID_ARGUMENT;
    }
    file_info->size_bytes = 0u;
    if (api_result != SDCARD_FS_OK)
    {
        return api_result;
    }

    result = f_stat(path, &info);
    if (result != FR_OK)
    {
        return sdcard_fs_map_result(result);
    }
    if ((info.fattrib & AM_DIR) != 0u)
    {
        return SDCARD_FS_INVALID_PATH;
    }
    file_info->size_bytes = (uint32_t) info.fsize;
    return SDCARD_FS_OK;
}
