#ifndef SDCARD_FS_H
#define SDCARD_FS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SDCARD_FS_PATH_MAX 96u

/* Paths are NUL-terminated relative printable-ASCII names, at most PATH_MAX
 * bytes excluding the terminator. Parent/current-directory segments and drive
 * prefixes are rejected. All filesystem calls belong to one core; none is ISR
 * safe. Operations block and must be scheduled outside the capture path. */

typedef enum
{
    SDCARD_FS_OK = 0,
    SDCARD_FS_INVALID_ARGUMENT,
    SDCARD_FS_INVALID_PATH,
    SDCARD_FS_NOT_MOUNTED,
    SDCARD_FS_NO_FILESYSTEM,
    SDCARD_FS_NOT_FOUND,
    SDCARD_FS_ALREADY_EXISTS,
    SDCARD_FS_OFFSET_OUT_OF_RANGE,
    SDCARD_FS_IO_ERROR
} sdcard_fs_result_t;

typedef struct
{
    uint32_t size_bytes;
} sdcard_fs_file_info_t;

/* Mounts the FAT volume on an already initialized SD card. */
sdcard_fs_result_t sdcard_fs_mount (void);

/* Flushes filesystem metadata and unmounts the volume. */
sdcard_fs_result_t sdcard_fs_unmount (void);

/* Returns true only while the filesystem volume is mounted. */
bool sdcard_fs_is_mounted (void);

/* Creates an empty file; returns ALREADY_EXISTS if the name is present. */
sdcard_fs_result_t sdcard_fs_create (const char * path);

/* Reads up to capacity bytes starting at offset. EOF is a successful 0-byte
 * read. */
sdcard_fs_result_t sdcard_fs_read (const char * path, uint32_t offset,
                                   void * buffer, uint32_t capacity,
                                   uint32_t * bytes_read);

/* Writes bytes to an existing file at offset, extending it when needed. */
sdcard_fs_result_t sdcard_fs_update (const char * path, uint32_t offset,
                                     const void * data, uint32_t length,
                                     uint32_t * bytes_written);

/* Removes an existing file. */
sdcard_fs_result_t sdcard_fs_delete (const char * path);

/* Retrieves the current file size. */
sdcard_fs_result_t sdcard_fs_stat (const char *            path,
                                   sdcard_fs_file_info_t * file_info);

#endif
