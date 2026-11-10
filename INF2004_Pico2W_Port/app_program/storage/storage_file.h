/** @file storage_file.h
 * @brief Exclusive new BIN/LOG incident pairs; never overwrite existing card
 * files.
 */
#ifndef STORAGE_FILE_H
#define STORAGE_FILE_H

#include <stdbool.h>
#include <stdint.h>

bool     storage_file_mount(void);
bool     storage_file_begin(void);
bool     storage_file_write(const uint8_t * p_data, uint32_t length);
bool     storage_file_commit(void);
void     storage_file_abort(void);
uint32_t storage_file_error(void);

#endif /* STORAGE_FILE_H */

/*** end of file ***/
