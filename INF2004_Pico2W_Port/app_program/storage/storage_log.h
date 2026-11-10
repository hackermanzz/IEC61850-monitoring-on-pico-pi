/** @file storage_log.h
 * @brief Compact native IRT log, read back from a completed BIN by S1 only.
 */
#ifndef STORAGE_LOG_H
#define STORAGE_LOG_H
#include "ff.h"
FRESULT storage_log_create(FIL * p_binary, const char * p_binary_name,
                           const char * p_log_name);
#endif
/*** end of file ***/
