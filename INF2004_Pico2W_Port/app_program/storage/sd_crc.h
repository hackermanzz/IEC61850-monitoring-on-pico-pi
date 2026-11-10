/** @file sd_crc.h
 * @brief SD SPI command/data checksums, independent of GPIO or filesystem.
 */
#ifndef SD_CRC_H
#define SD_CRC_H

#include <stddef.h>
#include <stdint.h>
uint8_t  sd_crc7(const uint8_t * p_bytes, size_t length);
uint16_t sd_crc16(const uint8_t * p_bytes, size_t length);

#endif /* SD_CRC_H */

/*** end of file ***/
