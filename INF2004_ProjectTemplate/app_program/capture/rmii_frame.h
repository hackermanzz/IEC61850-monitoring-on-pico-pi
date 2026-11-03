/** @file rmii_frame.h
 *
 * @brief Ethernet frame helpers for the RMII capture: decoding of the
 * receive samples, frame length recovery and FCS (CRC-32) checking.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2021 Sandeep Mistry. Extracted from rmii_ethernet.c.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef RMII_FRAME_H
#define RMII_FRAME_H

#include <stddef.h>
#include <stdint.h>

#define RMII_FRAME_MAX_BYTES (1518u)
#define RMII_FRAME_FCS_BYTES (4u)

uint32_t rmii_frame_crc(uint8_t const * p_data, size_t length);
size_t   rmii_frame_find_length(uint8_t const * p_data, size_t length);
size_t rmii_frame_decode_samples(uint32_t const * p_samples, size_t word_count,
                                 uint8_t * p_output, size_t capacity);

#endif /* RMII_FRAME_H */

/*** end of file ***/
