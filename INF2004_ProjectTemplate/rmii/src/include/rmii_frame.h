/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef RMII_FRAME_H
#define RMII_FRAME_H

#include <stddef.h>
#include <stdint.h>

#define RMII_FRAME_MAX_BYTES (1518U)
#define RMII_FRAME_FCS_BYTES (4U)

/* Ethernet reflected CRC-32. Input excludes the four transmitted FCS bytes.
 * The caller supplies readable data for length bytes; NULL/empty returns 0. */
uint32_t rmii_frame_crc (const uint8_t * data, size_t length);

/* Scan captured bytes for a matching little-endian FCS after a complete
 * Ethernet header. Return the frame length excluding FCS, or 0 on failure.
 * Extra capture bytes following the FCS are ignored. */
size_t rmii_frame_find_length (const uint8_t * data, size_t length);

/* Decode the 50 MHz RX sample words used by this 10 Mbps driver. Each word
 * contains 16 little-endian dibits. Preserve the established run-rounding
 * algorithm; the caller validates the resulting frame with its FCS.
 * Returns bytes stored, at most capacity; invalid/empty inputs return 0. */
size_t rmii_frame_decode_samples (const uint32_t * samples, size_t word_count,
                                  uint8_t * output, size_t capacity);

#endif /* RMII_FRAME_H */
