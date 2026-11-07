/** @file capture_decode.h
 * @brief Portable 10 Mbps oversample decoder; no hardware or kernel calls.
 */
#ifndef CAPTURE_DECODE_H
#define CAPTURE_DECODE_H

#include <stddef.h> /* Sample buffer lengths. */
#include <stdint.h> /* Packed samples and wire bytes. */

#define CAPTURE_WIRE_MAX         1536u
#define CAPTURE_DATA_SIZE        1544u
#define CAPTURE_SAMPLES_PER_WORD 10u

typedef enum
{
    CAPTURE_DECODE_OK,
    CAPTURE_DECODE_NO_SFD,
    CAPTURE_DECODE_SHORT,
    CAPTURE_DECODE_BAD_CRC,
    CAPTURE_DECODE_TOO_LARGE,
    CAPTURE_DECODE_INVALID
} capture_decode_result_t;

/** @brief Output includes FCS bytes, but length excludes the four-byte FCS. */
typedef struct
{
    uint64_t timestamp_us;
    uint32_t sequence;
    uint32_t loss_generation;
    uint16_t length;
    uint16_t wire_length;
    uint8_t  data[CAPTURE_DATA_SIZE];
} capture_frame_t;

/** @brief Ten chronological [CRS,RXD0,RXD1] samples occupy bits 2..31.
 * @note Requires approximately ten 50 MHz samples per 10 Mbps dibit.
 */
capture_decode_result_t capture_decode(const uint32_t *  p_words,
                                       size_t            word_count,
                                       capture_frame_t * p_frame);

/** @brief Ethernet reflected CRC-32, also exposed for deterministic fixtures.
 */
uint32_t capture_crc32(const uint8_t * p_data, size_t length);

#endif /* CAPTURE_DECODE_H */

/*** end of file ***/
