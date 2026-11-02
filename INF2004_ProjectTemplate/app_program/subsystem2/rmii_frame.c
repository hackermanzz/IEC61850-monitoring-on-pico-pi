/** @file rmii_frame.c
 *
 * @brief Ethernet frame helpers for the RMII capture: decoding of the
 * receive samples, frame length recovery and FCS (CRC-32) checking.
 *
 * @par
 * These helpers use no hardware, so they can also be verified on a host.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2021 Sandeep Mistry. Extracted from rmii_ethernet.c.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rmii_frame.h"

// Ethernet framing and the IEEE 802.3 CRC-32 (reflected form).
//
#define FRAME_HEADER_BYTES       (14u)
#define BITS_PER_OCTET           (8u)
#define FCS_OCTET_FIRST          (0u)
#define FCS_OCTET_SECOND         (1u)
#define FCS_OCTET_THIRD          (2u)
#define FCS_OCTET_FOURTH         (3u)
#define CRC_SECOND_OCTET_SHIFT   (8u)
#define CRC_THIRD_OCTET_SHIFT    (16u)
#define CRC_FOURTH_OCTET_SHIFT   (24u)
#define CRC_INITIAL_REMAINDER    (UINT32_MAX)
#define CRC_REFLECTED_POLYNOMIAL (0xEDB88320u)

// Layout of the sample words written by the PIO receive program: sixteen
// little-endian dibits (2-bit RXD1:RXD0 samples) per 32-bit word.
//
#define SAMPLES_PER_WORD     (16u)
#define SAMPLE_WORD_SHIFT    (4u)
#define SAMPLE_INDEX_MASK    (15u)
#define DIBIT_WIDTH_BITS     (2u)
#define DIBITS_PER_BYTE      (4u)
#define DIBIT_VALUE_MASK     (3u)
#define DIBIT_REPEAT_PATTERN (0x55555555u)

// The sampler runs at 50 MHz and a 10 Mbps dibit lasts 100 ns, so a dibit is
// ten samples long. A run of equal samples is rounded to whole dibits.
//
#define CYCLES_PER_DIBIT    (10u)
#define DIBIT_ROUNDING_BIAS (5u)

// The start frame delimiter ends with the dibit 11; data follows it.
//
#define DIBIT_STATE_SFD (3u)

// Output state while dibits are assembled into octets.
//
typedef struct
{
    uint8_t * p_output;
    size_t    capacity;
    size_t    length;
    uint32_t  dibits;
    uint32_t  octet;
    bool      b_in_frame;
} decode_output_t;

static uint32_t crc_update_octet(uint32_t remainder, uint8_t octet);
static bool     fcs_matches(uint8_t const * p_fcs, uint32_t expected);
static uint32_t count_matching_samples(uint32_t packed, uint32_t value,
                                       uint32_t offset);
static void decode_run(decode_output_t * p_state, uint32_t value, size_t run);
static void store_dibit(decode_output_t * p_state, uint32_t value);

/*!
 * @brief Compute the Ethernet CRC-32 of a block of bytes.
 *
 * @param[in] p_data The bytes to check, without the four FCS bytes.
 * @param[in] length The number of bytes at p_data.
 *
 * @return The CRC-32 value, or 0 if p_data is NULL.
 */
uint32_t
rmii_frame_crc (uint8_t const * p_data, size_t length)
{
    uint32_t result = 0u;

    if (NULL != p_data)
    {
        uint32_t remainder = CRC_INITIAL_REMAINDER;

        for (size_t index = 0u; index < length; ++index)
        {
            remainder = crc_update_octet(remainder, p_data[index]);
        }

        result = ~remainder;
    }

    return (result);
}

/*!
 * @brief Find the length of an Ethernet frame inside captured bytes.
 *
 * @par
 * Scans for a matching little-endian FCS after a complete Ethernet header.
 * Extra captured bytes after the final FCS are ignored.
 *
 * @param[in] p_data The captured bytes.
 * @param[in] length The number of captured bytes.
 *
 * @return The longest verified frame length without the FCS, or 0 if no
 *         FCS matches.
 *
 * WARNING: This helper cannot prove the physical end of frame from truncated
 * samples; framing must still be qualified on the board.
 */
size_t
rmii_frame_find_length (uint8_t const * p_data, size_t length)
{
    size_t matched_length = 0u;

    if ((NULL != p_data)
        && (length >= (FRAME_HEADER_BYTES + RMII_FRAME_FCS_BYTES)))
    {
        uint32_t remainder = CRC_INITIAL_REMAINDER;

        for (size_t index = 0u; index < (length - RMII_FRAME_FCS_BYTES);
             ++index)
        {
            remainder = crc_update_octet(remainder, p_data[index]);

            // NOTE: Payload bytes can equal the FCS of an earlier prefix.
            // Keep scanning to the last verified end instead of truncating
            // a valid frame.
            if (((index + 1u) >= FRAME_HEADER_BYTES)
                && fcs_matches(&p_data[index + 1u], ~remainder))
            {
                matched_length = index + 1u;
            }
        }
    }

    return (matched_length);
}

/*!
 * @brief Decode the 50 MHz receive samples of this 10 Mbps driver into
 *        bytes.
 *
 * @par
 * Each run of equal samples is rounded to whole dibits; decoding starts
 * after the start frame delimiter. The caller validates the resulting frame
 * with its FCS. The input and output buffers must not overlap.
 *
 * @param[in]  p_samples  The sample words.
 * @param[in]  word_count The number of sample words.
 * @param[out] p_output   Where the decoded bytes are stored.
 * @param[in]  capacity   The size of the output buffer in bytes.
 *
 * @return The number of bytes stored, at most capacity. Invalid or empty
 *         inputs return 0.
 */
size_t
rmii_frame_decode_samples (uint32_t const * p_samples, size_t word_count,
                           uint8_t * p_output, size_t capacity)
{
    decode_output_t state = {.p_output = p_output, .capacity = capacity};
    bool const      b_is_input_valid =
        (NULL != p_samples) && (NULL != p_output) && (0u != word_count)
        && (0u != capacity)
        && (word_count <= ((SIZE_MAX - 1u) / SAMPLES_PER_WORD));

    if (b_is_input_valid)
    {
        size_t const total            = word_count * SAMPLES_PER_WORD;
        uint32_t     previous         = p_samples[0] & DIBIT_VALUE_MASK;
        size_t       index            = 0u;
        size_t       run              = 0u;
        bool         b_is_output_full = false;

        while ((index < total) && !b_is_output_full)
        {
            // The cast is safe: the mask leaves a value from 0 to 15.
            uint32_t const offset = (uint32_t) (index & SAMPLE_INDEX_MASK);
            uint32_t const packed = p_samples[index >> SAMPLE_WORD_SHIFT]
                                 >> (offset * DIBIT_WIDTH_BITS);
            uint32_t const value  = packed & DIBIT_VALUE_MASK;

            if (value != previous)
            {
                decode_run(&state, previous, run);
                b_is_output_full = (state.length == capacity);
                previous         = value;
                run              = 0u;
            }

            if (!b_is_output_full)
            {
                uint32_t const matching =
                    count_matching_samples(packed, value, offset);

                run += matching;
                index += matching;
            }
        }

        if (!b_is_output_full)
        {
            decode_run(&state, previous, run);
        }
    }

    return (state.length);
}

/*!
 * @brief Add one octet to a running Ethernet CRC-32.
 *
 * @param[in] remainder The CRC remainder so far.
 * @param[in] octet     The next data octet.
 *
 * @return The updated remainder.
 */
static uint32_t
crc_update_octet (uint32_t remainder, uint8_t octet)
{
    uint32_t result = remainder;
    uint32_t data   = octet;

    for (uint32_t bit = 0u; bit < BITS_PER_OCTET; ++bit)
    {
        uint32_t const carry = (result ^ data) & 1u;

        result >>= 1u;

        if (0u != carry)
        {
            result ^= CRC_REFLECTED_POLYNOMIAL;
        }

        data >>= 1u;
    }

    return (result);
}

/*!
 * @brief Compare four received FCS bytes with an expected CRC-32.
 *
 * @param[in] p_fcs    The four FCS bytes, least significant first.
 * @param[in] expected The expected CRC-32.
 *
 * @return True if all four bytes match.
 */
static bool
fcs_matches (uint8_t const * p_fcs, uint32_t expected)
{
    // Each cast keeps only the low eight bits of the shifted CRC, which is
    // the octet being compared.
    return ((p_fcs[FCS_OCTET_FIRST] == (uint8_t) expected)
            && (p_fcs[FCS_OCTET_SECOND]
                == (uint8_t) (expected >> CRC_SECOND_OCTET_SHIFT))
            && (p_fcs[FCS_OCTET_THIRD]
                == (uint8_t) (expected >> CRC_THIRD_OCTET_SHIFT))
            && (p_fcs[FCS_OCTET_FOURTH]
                == (uint8_t) (expected >> CRC_FOURTH_OCTET_SHIFT)));
}

/*!
 * @brief Count the samples that repeat the current dibit, from the current
 *        position to the end of its sample word.
 *
 * @param[in] packed The sample word, shifted so the current sample is in
 *                   bits 1 and 0.
 * @param[in] value  The dibit value of the current sample.
 * @param[in] offset The position of the current sample in its word.
 *
 * @return The number of equal samples, at least 1.
 */
static uint32_t
count_matching_samples (uint32_t packed, uint32_t value, uint32_t offset)
{
    // XOR with a word holding sixteen copies of this dibit. The first
    // differing bit marks the next run boundary.
    uint32_t const changed   = packed ^ (value * DIBIT_REPEAT_PATTERN);
    uint32_t const available = SAMPLES_PER_WORD - offset;
    uint32_t       matching  = SAMPLES_PER_WORD;

    // NOTE: __builtin_ctz(0) is undefined, so a word whose remaining samples
    // all match keeps the full count. GCC and Clang provide this builtin on
    // both the target and the host test compilers.
    if (0u != changed)
    {
        // The cast is safe: ctz of a non-zero 32-bit value is 0 to 31.
        matching = ((uint32_t) __builtin_ctz(changed)) / DIBIT_WIDTH_BITS;
    }

    if (matching > available)
    {
        matching = available;
    }

    return (matching);
}

/*!
 * @brief Turn one run of equal samples into dibits.
 *
 * @param[in,out] p_state The decoder output state.
 * @param[in]     value   The dibit value of the run.
 * @param[in]     run     The run length in samples.
 */
static void
decode_run (decode_output_t * p_state, uint32_t value, size_t run)
{
    size_t first = 0u;

    // Data starts after the final dibit (11) of the start frame delimiter;
    // that dibit itself is not stored.
    if (!p_state->b_in_frame && (DIBIT_STATE_SFD == value))
    {
        p_state->b_in_frame = true;
        first               = 1u;
    }

    if (p_state->b_in_frame)
    {
        // Equivalent to max(1, (run + 5) / 10) without overflowing run + 5.
        // Keeping only a quotient also avoids the duplicate software division
        // calls the target compiler emits for quotient and remainder.
        size_t const threshold = CYCLES_PER_DIBIT - DIBIT_ROUNDING_BIAS;
        size_t       count     = 1u;

        if (run >= threshold)
        {
            count = 1u + ((run - threshold) / CYCLES_PER_DIBIT);
        }

        for (size_t dibit = first;
             (dibit < count) && (p_state->length < p_state->capacity); ++dibit)
        {
            store_dibit(p_state, value);
        }
    }
}

/*!
 * @brief Append one dibit to the octet being assembled, storing the octet
 *        once it holds four dibits.
 *
 * @param[in,out] p_state The decoder output state.
 * @param[in]     value   The dibit value, 0 to 3.
 */
static void
store_dibit (decode_output_t * p_state, uint32_t value)
{
    p_state->octet |= (value << (p_state->dibits * DIBIT_WIDTH_BITS));
    p_state->dibits++;

    if (DIBITS_PER_BYTE == p_state->dibits)
    {
        // The cast is safe: four 2-bit dibits fill exactly eight bits.
        p_state->p_output[p_state->length] = (uint8_t) p_state->octet;
        p_state->length++;
        p_state->octet  = 0u;
        p_state->dibits = 0u;
    }
}

/*** end of file ***/
