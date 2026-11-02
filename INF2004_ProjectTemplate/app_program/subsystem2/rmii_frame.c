/*
 * Copyright (c) 2021 Sandeep Mistry
 * SPDX-License-Identifier: BSD-3-Clause
 * Pure frame helpers extracted from rmii_ethernet.c for host verification.
 */
#include "rmii_frame.h"

#include <stdbool.h>

#define FRAME_HEADER_BYTES (14U)
#define BITS_PER_OCTET (8U)
#define FCS_OCTET_THIRD (2U)
#define FCS_OCTET_FOURTH (3U)
#define CRC_THIRD_OCTET_SHIFT (16U)
#define CRC_FOURTH_OCTET_SHIFT (24U)
#define SAMPLES_PER_WORD (16U)
#define SAMPLE_WORD_SHIFT (4U)
#define SAMPLE_INDEX_MASK (15U)
#define DIBIT_WIDTH_BITS (2U)
#define DIBITS_PER_BYTE (4U)
#define DIBIT_VALUE_MASK (3U)
#define CYCLES_PER_DIBIT (10U)
#define DIBIT_ROUNDING_BIAS (5U)
#define DIBIT_STATE_SFD (3U)

static uint32_t
crc_update_octet (uint32_t crc, uint8_t octet)
{
    for (uint8_t bit = 0U; bit < BITS_PER_OCTET; ++bit)
    {
        const uint32_t carry = (crc ^ octet) & 1U;
        crc >>= 1U;
        if (carry != 0U)
        {
            crc ^= UINT32_C(0xedb88320);
        }
        octet >>= 1U;
    }
    return crc;
}

uint32_t
rmii_frame_crc (const uint8_t * data, size_t length)
{
    uint32_t crc = UINT32_MAX;
    if (data == NULL)
    {
        return 0U;
    }
    for (size_t index = 0U; index < length; ++index)
    {
        crc = crc_update_octet(crc, data[index]);
    }
    return ~crc;
}

size_t
rmii_frame_find_length (const uint8_t * data, size_t length)
{
    uint32_t crc = UINT32_MAX;
    size_t matched_length = 0U;
    if (data == NULL || length < FRAME_HEADER_BYTES + RMII_FRAME_FCS_BYTES)
    {
        return 0U;
    }
    for (size_t index = 0U; index < length - RMII_FRAME_FCS_BYTES; ++index)
    {
        const uint8_t * fcs     = &data[index + 1U];
        crc                     = crc_update_octet(crc, data[index]);
        const uint32_t expected = ~crc;
        if (index + 1U >= FRAME_HEADER_BYTES && fcs[0] == (uint8_t) expected &&
            fcs[1] == (uint8_t) (expected >> BITS_PER_OCTET) &&
            fcs[FCS_OCTET_THIRD] ==
                (uint8_t) (expected >> CRC_THIRD_OCTET_SHIFT) &&
            fcs[FCS_OCTET_FOURTH] ==
                (uint8_t) (expected >> CRC_FOURTH_OCTET_SHIFT))
        {
            /* Payload bytes can equal an earlier prefix's FCS. Continue to
             * the last verified endpoint instead of truncating a valid frame. */
            matched_length = index + 1U;
        }
    }
    return matched_length;
}

typedef struct
{
    uint8_t *output;
    size_t capacity;
    size_t length;
    uint8_t dibits;
    uint8_t octet;
    bool in_frame;
} decode_output_t;

static void
decode_run (decode_output_t *state, uint32_t value, size_t run)
{
    size_t first = 0U;
    if (!state->in_frame)
    {
        if (value != DIBIT_STATE_SFD) return;
        state->in_frame = true;
        first = 1U;
    }
    /* Equivalent to max(1, (run + 5) / 10), without overflowing run + 5.
     * Keeping only a quotient also avoids duplicate software division calls
     * emitted by the target compiler for quotient/remainder expressions. */
    const size_t threshold = CYCLES_PER_DIBIT - DIBIT_ROUNDING_BIAS;
    const size_t count = run >= threshold ?
        1U + (run - threshold) / CYCLES_PER_DIBIT : 1U;
    for (size_t dibit = first; dibit < count && state->length < state->capacity; ++dibit)
    {
        state->octet |= (uint8_t)(value << (state->dibits * DIBIT_WIDTH_BITS));
        if (++state->dibits == DIBITS_PER_BYTE)
        {
            state->output[state->length++] = state->octet;
            state->octet = 0U;
            state->dibits = 0U;
        }
    }
}

size_t
rmii_frame_decode_samples (const uint32_t * samples, size_t word_count,
                           uint8_t * output, size_t capacity)
{
    if (samples == NULL || output == NULL || word_count == 0U ||
        capacity == 0U || word_count > (SIZE_MAX - 1U) / SAMPLES_PER_WORD)
    {
        return 0U;
    }
    decode_output_t state = {.output = output, .capacity = capacity};
    const size_t total = word_count * SAMPLES_PER_WORD;
    uint32_t previous = samples[0] & DIBIT_VALUE_MASK;
    size_t index = 0U, run = 0U;
    while (index < total)
    {
        const unsigned offset = (unsigned)(index & SAMPLE_INDEX_MASK);
        const uint32_t packed = samples[index >> SAMPLE_WORD_SHIFT] >>
                                (offset * DIBIT_WIDTH_BITS);
        const uint32_t value = packed & DIBIT_VALUE_MASK;
        if (value != previous)
        {
            decode_run(&state, previous, run);
            if (state.length == capacity) return state.length;
            previous = value;
            run = 0U;
        }
        /* XOR with a word containing sixteen copies of this dibit. The first
         * differing bit identifies the next run boundary. ctz(0) is undefined,
         * so an entirely matching word is handled separately. GCC/Clang supply
         * this builtin on both the target and host test compilers. */
        const uint32_t changed = packed ^ (value * UINT32_C(0x55555555));
        unsigned matching = changed ? (unsigned)__builtin_ctz(changed) / DIBIT_WIDTH_BITS
                                    : SAMPLES_PER_WORD;
        const unsigned available = SAMPLES_PER_WORD - offset;
        if (matching > available) matching = available;
        run += matching;
        index += matching;
    }
    decode_run(&state, previous, run);
    return state.length;
}
