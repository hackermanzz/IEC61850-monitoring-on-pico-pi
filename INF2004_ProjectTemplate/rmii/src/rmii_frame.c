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
#define CAPTURE_END_SENTINEL (255U)
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
            return index + 1U;
        }
    }
    return 0U;
}

size_t
rmii_frame_decode_samples (const uint32_t * samples, size_t word_count,
                           uint8_t * output, size_t capacity)
{
    size_t  run           = 0U;
    size_t  output_length = 0U;
    uint8_t dibits        = 0U;
    uint8_t octet         = 0U;
    bool    in_frame      = false;
    if (samples == NULL || output == NULL || word_count == 0U ||
        capacity == 0U || word_count > (SIZE_MAX - 1U) / SAMPLES_PER_WORD)
    {
        return 0U;
    }
    const size_t total    = word_count * SAMPLES_PER_WORD;
    uint32_t     previous = samples[0] & DIBIT_VALUE_MASK;
    for (size_t index = 0U; index <= total; ++index)
    {
        /* One past the sample range flushes the final run. */
        const uint32_t value =
            index < total ? (samples[index >> SAMPLE_WORD_SHIFT] >>
                             ((index & SAMPLE_INDEX_MASK) * DIBIT_WIDTH_BITS)) &
                                DIBIT_VALUE_MASK
                          : CAPTURE_END_SENTINEL;
        if (value == previous)
        {
            ++run;
            continue;
        }
        size_t count =
            run / CYCLES_PER_DIBIT +
            (run % CYCLES_PER_DIBIT >= DIBIT_ROUNDING_BIAS ? 1U : 0U);
        if (count == 0U)
        {
            count = 1U;
        }
        size_t first = 0U;
        if (!in_frame)
        {
            if (previous == DIBIT_STATE_SFD)
            {
                in_frame = true;
                first    = 1U;
            }
            else
            {
                previous = value;
                run      = 1U;
                continue;
            }
        }
        for (size_t dibit = first; dibit < count && output_length < capacity;
             ++dibit)
        {
            octet |= (uint8_t) (previous << (dibits * DIBIT_WIDTH_BITS));
            if (++dibits == DIBITS_PER_BYTE)
            {
                output[output_length++] = octet;
                octet                   = 0U;
                dibits                  = 0U;
            }
        }
        previous = value;
        run      = 1U;
    }
    return output_length;
}
