#include "rmii_frame.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define TEST_SAMPLE_WORDS (3900U)
#define TEST_PREAMBLE_DIBITS (31U)
#define TEST_CYCLES_PER_DIBIT (10U)
#define TEST_DIBITS_PER_OCTET (4U)
#define TEST_DIBIT_BITS (2U)
#define TEST_SAMPLES_PER_WORD (16U)
#define TEST_MIN_FRAME_BYTES (60U)
#define TEST_PATTERN_MULTIPLIER (37U)
#define TEST_PATTERN_OFFSET (11U)
#define TEST_OCTET_BITS (8U)
#define TEST_CRC_VECTOR_BYTES (9U)
#define TEST_TIMING_MODES (2U)

static uint32_t g_samples[TEST_SAMPLE_WORDS];
static uint8_t  g_frame[RMII_FRAME_MAX_BYTES + RMII_FRAME_FCS_BYTES];
static uint8_t  g_decoded[RMII_FRAME_MAX_BYTES + RMII_FRAME_FCS_BYTES];
static bool     g_shorten_runs;

static void
append_dibit (uint32_t value, size_t * sample_count)
{
    size_t cycles = TEST_CYCLES_PER_DIBIT;
    if (g_shorten_runs && *sample_count > 0U)
    {
        const size_t   prior_index = *sample_count - 1U;
        const uint32_t prior_value =
            (g_samples[prior_index / TEST_SAMPLES_PER_WORD] >>
             ((prior_index % TEST_SAMPLES_PER_WORD) * TEST_DIBIT_BITS)) &
            3U;
        if (value != prior_value)
        {
            /* Exercise nine-cycle runs without accumulated clock drift. */
            --cycles;
        }
    }
    for (size_t cycle = 0U; cycle < cycles; ++cycle)
    {
        const size_t word = *sample_count / TEST_SAMPLES_PER_WORD;
        const size_t shift =
            (*sample_count % TEST_SAMPLES_PER_WORD) * TEST_DIBIT_BITS;
        assert(word < TEST_SAMPLE_WORDS);
        g_samples[word] |= value << shift;
        ++*sample_count;
    }
}

static size_t
encode_frame (size_t length)
{
    size_t sample_count = 0U;
    memset(g_samples, 0, sizeof(g_samples));
    for (size_t dibit = 0U; dibit < TEST_PREAMBLE_DIBITS; ++dibit)
    {
        append_dibit(1U, &sample_count);
    }
    append_dibit(3U, &sample_count);
    for (size_t index = 0U; index < length; ++index)
    {
        for (size_t dibit = 0U; dibit < TEST_DIBITS_PER_OCTET; ++dibit)
        {
            append_dibit((g_frame[index] >> (dibit * TEST_DIBIT_BITS)) & 3U,
                         &sample_count);
        }
    }
    return (sample_count + TEST_SAMPLES_PER_WORD - 1U) / TEST_SAMPLES_PER_WORD;
}

static void
check_frame (size_t frame_length)
{
    for (size_t index = 0U; index < frame_length; ++index)
    {
        g_frame[index] =
            (uint8_t) (index * TEST_PATTERN_MULTIPLIER + TEST_PATTERN_OFFSET);
    }
    const uint32_t crc = rmii_frame_crc(g_frame, frame_length);
    for (size_t octet = 0U; octet < RMII_FRAME_FCS_BYTES; ++octet)
    {
        g_frame[frame_length + octet] =
            (uint8_t) (crc >> (octet * TEST_OCTET_BITS));
    }
    const size_t wire_length = frame_length + RMII_FRAME_FCS_BYTES;
    size_t       words       = 0U;
    for (size_t mode = 0U; mode < TEST_TIMING_MODES; ++mode)
    {
        g_shorten_runs              = mode != 0U;
        words                       = encode_frame(wire_length);
        const size_t decoded_length = rmii_frame_decode_samples(
            g_samples, words, g_decoded, sizeof(g_decoded));
        assert(decoded_length >= wire_length);
        assert(memcmp(g_frame, g_decoded, wire_length) == 0);
        assert(rmii_frame_find_length(g_decoded, decoded_length) ==
               frame_length);
    }

    if (frame_length == RMII_FRAME_MAX_BYTES)
    {
        /* A data-only receive buffer drops the FCS of a maximum frame. */
        const size_t truncated_length = rmii_frame_decode_samples(
            g_samples, words, g_decoded, RMII_FRAME_MAX_BYTES);
        assert(truncated_length == RMII_FRAME_MAX_BYTES);
        assert(rmii_frame_find_length(g_decoded, truncated_length) == 0U);
    }
    g_frame[frame_length] ^= 1U;
    assert(rmii_frame_find_length(g_frame, wire_length) == 0U);
}

int
main (void)
{
    const uint8_t crc_vector[] = "123456789";
    assert(rmii_frame_crc(crc_vector, TEST_CRC_VECTOR_BYTES) ==
           UINT32_C(0xcbf43926));
    assert(rmii_frame_crc(NULL, 1U) == 0U);
    assert(rmii_frame_find_length(NULL, sizeof(g_frame)) == 0U);
    assert(rmii_frame_find_length(g_frame, 0U) == 0U);
    assert(rmii_frame_decode_samples(NULL, 1U, g_decoded, sizeof(g_decoded)) ==
           0U);
    assert(rmii_frame_decode_samples(g_samples, 0U, g_decoded,
                                     sizeof(g_decoded)) == 0U);
    assert(rmii_frame_decode_samples(g_samples, SIZE_MAX, g_decoded,
                                     sizeof(g_decoded)) == 0U);
    check_frame(TEST_MIN_FRAME_BYTES);
    check_frame(RMII_FRAME_MAX_BYTES - RMII_FRAME_FCS_BYTES);
    check_frame(RMII_FRAME_MAX_BYTES);
    puts("RMII frame host tests passed");
    return 0;
}
