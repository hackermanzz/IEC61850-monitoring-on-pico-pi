/** @file capture_decode.c
 * @brief Recover dibits from repeated RMII samples and validate Ethernet FCS.
 *
 * A dibit is two bits. At 10 Mbps each dibit lasts 200 ns, hence ten samples
 * at 50 MHz. Run lengths tolerate the sampling clock's unknown starting phase.
 * This implementation reads three pins, including CRS_DV, unlike the legacy
 * two-pin decoder. No payload-prefix CRC search or unchecked output writes.
 */
#include "capture_decode.h"

#include <stdbool.h> /* Decoder phase flags. */

#define CAPTURE_CRS_MASK 0x24924924u

/* Four bits per lookup reduces CRC work without a 1 KiB byte table. */
static const uint32_t g_crc_table[16] = {
    0x00000000u, 0x1db71064u, 0x3b6e20c8u, 0x26d930acu,
    0x76dc4190u, 0x6b6b51f4u, 0x4db26158u, 0x5005713cu,
    0xedb88320u, 0xf00f9344u, 0xd6d6a3e8u, 0xcb61b38cu,
    0x9b64c2b0u, 0x86d3d2d4u, 0xa00ae278u, 0xbdbdf21cu};

static uint32_t capture_sample(const uint32_t * p_words, size_t index);
static size_t   capture_end(const uint32_t * p_words, size_t count);
static size_t   capture_run(const uint32_t * p_words, size_t start, size_t end,
                            uint32_t value);
static bool     capture_fcs(const uint8_t * p_data, size_t length);

uint32_t
capture_crc32 (const uint8_t * p_data, size_t length)
{
    uint32_t crc   = UINT32_MAX;
    size_t   index = 0u;

    for (index = 0u; length > index; index++)
    {
        crc ^= p_data[index];
        crc = (crc >> 4u) ^ g_crc_table[crc & 15u];
        crc = (crc >> 4u) ^ g_crc_table[crc & 15u];
    }
    return ~crc;
}

/** @brief Resolve the physical tail before decoding; idle RXD is undefined. */
static size_t
capture_end (const uint32_t * p_words, size_t count)
{
    size_t   word   = count;
    size_t   end    = 0u;
    uint32_t active = 0u;

    while ((0u < word) && (0u == end))
    {
        word--;
        active = p_words[word] & CAPTURE_CRS_MASK;
        if (0u != active)
        {
            /* Highest set bit is the last chronological high CRS sample. */
            end = word * 10u
                + (31u - (uint32_t) __builtin_clz(active) - 2u) / 3u + 1u;
            /* A final low half of the LAN8720 tail can contain one dibit. */
            end += 10u;
        }
    }
    if (count * 10u < end)
    {
        end = count * 10u;
    }
    return end;
}

static uint32_t
capture_sample (const uint32_t * p_words, size_t index)
{
    return (p_words[index / 10u] >> (3u + 3u * (index % 10u))) & 3u;
}

/** @brief Skip ten matching samples at a time, then locate the transition. */
static size_t
capture_run (const uint32_t * p_words, size_t start, size_t end, uint32_t value)
{
    size_t   position = start;
    uint32_t pattern =
        (value & 1u) * 0x12492492u | ((value >> 1u) & 1u) * 0x24924924u;

    while ((end > position) && (0u != (position % 10u))
           && (value == capture_sample(p_words, position)))
    {
        position++;
    }
    while ((end >= position + 10u) && (0u == (position % 10u))
           && (pattern == ((p_words[position / 10u] >> 2u) & 0x36db6db6u)))
    {
        position += 10u;
    }
    while ((end > position) && (value == capture_sample(p_words, position)))
    {
        position++;
    }
    return position - start;
}

static bool
capture_fcs (const uint8_t * p_data, size_t length)
{
    size_t   offset   = length - 4u;
    uint32_t expected = (uint32_t) p_data[offset]
                      | ((uint32_t) p_data[offset + 1u] << 8u)
                      | ((uint32_t) p_data[offset + 2u] << 16u)
                      | ((uint32_t) p_data[offset + 3u] << 24u);

    return expected == capture_crc32(p_data, offset);
}

capture_decode_result_t
capture_decode (const uint32_t * p_words, size_t word_count,
                capture_frame_t * p_frame)
{
    size_t                  end        = 0u;
    size_t                  position   = 0u;
    size_t                  run        = 0u;
    size_t                  repeats    = 0u;
    size_t                  bytes      = 0u;
    size_t                  candidate  = 0u;
    uint32_t                value      = 0u;
    uint32_t                bit        = 0u;
    uint8_t                 byte       = 0u;
    bool                    b_preamble = false;
    bool                    b_data     = false;
    bool                    b_overflow = false;
    capture_decode_result_t result     = CAPTURE_DECODE_INVALID;

    if (NULL != p_frame)
    {
        p_frame->length      = 0u;
        p_frame->wire_length = 0u;
    }
    if ((NULL == p_words) || (NULL == p_frame) || (0u == word_count)
        || (7000u < word_count))
    {
        return result;
    }
    end = capture_end(p_words, word_count);
    while ((end > position) && (!b_overflow))
    {
        value = capture_sample(p_words, position);
        run   = capture_run(p_words, position, end, value);
        position += run;
        repeats = (run + 5u) / 10u;
        if ((!b_data) && (1u == value) && (8u <= repeats))
        {
            b_preamble = true;
        }
        else if ((!b_data) && b_preamble && (3u == value) && (0u < repeats))
        {
            b_data = true;
            repeats--; /* SFD's final 11 dibit, not the first frame data. */
        }
        else if (!b_data)
        {
            b_preamble = false;
        }
        while (b_data && (0u < repeats) && (!b_overflow))
        {
            repeats--;
            byte |= (uint8_t) (value << bit);
            bit += 2u;
            if (8u == bit)
            {
                if (CAPTURE_WIRE_MAX + 2u > bytes)
                {
                    p_frame->data[bytes++] = byte;
                }
                else
                {
                    b_overflow = true;
                }
                bit  = 0u;
                byte = 0u;
            }
        }
    }
    result = CAPTURE_DECODE_NO_SFD;
    if (b_overflow)
    {
        result = CAPTURE_DECODE_TOO_LARGE;
    }
    else if (b_data)
    {
        result = (64u > bytes) ? CAPTURE_DECODE_SHORT : CAPTURE_DECODE_BAD_CRC;
        /* Physical end has <= one dibit's ambiguity. Two bytes is a bounded
         * allowance for run rounding, never an arbitrary payload CRC search.
         */
        for (candidate = bytes; (64u <= candidate) && (bytes - candidate <= 2u);
             candidate--)
        {
            if ((CAPTURE_WIRE_MAX >= candidate)
                && capture_fcs(p_frame->data, candidate))
            {
                p_frame->wire_length = (uint16_t) candidate;
                p_frame->length      = (uint16_t) (candidate - 4u);
                result               = CAPTURE_DECODE_OK;
                break;
            }
        }
    }
    return result;
}

/*** end of file ***/
