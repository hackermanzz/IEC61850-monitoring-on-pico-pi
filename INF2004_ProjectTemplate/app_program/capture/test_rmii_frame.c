/** @file test_rmii_frame.c
 *
 * @brief Test cases for the RMII frame helpers (rmii_frame.c): CRC-32,
 * frame length recovery and sample decoding.
 *
 * @par
 * The CRC cases use published CRC-32 check values. The decode cases build
 * the 50 MHz sample words that the PIO receive program would capture for a
 * known frame (preamble, start frame delimiter, frame, FCS), then check that
 * the decoder gives back exactly that frame.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rmii_frame.h"
#include "test_rmii_frame.h"

#if APP_TEST

// Sample layout of the PIO program: sixteen 2-bit samples per word, the
// first sample in the low bits; one dibit lasts ten samples at 10 Mbps.
//
#define SAMPLES_PER_WORD  (16u)
#define BITS_PER_SAMPLE   (2u)
#define SAMPLE_MASK       (3u)
#define SAMPLES_PER_DIBIT (10u)
#define DIBITS_PER_BYTE   (4u)
#define BITS_PER_BYTE     (8u)

// Ethernet framing.
//
#define PREAMBLE_BYTES   (7u)
#define PREAMBLE_OCTET   (0x55u)
#define SFD_OCTET        (0xD5u)
#define TEST_FRAME_BYTES (60u)
#define WIRE_FRAME_BYTES (TEST_FRAME_BYTES + RMII_FRAME_FCS_BYTES)
#define HEADER_BYTES     (14u)
#define TRAILING_BYTES   (3u)
#define IDLE_SAMPLES     (40u)
#define IDLE_DIBIT       (0u)
#define TRAILING_OCTET   (0xEEu)

// Buffer sizes, with room for jitter and idle samples.
//
#define MAXIMUM_DIBITS                                                         \
    ((PREAMBLE_BYTES + 1u + WIRE_FRAME_BYTES) * DIBITS_PER_BYTE)
#define MAXIMUM_WORDS                                                          \
    (((((MAXIMUM_DIBITS + 1u) * SAMPLES_PER_DIBIT) + IDLE_SAMPLES)             \
      / SAMPLES_PER_WORD)                                                      \
     + 2u)
#define DECODE_CAPACITY (2u * WIRE_FRAME_BYTES)
#define SMALL_CAPACITY  (10u)
#define CANARY_BYTES    (8u)
#define CANARY_OCTET    (0xA5u)
#define JITTER_STEPS    (8u)

// Published CRC-32 (IEEE 802.3) check values.
//
#define CHECK_DIGITS_CRC (0xCBF43926u)
#define QUICK_FOX_CRC    (0x414FA339u)

/*!
 * @brief One test case.
 */
typedef struct
{
    char const * p_id;
    char const * p_description;
    bool (*p_run)(void);
} test_case_t;

static bool   case_crc_check_digits(void);
static bool   case_crc_quick_fox(void);
static bool   case_crc_null(void);
static bool   case_length_found(void);
static bool   case_length_trailing_bytes(void);
static bool   case_length_corrupted(void);
static bool   case_length_too_short(void);
static bool   case_decode_exact(void);
static bool   case_decode_jitter(void);
static bool   case_decode_end_to_end(void);
static bool   case_decode_capacity(void);
static bool   case_decode_invalid(void);
static bool   case_decode_no_sfd(void);
static void   build_wire_frame(void);
static size_t encode_samples(uint8_t const * p_bytes, size_t length,
                             bool b_with_sfd, bool b_with_jitter,
                             bool b_with_idle);
static void   put_sample(size_t index, uint32_t value);

static test_case_t const g_cases[] = {
    {"RF-01", "CRC-32 of \"123456789\" is 0xCBF43926", case_crc_check_digits},
    {"RF-02", "CRC-32 of the quick-fox sentence is 0x414FA339",
     case_crc_quick_fox},
    {"RF-03", "CRC-32 of a NULL buffer is 0", case_crc_null},
    {"RF-04", "frame length is found from a matching FCS", case_length_found},
    {"RF-05", "bytes after the FCS are ignored", case_length_trailing_bytes},
    {"RF-06", "a frame with one corrupted byte is rejected",
     case_length_corrupted},
    {"RF-07", "input shorter than header and FCS is rejected",
     case_length_too_short},
    {"RF-08", "decode returns the exact frame from ideal samples",
     case_decode_exact},
    {"RF-09", "decode tolerates up to 4 samples of jitter per run",
     case_decode_jitter},
    {"RF-10", "decode and length search recover the frame end to end",
     case_decode_end_to_end},
    {"RF-11", "decode never writes past the output capacity",
     case_decode_capacity},
    {"RF-12", "decode rejects NULL or empty arguments", case_decode_invalid},
    {"RF-13", "decode ignores samples without a start frame delimiter",
     case_decode_no_sfd},
};

// Run-length jitter applied in turn to each run of equal dibits.
//
static int32_t const g_jitter[JITTER_STEPS] = {-4, 3, -2, 4, 0, -3, 2, -1};

static uint8_t  g_frame[WIRE_FRAME_BYTES + TRAILING_BYTES];
static uint32_t g_samples[MAXIMUM_WORDS];
static uint8_t  g_dibits[MAXIMUM_DIBITS];
static uint8_t  g_decoded[DECODE_CAPACITY + CANARY_BYTES];

/*!
 * @brief Give the number of test cases.
 *
 * @return The number of cases.
 */
size_t
test_rmii_frame_count (void)
{
    return (sizeof(g_cases) / sizeof(g_cases[0]));
}

/*!
 * @brief Run one test case.
 *
 * @param[in]  index          The case index, below test_rmii_frame_count().
 * @param[out] pp_id          Receives the test ID.
 * @param[out] pp_description Receives the test description.
 *
 * @return True if the case passed; false if it failed or does not exist.
 */
bool
test_rmii_frame_run (size_t index, char const ** pp_id,
                     char const ** pp_description)
{
    bool b_passed = false;

    if ((index < test_rmii_frame_count()) && (NULL != pp_id)
        && (NULL != pp_description))
    {
        *pp_id          = g_cases[index].p_id;
        *pp_description = g_cases[index].p_description;
        build_wire_frame();
        b_passed = g_cases[index].p_run();
    }

    return (b_passed);
}

/*!
 * @brief RF-01: the standard check value of the nine digits.
 *
 * @return True if the case passed.
 */
static bool
case_crc_check_digits (void)
{
    static char const digits[] = "123456789";

    // The cast is safe: the CRC reads the characters as bytes.
    return (CHECK_DIGITS_CRC
            == rmii_frame_crc((uint8_t const *) digits, sizeof(digits) - 1u));
}

/*!
 * @brief RF-02: the published value of a longer text.
 *
 * @return True if the case passed.
 */
static bool
case_crc_quick_fox (void)
{
    static char const text[] = "The quick brown fox jumps over the lazy dog";

    // The cast is safe: the CRC reads the characters as bytes.
    return (QUICK_FOX_CRC
            == rmii_frame_crc((uint8_t const *) text, sizeof(text) - 1u));
}

/*!
 * @brief RF-03: a NULL buffer gives 0.
 *
 * @return True if the case passed.
 */
static bool
case_crc_null (void)
{
    return (0u == rmii_frame_crc(NULL, TEST_FRAME_BYTES));
}

/*!
 * @brief RF-04: the length of a frame with its FCS.
 *
 * @return True if the case passed.
 */
static bool
case_length_found (void)
{
    return (TEST_FRAME_BYTES
            == rmii_frame_find_length(g_frame, WIRE_FRAME_BYTES));
}

/*!
 * @brief RF-05: extra captured bytes after the FCS.
 *
 * @return True if the case passed.
 */
static bool
case_length_trailing_bytes (void)
{
    return (
        TEST_FRAME_BYTES
        == rmii_frame_find_length(g_frame, WIRE_FRAME_BYTES + TRAILING_BYTES));
}

/*!
 * @brief RF-06: one flipped bit in the payload.
 *
 * @return True if the case passed.
 */
static bool
case_length_corrupted (void)
{
    g_frame[HEADER_BYTES + 1u] ^= 1u;

    return (0u == rmii_frame_find_length(g_frame, WIRE_FRAME_BYTES));
}

/*!
 * @brief RF-07: fewer bytes than a header and an FCS.
 *
 * @return True if the case passed.
 */
static bool
case_length_too_short (void)
{
    return ((0u
             == rmii_frame_find_length(
                 g_frame, (HEADER_BYTES + RMII_FRAME_FCS_BYTES) - 1u))
            && (0u == rmii_frame_find_length(NULL, WIRE_FRAME_BYTES)));
}

/*!
 * @brief RF-08: ideal ten-sample dibits decode to the exact frame.
 *
 * @return True if the case passed.
 */
static bool
case_decode_exact (void)
{
    size_t const words =
        encode_samples(g_frame, WIRE_FRAME_BYTES, true, false, false);
    size_t const length =
        rmii_frame_decode_samples(g_samples, words, g_decoded, DECODE_CAPACITY);

    return ((WIRE_FRAME_BYTES == length)
            && (0 == memcmp(g_decoded, g_frame, WIRE_FRAME_BYTES)));
}

/*!
 * @brief RF-09: each run of equal dibits is up to four samples off.
 *
 * @return True if the case passed.
 */
static bool
case_decode_jitter (void)
{
    size_t const words =
        encode_samples(g_frame, WIRE_FRAME_BYTES, true, true, false);
    size_t const length =
        rmii_frame_decode_samples(g_samples, words, g_decoded, DECODE_CAPACITY);

    return ((WIRE_FRAME_BYTES == length)
            && (0 == memcmp(g_decoded, g_frame, WIRE_FRAME_BYTES)));
}

/*!
 * @brief RF-10: jittered samples with idle line after the frame, as the
 *        capture task sees them.
 *
 * @return True if the case passed.
 */
static bool
case_decode_end_to_end (void)
{
    size_t const words =
        encode_samples(g_frame, WIRE_FRAME_BYTES, true, true, true);
    size_t const length =
        rmii_frame_decode_samples(g_samples, words, g_decoded, DECODE_CAPACITY);

    return ((length >= WIRE_FRAME_BYTES)
            && (TEST_FRAME_BYTES == rmii_frame_find_length(g_decoded, length))
            && (0 == memcmp(g_decoded, g_frame, TEST_FRAME_BYTES)));
}

/*!
 * @brief RF-11: a small output buffer is filled but not overrun.
 *
 * @return True if the case passed.
 */
static bool
case_decode_capacity (void)
{
    size_t const words =
        encode_samples(g_frame, WIRE_FRAME_BYTES, true, false, false);
    size_t length = 0u;
    bool   b_ok   = true;
    size_t index  = 0u;

    memset(g_decoded, CANARY_OCTET, sizeof(g_decoded));
    length =
        rmii_frame_decode_samples(g_samples, words, g_decoded, SMALL_CAPACITY);

    for (index = SMALL_CAPACITY; index < (SMALL_CAPACITY + CANARY_BYTES);
         ++index)
    {
        b_ok = b_ok && (CANARY_OCTET == g_decoded[index]);
    }

    return (b_ok && (SMALL_CAPACITY == length)
            && (0 == memcmp(g_decoded, g_frame, SMALL_CAPACITY)));
}

/*!
 * @brief RF-12: NULL buffers, no words or no capacity give 0 bytes.
 *
 * @return True if the case passed.
 */
static bool
case_decode_invalid (void)
{
    size_t const words =
        encode_samples(g_frame, WIRE_FRAME_BYTES, true, false, false);

    return (
        (0u
         == rmii_frame_decode_samples(NULL, words, g_decoded, DECODE_CAPACITY))
        && (0u
            == rmii_frame_decode_samples(g_samples, 0u, g_decoded,
                                         DECODE_CAPACITY))
        && (0u
            == rmii_frame_decode_samples(g_samples, words, NULL,
                                         DECODE_CAPACITY))
        && (0u == rmii_frame_decode_samples(g_samples, words, g_decoded, 0u)));
}

/*!
 * @brief RF-13: a preamble without the final SFD dibit gives no data.
 *
 * @return True if the case passed.
 */
static bool
case_decode_no_sfd (void)
{
    size_t const words = encode_samples(g_frame, 0u, false, false, false);

    return (0u
            == rmii_frame_decode_samples(g_samples, words, g_decoded,
                                         DECODE_CAPACITY));
}

/*!
 * @brief Build a GOOSE-like test frame, its FCS and three trailing bytes.
 */
static void
build_wire_frame (void)
{
    static uint8_t const header[HEADER_BYTES] = {
        0x01u, 0x0Cu, 0xCDu, 0x01u, 0x00u, 0x01u, // Destination.
        0x02u, 0x00u, 0x00u, 0x00u, 0x01u, 0x01u, // Source.
        0x88u, 0xB8u,                             // EtherType: GOOSE.
    };
    uint32_t fcs   = 0u;
    size_t   index = 0u;

    memcpy(g_frame, header, sizeof(header));

    for (index = HEADER_BYTES; index < TEST_FRAME_BYTES; ++index)
    {
        // The cast is safe: the payload pattern keeps the low eight bits.
        g_frame[index] = (uint8_t) ((index * 7u) + 3u);
    }

    // The FCS goes on the wire least significant byte first.
    fcs = rmii_frame_crc(g_frame, TEST_FRAME_BYTES);

    for (index = 0u; index < RMII_FRAME_FCS_BYTES; ++index)
    {
        // The cast is safe: it keeps one byte of the FCS.
        g_frame[TEST_FRAME_BYTES + index] =
            (uint8_t) (fcs >> (index * BITS_PER_BYTE));
    }

    for (index = 0u; index < TRAILING_BYTES; ++index)
    {
        g_frame[WIRE_FRAME_BYTES + index] = TRAILING_OCTET;
    }
}

/*!
 * @brief Build the RMII sample words for a preamble and some bytes.
 *
 * @param[in] p_bytes       The bytes after the preamble.
 * @param[in] length        The number of bytes.
 * @param[in] b_with_sfd    True to end the preamble with the SFD octet.
 * @param[in] b_with_jitter True to lengthen or shorten each run of equal
 *                          dibits by up to four samples.
 * @param[in] b_with_idle   True to add an idle line (00) after the bytes.
 *
 * @return The number of sample words built.
 */
static size_t
encode_samples (uint8_t const * p_bytes, size_t length, bool b_with_sfd,
                bool b_with_jitter, bool b_with_idle)
{
    size_t dibit_count  = 0u;
    size_t sample_count = 0u;
    size_t run_count    = 0u;
    size_t index        = 0u;

    memset(g_samples, 0, sizeof(g_samples));

    // Ethernet sends each octet least significant dibit first.
    for (index = 0u; index < (PREAMBLE_BYTES + 1u + length); ++index)
    {
        uint32_t octet  = PREAMBLE_OCTET;
        size_t   offset = 0u;

        if (PREAMBLE_BYTES == index)
        {
            octet = b_with_sfd ? SFD_OCTET : PREAMBLE_OCTET;
        }
        else if (index > PREAMBLE_BYTES)
        {
            octet = p_bytes[index - PREAMBLE_BYTES - 1u];
        }
        else
        {
            // A preamble octet.
        }

        for (offset = 0u; offset < DIBITS_PER_BYTE; ++offset)
        {
            // The cast is safe: the mask leaves a value from 0 to 3.
            g_dibits[dibit_count] =
                (uint8_t) ((octet >> (offset * BITS_PER_SAMPLE)) & SAMPLE_MASK);
            dibit_count++;
        }
    }

    index = 0u;

    while (index < dibit_count)
    {
        size_t  run    = 1u;
        int32_t extra  = 0;
        size_t  sample = 0u;
        size_t  total  = 0u;

        while (((index + run) < dibit_count)
               && (g_dibits[index + run] == g_dibits[index]))
        {
            run++;
        }

        if (b_with_jitter)
        {
            extra = g_jitter[run_count % JITTER_STEPS];
        }

        // The casts are safe: a run is at least ten samples long and the
        // jitter at most four.
        total = (size_t) ((int32_t) (run * SAMPLES_PER_DIBIT) + extra);

        for (sample = 0u; sample < total; ++sample)
        {
            put_sample(sample_count, g_dibits[index]);
            sample_count++;
        }

        index += run;
        run_count++;
    }

    if (b_with_idle)
    {
        for (index = 0u; index < IDLE_SAMPLES; ++index)
        {
            put_sample(sample_count, IDLE_DIBIT);
            sample_count++;
        }
    }

    return ((sample_count + SAMPLES_PER_WORD - 1u) / SAMPLES_PER_WORD);
}

/*!
 * @brief Store one 2-bit sample in the sample words.
 *
 * @param[in] index The sample number.
 * @param[in] value The dibit value, 0 to 3.
 */
static void
put_sample (size_t index, uint32_t value)
{
    size_t const word = index / SAMPLES_PER_WORD;

    if (word < MAXIMUM_WORDS)
    {
        g_samples[word] |= (value & SAMPLE_MASK)
                        << ((index % SAMPLES_PER_WORD) * BITS_PER_SAMPLE);
    }
}

#endif /* APP_TEST */

/*** end of file ***/
