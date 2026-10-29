/* Host replay harness for real_packet_fixtures.json. */

#include "analyzer.h"

#include <stdbool.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIXTURE_MAX_FRAMES (100000u)
#define FIXTURE_MAX_CASES (10000u)
#define FIXTURE_MAX_FEATURES (72u)
#define FIXTURE_GOOSE_FEATURE_COUNT (52u)
#define FIXTURE_SV_FEATURE_COUNT (72u)
#define FIXTURE_MIN_PACKET_SIZE (14u)
/* Per-prefix allocation budget includes records, strings, and packet bytes. */
#define FIXTURE_MAX_PREFIX_ALLOCATION_BYTES (8u * 1024u * 1024u)
#define FEATURE_TOLERANCE (2.0e-4f)
#define PROBABILITY_TOLERANCE (1.0e-5f)

typedef struct
{
    uint32_t  index;
    uint64_t  timestamp_us;
    uint32_t  packet_length;
    uint8_t * packet;
} Frame;

typedef struct
{
    char * name;
    float  expected;
} Feature;

typedef struct
{
    uint8_t    protocol;
    char *     id;
    uint8_t    index_count;
    uint32_t * batch_frame_indices;
    uint32_t   feature_count;
    Feature *  features;
    float      expected_probability;
    float      threshold;
    bool       seen;
} TestCase;

typedef struct
{
    char *     capture;
    uint32_t   frame_count;
    Frame *    frames;
    uint32_t   case_count;
    TestCase * cases;
} Prefix;

typedef struct
{
    size_t allocated_bytes;
} allocation_budget_t;

static bool
reserve_allocation (allocation_budget_t * budget, size_t count,
                    size_t element_size)
{
    size_t bytes = 0u;

    if (budget == NULL ||
        budget->allocated_bytes > FIXTURE_MAX_PREFIX_ALLOCATION_BYTES ||
        (count != 0u && element_size > SIZE_MAX / count))
    {
        return false;
    }
    bytes = count * element_size;
    if (bytes > FIXTURE_MAX_PREFIX_ALLOCATION_BYTES - budget->allocated_bytes)
    {
        return false;
    }
    budget->allocated_bytes += bytes;
    return true;
}

static bool
read_bytes (FILE * input, void * output, size_t size)
{
    return fread(output, 1u, size, input) == size;
}

static bool
read_u8 (FILE * input, uint8_t * value)
{
    return read_bytes(input, value, sizeof(*value));
}

static bool
read_u16 (FILE * input, uint16_t * value)
{
    uint8_t bytes[2];

    if (!read_bytes(input, bytes, sizeof(bytes)))
    {
        return false;
    }
    *value = (uint16_t) ((uint16_t) bytes[0] | ((uint16_t) bytes[1] << 8u));
    return true;
}

static bool
read_u32 (FILE * input, uint32_t * value)
{
    uint8_t bytes[4];

    if (!read_bytes(input, bytes, sizeof(bytes)))
    {
        return false;
    }
    *value = (uint32_t) bytes[0] | ((uint32_t) bytes[1] << 8u) |
             ((uint32_t) bytes[2] << 16u) | ((uint32_t) bytes[3] << 24u);
    return true;
}

static bool
read_u64 (FILE * input, uint64_t * value)
{
    uint8_t bytes[8];
    size_t  index;

    if (!read_bytes(input, bytes, sizeof(bytes)))
    {
        return false;
    }
    *value = 0u;
    for (index = 0u; index < sizeof(bytes); ++index)
    {
        *value |= (uint64_t) bytes[index] << (8u * index);
    }
    return true;
}

static bool
read_f32 (FILE * input, float * value)
{
    uint32_t bits;

    if (!read_u32(input, &bits) || sizeof(*value) != sizeof(bits))
    {
        return false;
    }
    (void) memcpy(value, &bits, sizeof(*value));
    return isfinite(*value);
}

static bool
read_string (FILE * input, char ** value, allocation_budget_t * budget)
{
    uint16_t length;

    *value = NULL;
    if (!read_u16(input, &length))
    {
        return false;
    }
    if (!reserve_allocation(budget, (size_t) length + 1u, sizeof(char)))
    {
        return false;
    }
    *value = (char *) malloc((size_t) length + 1u);
    if (*value == NULL)
    {
        return false;
    }
    if ((length > 0u) && !read_bytes(input, *value, length))
    {
        free(*value);
        *value = NULL;
        return false;
    }
    if ((length > 0u) && memchr(*value, '\0', length) != NULL)
    {
        free(*value);
        *value = NULL;
        return false;
    }
    (*value)[length] = '\0';
    return true;
}

static void
free_prefix (Prefix * prefix)
{
    uint32_t index;

    if (prefix->frames != NULL)
    {
        for (index = 0u; index < prefix->frame_count; ++index)
        {
            free(prefix->frames[index].packet);
        }
    }
    if (prefix->cases != NULL)
    {
        for (index = 0u; index < prefix->case_count; ++index)
        {
            uint32_t   feature_index;
            TestCase * test_case = &prefix->cases[index];

            free(test_case->id);
            free(test_case->batch_frame_indices);
            if (test_case->features != NULL)
            {
                for (feature_index = 0u;
                     feature_index < test_case->feature_count; ++feature_index)
                {
                    free(test_case->features[feature_index].name);
                }
            }
            free(test_case->features);
        }
    }
    free(prefix->capture);
    free(prefix->frames);
    free(prefix->cases);
    (void) memset(prefix, 0, sizeof(*prefix));
}

static bool
read_prefix (FILE * input, Prefix * prefix)
{
    allocation_budget_t budget = {0u};
    uint32_t            index  = 0u;

    if (!read_string(input, &prefix->capture, &budget) ||
        !read_u32(input, &prefix->frame_count) ||
        (prefix->frame_count > FIXTURE_MAX_FRAMES))
    {
        return false;
    }
    if (!reserve_allocation(&budget, prefix->frame_count,
                            sizeof(*prefix->frames)))
    {
        return false;
    }
    prefix->frames = (Frame *) calloc(prefix->frame_count, sizeof(Frame));
    if ((prefix->frame_count > 0u) && (prefix->frames == NULL))
    {
        return false;
    }
    for (index = 0u; index < prefix->frame_count; ++index)
    {
        Frame * frame = &prefix->frames[index];

        if (!read_u32(input, &frame->index) ||
            !read_u64(input, &frame->timestamp_us) ||
            !read_u32(input, &frame->packet_length) ||
            (frame->packet_length < FIXTURE_MIN_PACKET_SIZE) ||
            (frame->packet_length > ANALYZER_MAXIMUM_FRAME_LENGTH) ||
            !reserve_allocation(&budget, frame->packet_length,
                                sizeof(*frame->packet)))
        {
            return false;
        }
        frame->packet = (uint8_t *) malloc(frame->packet_length);
        if ((frame->packet_length > 0u) &&
            ((frame->packet == NULL) ||
             !read_bytes(input, frame->packet, frame->packet_length)))
        {
            return false;
        }
    }

    if (!read_u32(input, &prefix->case_count) ||
        (prefix->case_count > FIXTURE_MAX_CASES))
    {
        return false;
    }
    if (!reserve_allocation(&budget, prefix->case_count,
                            sizeof(*prefix->cases)))
    {
        return false;
    }
    prefix->cases = (TestCase *) calloc(prefix->case_count, sizeof(TestCase));
    if ((prefix->case_count > 0u) && (prefix->cases == NULL))
    {
        return false;
    }
    for (index = 0u; index < prefix->case_count; ++index)
    {
        TestCase * test_case = &prefix->cases[index];
        uint8_t    index_count;
        uint32_t   feature_index;

        if (!read_u8(input, &test_case->protocol) || test_case->protocol > 1u ||
            !read_string(input, &test_case->id, &budget) ||
            !read_u8(input, &index_count))
        {
            return false;
        }
        if (index_count != ANALYZER_BATCH_FRAME_COUNT ||
            !reserve_allocation(&budget, index_count,
                                sizeof(*test_case->batch_frame_indices)))
        {
            return false;
        }
        test_case->index_count = index_count;
        test_case->batch_frame_indices =
            (uint32_t *) calloc(index_count, sizeof(uint32_t));
        if ((index_count > 0u) && (test_case->batch_frame_indices == NULL))
        {
            return false;
        }
        for (feature_index = 0u; feature_index < index_count; ++feature_index)
        {
            if (!read_u32(input,
                          &test_case->batch_frame_indices[feature_index]))
            {
                return false;
            }
        }
        if (!read_u32(input, &test_case->feature_count) ||
            (test_case->feature_count > FIXTURE_MAX_FEATURES) ||
            (test_case->feature_count != ((test_case->protocol == 0u)
                                              ? FIXTURE_GOOSE_FEATURE_COUNT
                                              : FIXTURE_SV_FEATURE_COUNT)) ||
            !reserve_allocation(&budget, test_case->feature_count,
                                sizeof(*test_case->features)))
        {
            return false;
        }
        test_case->features =
            (Feature *) calloc(test_case->feature_count, sizeof(Feature));
        if ((test_case->feature_count > 0u) && (test_case->features == NULL))
        {
            return false;
        }
        for (feature_index = 0u; feature_index < test_case->feature_count;
             ++feature_index)
        {
            if (!read_string(input, &test_case->features[feature_index].name,
                             &budget) ||
                !read_f32(input, &test_case->features[feature_index].expected))
            {
                return false;
            }
        }
        if (!read_f32(input, &test_case->expected_probability) ||
            !read_f32(input, &test_case->threshold) ||
            test_case->expected_probability < 0.0f ||
            test_case->expected_probability > 1.0f ||
            test_case->threshold < 0.0f || test_case->threshold > 1.0f)
        {
            return false;
        }
    }
    return true;
}

static bool
compare_case (const Prefix * prefix, TestCase * test_case, uint32_t frame_index,
              const analyzer_result_t * result)
{
    analyzer_protocol_t        expected_protocol;
    analyzer_protocol_t        actual_protocol = ANALYZER_PROTOCOL_GOOSE;
    float                      actual_features[72];
    size_t                     actual_count = 0u;
    size_t                     index;
    float                      max_error = 0.0f;
    float                      probability_error;
    uint8_t                    expected_label;
    uint64_t                   feature_hash = UINT64_C(14695981039346656037);
    static uint8_t             raw_frame[ANALYZER_MAXIMUM_FRAME_LENGTH];
    analyzer_packet_metadata_t packet_metadata;

    if ((test_case->index_count == 0u) || test_case->seen ||
        (test_case->batch_frame_indices[test_case->index_count - 1u] !=
         frame_index))
    {
        return true;
    }
    if (!result->prediction_ready)
    {
        return true;
    }
    expected_protocol = (test_case->protocol == 0u)
                            ? ANALYZER_PROTOCOL_GOOSE
                            : ANALYZER_PROTOCOL_SAMPLED_VALUES;
    if (result->protocol != expected_protocol)
    {
        return true;
    }
    for (index = 0u; index < ANALYZER_BATCH_FRAME_COUNT; ++index)
    {
        const Frame * expected_frame = NULL;
        uint32_t      fixture_index  = test_case->batch_frame_indices[index];
        uint32_t      frame_cursor   = 0u;

        for (frame_cursor = 0u; frame_cursor < prefix->frame_count;
             ++frame_cursor)
        {
            if (prefix->frames[frame_cursor].index == fixture_index)
            {
                expected_frame = &prefix->frames[frame_cursor];
                break;
            }
        }
        if (expected_frame == NULL ||
            !analyzer_copy_last_batch_frame(index, raw_frame, sizeof(raw_frame),
                                            &packet_metadata) ||
            packet_metadata.capture_sequence != fixture_index ||
            packet_metadata.frame_length != expected_frame->packet_length ||
            memcmp(raw_frame, expected_frame->packet,
                   expected_frame->packet_length) != 0)
        {
            (void) fprintf(
                stderr,
                "%s: retained raw batch frame %lu did not match fixture\n",
                test_case->id, (unsigned long) index);
            return false;
        }
    }
    if (!analyzer_copy_last_batch_features(actual_features, 72u, &actual_count,
                                           &actual_protocol) ||
        (actual_protocol != expected_protocol) ||
        (actual_count != test_case->feature_count))
    {
        (void) fprintf(stderr,
                       "%s: batch feature API returned unexpected shape\n",
                       test_case->id);
        return false;
    }
    for (index = 0u; index < actual_count; ++index)
    {
        if (!isfinite(actual_features[index]))
        {
            (void) fprintf(stderr, "%s: non-finite actual feature %lu\n",
                           test_case->id, (unsigned long) index);
            return false;
        }
        const float error =
            fabsf(actual_features[index] - test_case->features[index].expected);

        if (error > max_error)
        {
            max_error = error;
        }
        if (error > FEATURE_TOLERANCE)
        {
            (void) fprintf(
                stderr, "%s: feature %s expected=%.9g actual=%.9g error=%.9g\n",
                test_case->id, test_case->features[index].name,
                (double) test_case->features[index].expected,
                (double) actual_features[index], (double) error);
            for (index = 0u; index < actual_count; ++index)
            {
                (void) fprintf(stderr, "  [%lu] %s expected=%.9g actual=%.9g\n",
                               (unsigned long) index,
                               test_case->features[index].name,
                               (double) test_case->features[index].expected,
                               (double) actual_features[index]);
            }
            return false;
        }
    }
    probability_error =
        fabsf(result->primary_probability - test_case->expected_probability);
    if (!isfinite(result->primary_probability) ||
        result->primary_probability < 0.0f ||
        result->primary_probability > 1.0f)
    {
        (void) fprintf(stderr, "%s: invalid actual probability\n",
                       test_case->id);
        return false;
    }
    expected_label =
        (uint8_t) (test_case->expected_probability >= test_case->threshold);
    if ((probability_error > PROBABILITY_TOLERANCE) ||
        (result->primary_label != expected_label))
    {
        (void) fprintf(stderr,
                       "%s: probability/label mismatch expected=%.9g "
                       "actual=%.9g error=%.9g\n",
                       test_case->id, (double) test_case->expected_probability,
                       (double) result->primary_probability,
                       (double) probability_error);
        return false;
    }
    for (index = 0u; index <= actual_count; ++index)
    {
        uint32_t     bits;
        unsigned int byte_index;
        const float  value = (index < actual_count)
                                 ? actual_features[index]
                                 : result->primary_probability;

        (void) memcpy(&bits, &value, sizeof(bits));
        for (byte_index = 0u; byte_index < sizeof(bits); ++byte_index)
        {
            feature_hash ^= (uint8_t) (bits >> (8u * byte_index));
            feature_hash *= UINT64_C(1099511628211);
        }
    }
    test_case->seen = true;
    (void) printf(
        "%s: features=%lu max_feature_error=%.9g probability_error=%.9g "
        "feature_hash=%016llx PASS\n",
        test_case->id, (unsigned long) actual_count, (double) max_error,
        (double) probability_error, (unsigned long long) feature_hash);
    return true;
}

static bool
replay_prefix (Prefix * prefix)
{
    uint32_t frame_index;

    analyzer_reset();
    for (frame_index = 0u; frame_index < prefix->frame_count; ++frame_index)
    {
        const Frame *     frame = &prefix->frames[frame_index];
        analyzer_result_t result;
        uint32_t          case_index;

        if (!analyzer_process_ethernet_capture(
                frame->packet, frame->packet_length, frame->timestamp_us,
                frame->index, &result))
        {
            (void) fprintf(stderr, "%s: analyzer rejected source frame %lu\n",
                           prefix->capture, (unsigned long) frame->index);
            return false;
        }
        for (case_index = 0u; case_index < prefix->case_count; ++case_index)
        {
            if (!compare_case(prefix, &prefix->cases[case_index], frame->index,
                              &result))
            {
                return false;
            }
        }
    }
    for (frame_index = 0u; frame_index < prefix->case_count; ++frame_index)
    {
        if (!prefix->cases[frame_index].seen)
        {
            (void) fprintf(stderr, "%s: expected batch was not emitted\n",
                           prefix->cases[frame_index].id);
            return false;
        }
    }
    return true;
}

int
main (int argc, char ** argv)
{
    FILE *   input;
    uint8_t  magic[4];
    uint32_t prefix_count;
    uint32_t index;
    int      result = 1;

    if (argc != 2)
    {
        (void) fprintf(stderr, "usage: batch_fixture_replay fixture.bin\n");
        return 2;
    }
    input = fopen(argv[1], "rb");
    if ((input == NULL) || !read_bytes(input, magic, sizeof(magic)) ||
        (memcmp(magic, "BPF1", sizeof(magic)) != 0) ||
        !read_u32(input, &prefix_count) || (prefix_count > FIXTURE_MAX_CASES))
    {
        (void) fprintf(stderr, "invalid fixture binary\n");
        if (input != NULL)
        {
            (void) fclose(input);
        }
        return 2;
    }
    result = 0;
    for (index = 0u; index < prefix_count; ++index)
    {
        Prefix prefix = {0};

        if (!read_prefix(input, &prefix))
        {
            (void) fprintf(stderr, "truncated or invalid fixture prefix %lu\n",
                           (unsigned long) index);
            result = 2;
            free_prefix(&prefix);
            break;
        }
        if (!replay_prefix(&prefix))
        {
            result = 1;
            free_prefix(&prefix);
            break;
        }
        free_prefix(&prefix);
    }
    if (result == 0 && fgetc(input) != EOF)
    {
        (void) fprintf(stderr, "unexpected trailing fixture data\n");
        result = 2;
    }
    if (result == 0 && ferror(input))
    {
        (void) fprintf(stderr, "failed while reading fixture input\n");
        result = 2;
    }
    if (fclose(input) != 0)
    {
        (void) fprintf(stderr, "failed to close fixture input\n");
        result = 2;
    }
    if (result == 0)
    {
        (void) puts("real-packet batch feature and score parity PASS");
    }
    return result;
}
