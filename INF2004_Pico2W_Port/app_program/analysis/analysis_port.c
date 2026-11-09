/** @file analysis_port.c
 * @brief Preserve reference features/models while adapting capture ownership.
 */
#include "analysis_port.h"

#include <math.h> /* NaN-aware reference comparison in startup self-check. */
#include <stddef.h>
#include <string.h>
#include "pico/time.h"
#include "analyzer.h"
#include "iec_rules.h"
#include "analysis_fixture.h"
#include "analysis_expected.h"
#if PORT_DETECTION
#include "../health/detection.h"
#endif

static analysis_port_stats_t g_stats;
static analyzer_result_t     g_result;
static uint32_t              g_sequence;
static uint32_t              g_generation;
static uint64_t              g_timestamp;
static bool                  gb_have_previous;

/** @brief Read only the bounded Ethernet/VLAN header for diagnostics.
 * @return Final EtherType, or zero for an incomplete/unsupported header.
 */
static uint16_t
analysis_port_type (const capture_frame_t * p_frame)
{
    size_t   offset = 12u;
    uint32_t tags   = 0u;
    uint16_t type   = 0u;

    if (14u <= p_frame->length)
    {
        type = (uint16_t) (((uint16_t) p_frame->data[offset] << 8u)
                           | p_frame->data[offset + 1u]);
        while (((0x8100u == type) || (0x88a8u == type)) && (2u > tags))
        {
            offset += 4u;
            if (offset + 2u > p_frame->length)
            {
                return 0u;
            }
            type = (uint16_t) (((uint16_t) p_frame->data[offset] << 8u)
                               | p_frame->data[offset + 1u]);
            tags++;
        }
    }
    return type;
}

/** @brief Permit math-library rounding, but never hide a missing feature. */
static bool
analysis_port_matches (float actual, uint32_t expected_bits)
{
    float expected = 0.0f;

    memcpy(&expected, &expected_bits, sizeof(expected));
    return (isnan(actual) && isnan(expected))
        || (isfinite(actual) && isfinite(expected)
            && (fabsf(actual - expected)
                <= 0.000001f + 0.00001f * fabsf(expected)));
}

void
analysis_port_init (void)
{
    memset(&g_stats, 0, sizeof(g_stats));
    memset(&g_result, 0, sizeof(g_result));
    gb_have_previous = false;
    analyzer_reset();
}

void
analysis_port_observe (const capture_frame_t * p_frame)
{
    uint64_t started   = 0u;
    uint64_t elapsed   = 0u;
    uint32_t delta     = 0u;
    bool     b_restart = false;
    bool     b_gap     = false;
    uint16_t type      = 0u;
    bool     b_window  = false;
    uint64_t age       = 0u;

    if (NULL != p_frame)
    {
        started                   = time_us_64();
        g_stats.last_frame_age_us = 0u;
        if (started >= p_frame->timestamp_us)
        {
            age = started - p_frame->timestamp_us;
            g_stats.last_frame_age_us =
                (UINT32_MAX < age) ? UINT32_MAX : (uint32_t) age;
            if (age > g_stats.max_frame_age_us)
            {
                g_stats.max_frame_age_us =
                    (UINT32_MAX < age) ? UINT32_MAX : (uint32_t) age;
            }
        }
        g_stats.received++;
        type = analysis_port_type(p_frame);
        if (0x88b8u == type)
        {
            g_stats.goose_seen++;
        }
        else if (0x88bau == type)
        {
            g_stats.sv_seen++;
        }
        else
        {
            g_stats.background++;
        }
        if (gb_have_previous)
        {
            delta = p_frame->sequence - g_sequence;
            /* Unsigned wrap by one is normal. Duplicate/backwards IDs or
             * a backwards clock invalidate all histories, not just a vote.
             */
            b_restart = (0u == delta) || (UINT32_MAX / 2u < delta)
                     || (p_frame->timestamp_us < g_timestamp);
            b_gap = (1u != delta) || (p_frame->loss_generation != g_generation);
            if (b_restart)
            {
                analyzer_reset();
                g_stats.restarts++;
            }
            if (b_gap || b_restart)
            {
                analyzer_note_capture_gap();
                g_stats.gaps++;
            }
        }
        g_sequence       = p_frame->sequence;
        g_generation     = p_frame->loss_generation;
        g_timestamp      = p_frame->timestamp_us;
        gb_have_previous = true;
        /* Do not truncate capture frames to the reference evidence capacity.
         * Preserve its 1518-byte contract; unsupported sizes are explicit.
         */
        if ((p_frame->length <= ANALYZER_MAXIMUM_FRAME_LENGTH)
            && analyzer_process_capture(p_frame->data, p_frame->length,
                                        p_frame->timestamp_us,
                                        p_frame->sequence, &g_result))
        {
            g_stats.accepted++;
#if PORT_DETECTION
            /* S3 must copy evidence while this four-frame snapshot is live,
             * before any later analyzer call advances/reuses its storage.
             */
            detection_observe(&g_result);
#endif
            if (g_result.stream_reset)
            {
                g_stats.stream_resets++;
            }
            if (g_result.prediction_ready)
            {
                b_window = true;
                g_stats.windows++;
                if (ANALYZER_PROTOCOL_GOOSE == g_result.protocol)
                {
                    g_stats.goose_windows++;
                }
                else
                {
                    g_stats.sv_windows++;
                }
                g_stats.last_protocol = (uint32_t) g_result.protocol;
                g_stats.last_label    = g_result.primary_label;
                g_stats.last_probability_ppm =
                    (uint32_t) (g_result.primary_probability * 1000000.0f);
                if (0u != g_result.primary_label)
                {
                    g_stats.positive_windows++;
                }
            }
        }
        else
        {
            if ((0x88b8u == type) || (0x88bau == type))
            {
                g_stats.iec_rejected++;
            }
            if (p_frame->length > ANALYZER_MAXIMUM_FRAME_LENGTH)
            {
                g_stats.oversize++;
                analyzer_note_capture_gap();
                g_stats.gaps++;
            }
            /* Includes ordinary non-IEC background Ethernet traffic. */
            g_stats.rejected++;
        }
        elapsed = time_us_64() - started;
        g_stats.last_us =
            (UINT32_MAX < elapsed) ? UINT32_MAX : (uint32_t) elapsed;
        g_stats.total_us += elapsed;
        if (b_window && (g_stats.last_us > g_stats.max_window_us))
        {
            g_stats.max_window_us = g_stats.last_us;
        }
        if (g_stats.last_us > g_stats.max_us)
        {
            g_stats.max_us = g_stats.last_us;
        }
    }
}

void
analysis_port_poll (uint64_t now_us)
{
    iec_rules_poll(now_us);
}

void
analysis_port_stats (analysis_port_stats_t * p_stats)
{
    if (NULL != p_stats)
    {
        *p_stats = g_stats;
    }
}

/** @brief Run both real protocol/model paths without transmitting traffic. */
bool
analysis_port_self_check (void)
{
    uint32_t            index        = 0u;
    uint32_t            windows      = 0u;
    size_t              count        = 0u;
    float               features[72] = {0};
    analyzer_protocol_t protocol     = ANALYZER_PROTOCOL_GOOSE;
    bool                b_ok         = true;
    uint32_t            protocols    = 0u;
    iec_rules_stats_t   rules        = {0};
    const uint32_t *    p_expected   = NULL;
    size_t              feature      = 0u;

    analyzer_reset();
    for (index = 0u; 8u > index; index++)
    {
        b_ok = analyzer_process_capture(g_analysis_fixtures[index],
                                        g_analysis_fixture_lengths[index],
                                        1000000u + index * 1000u, index + 1u,
                                        &g_result)
            && b_ok;
        if (g_result.prediction_ready)
        {
            windows++;
            protocols |= 1u << (uint32_t) g_result.protocol;
            b_ok = ((3u == index) || (7u == index)) && b_ok;
            b_ok =
                analyzer_copy_batch_features(features, 72u, &count, &protocol)
                && b_ok;
            b_ok       = (count == ((4u > index) ? 52u : 72u)) && b_ok;
            b_ok       = (g_result.primary_probability >= 0.0f)
                      && (g_result.primary_probability <= 1.0f) && b_ok;
            b_ok       = (g_result.batch_frame_count == 4u) && b_ok;
            p_expected = (4u > index) ? g_analysis_goose_expected
                                      : g_analysis_sv_expected;
            b_ok       = analysis_port_matches(g_result.primary_probability,
                                               p_expected[0])
                      && b_ok;
            for (feature = 0u; count > feature; feature++)
            {
                b_ok = analysis_port_matches(features[feature],
                                             p_expected[feature + 1u])
                    && b_ok;
            }
        }
    }
    iec_rules_stats(&rules);
    b_ok = (2u == windows) && (3u == protocols) && b_ok;
    b_ok = (2u == rules.model_run) && (0u == rules.model_skipped) && b_ok;
    /* Synthetic counters/histories must never contaminate live analysis. */
    analysis_port_init();
    return b_ok;
}

/*** end of file ***/
