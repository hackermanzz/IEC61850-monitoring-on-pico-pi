/** @file iec_rules.c
 *
 * @brief IEC 61850 rule checks: compares each GOOSE and SV frame with a
 * trusted stream profile, and decides when the model may be skipped.
 *
 * @par
 * Each profile keeps a small baseline (last time, counters, payload hash)
 * and the reasons of its last four frames. A frame that fails a source,
 * configuration, structure or support check never updates the baseline, so
 * it cannot poison it; its reasons still force the model to run.
 *
 * @par
 * Skipping the model ("gating") is off by default. When it is on, a clean
 * known stream may skip at most audit_windows - 1 windows in a row, and never
 * for longer than audit_us.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "iec_rules.h"

#define REASON_WINDOW_FRAMES  (4u)
#define MAXIMUM_ID_LENGTH     (64u)
#define MINIMUM_SV_MODULUS    (1u)
#define MAXIMUM_SV_MODULUS    (65536u)
#define MAC_GROUP_BIT         (0x01u)
#define MICROSECONDS_PER_MS   (1000u)
#define SINGLE_ASDU           (1u)
#define FNV_OFFSET_BASIS      (2166136261u)
#define FNV_PRIME             (16777619u)
#define COUNTER_BACKWARD_FROM (0x80000000u)

// Reasons that mark a frame as untrusted for the baseline.
//
#define UNTRUSTED_REASONS                                                      \
    (IEC_RULE_SOURCE | IEC_RULE_CONFIG | IEC_RULE_STRUCTURE                    \
     | IEC_RULE_UNSUPPORTED)

/*!
 * @brief The baseline and recent reasons of one profiled stream.
 */
typedef struct
{
    uint64_t last_us;
    uint64_t last_model_us;
    uint32_t counter;
    uint32_t sequence;
    uint32_t data_hash;
    uint32_t ttl_ms;
    uint32_t synch;
    uint32_t reasons[REASON_WINDOW_FRAMES];
    uint32_t next;
    uint32_t since_audit;
    bool     b_seen;
    bool     b_scored;
    bool     b_malicious;
    bool     b_timed_out;
    bool     b_gap;
} rule_state_t;

static rule_state_t                g_states[IEC_RULE_MAX_PROFILES];
static iec_rules_profile_t const * gp_configuration;
static size_t                      g_profile_count;
static bool                        gb_gated;
static iec_rules_stats_t           g_stats;

static void     report_reasons(uint32_t reasons);
static bool     text_equals(uint8_t const * p_bytes, size_t count,
                            char const * p_text);
static bool     profile_is_valid(iec_rules_profile_t const * p_profile);
static bool     profiles_collide(iec_rules_profile_t const * p_first,
                                 iec_rules_profile_t const * p_second);
static size_t   find_profile(iec_rules_frame_t const * p_frame);
static uint32_t check_known_frame(size_t                    slot,
                                  iec_rules_frame_t const * p_frame,
                                  uint32_t                  reasons);
static uint32_t profile_reasons(iec_rules_profile_t const * p_profile,
                                iec_rules_frame_t const *   p_frame);
static uint32_t timing_reasons(iec_rules_profile_t const * p_profile,
                               rule_state_t const *        p_state,
                               iec_rules_frame_t const *   p_frame);
static uint32_t counter_reasons(iec_rules_profile_t const * p_profile,
                                rule_state_t const *        p_state,
                                iec_rules_frame_t const *   p_frame);
static void     update_baseline(rule_state_t *            p_state,
                                iec_rules_frame_t const * p_frame);
static uint64_t stream_timeout_us(size_t slot);
static bool     can_skip_model(size_t slot, uint64_t now_us,
                               uint32_t window_reasons);

/*!
 * @brief Install the trusted profiles and clear all rule state.
 *
 * @par
 * An invalid profile table disables every profile and gating, so unknown
 * frames always run the model. b_gate false is the default: the rules only
 * observe and every model window runs.
 *
 * @param[in] p_profiles The profile table; may be NULL if count is 0.
 * @param[in] count      The number of profiles.
 * @param[in] b_gate     True to allow clean windows to skip the model.
 *
 * @return True if the table was valid.
 */
bool
iec_rules_configure (iec_rules_profile_t const * p_profiles, size_t count,
                     bool b_gate)
{
    size_t index   = 0u;
    bool   b_valid = (count <= IEC_RULE_MAX_PROFILES)
                  && ((0u == count) || (NULL != p_profiles));

    for (index = 0u; b_valid && (index < count); ++index)
    {
        size_t other = 0u;

        b_valid = profile_is_valid(&p_profiles[index]);

        for (other = 0u; b_valid && (other < index); ++other)
        {
            if (profiles_collide(&p_profiles[index], &p_profiles[other]))
            {
                b_valid = false;
            }
        }
    }

    gp_configuration = b_valid ? p_profiles : NULL;
    g_profile_count  = b_valid ? count : 0u;
    gb_gated         = b_valid && b_gate;
    iec_rules_reset();

    return (b_valid);
}

/*!
 * @brief Clear every stream baseline and the statistics.
 */
void
iec_rules_reset (void)
{
    memset(g_states, 0, sizeof(g_states));
    memset(&g_stats, 0, sizeof(g_stats));
}

/*!
 * @brief Note that frames were lost before analysis.
 *
 * @par
 * Every profile then runs the model on its next windows.
 */
void
iec_rules_capture_gap (void)
{
    size_t index = 0u;

    for (index = 0u; index < g_profile_count; ++index)
    {
        g_states[index].b_gap = true;
    }
}

/*!
 * @brief Count a frame that could not be parsed.
 *
 * @par
 * The frame cannot be tied to a stream, so it must not quietly clear any
 * stream's context: every profile runs the model on its next windows.
 *
 * @param[in] b_unsupported True if the frame was well formed but used an
 *                          unsupported feature.
 */
void
iec_rules_parse_error (bool b_unsupported)
{
    g_stats.parse_errors++;
    report_reasons(b_unsupported ? IEC_RULE_UNSUPPORTED : IEC_RULE_STRUCTURE);
    iec_rules_capture_gap();
}

/*!
 * @brief Hash bytes with 32-bit FNV-1a.
 *
 * @param[in] p_bytes The bytes; may be NULL.
 * @param[in] count   The number of bytes.
 *
 * @return The hash; the FNV offset basis for NULL.
 */
uint32_t
iec_rules_hash (uint8_t const * p_bytes, size_t count)
{
    uint32_t value = FNV_OFFSET_BASIS;
    size_t   index = 0u;

    if (NULL != p_bytes)
    {
        for (index = 0u; index < count; ++index)
        {
            value = (value ^ p_bytes[index]) * FNV_PRIME;
        }
    }

    return (value);
}

/*!
 * @brief Check one parsed frame against its profile.
 *
 * @param[in] p_frame The frame fields.
 *
 * @return The profile index, or IEC_RULE_NO_PROFILE if no profile matches.
 */
uint32_t
iec_rules_observe (iec_rules_frame_t const * p_frame)
{
    uint32_t profile = IEC_RULE_NO_PROFILE;

    if ((NULL == p_frame) || (NULL == p_frame->p_source)
        || (NULL == p_frame->p_destination) || (NULL == p_frame->p_id))
    {
        iec_rules_parse_error(false);
    }
    else
    {
        uint32_t reasons = p_frame->semantic_reasons;
        size_t   slot    = 0u;

        g_stats.frames++;

        if (p_frame->b_test)
        {
            reasons |= IEC_RULE_TEST;
        }

        if (p_frame->b_needs_commission)
        {
            reasons |= IEC_RULE_COMMISSION;
        }

        slot = find_profile(p_frame);

        if (g_profile_count == slot)
        {
            report_reasons(reasons | IEC_RULE_UNCONFIGURED);
        }
        else
        {
            reasons = check_known_frame(slot, p_frame, reasons);
            report_reasons(reasons);

            // The cast is safe: slot is below IEC_RULE_MAX_PROFILES.
            profile = (uint32_t) slot;
        }
    }

    return (profile);
}

/*!
 * @brief Flag every stream that has been silent for too long.
 *
 * @param[in] now_us The current time.
 */
void
iec_rules_poll (uint64_t now_us)
{
    size_t index = 0u;

    for (index = 0u; index < g_profile_count; ++index)
    {
        rule_state_t * const p_state = &g_states[index];
        uint64_t const       timeout = stream_timeout_us(index);

        if (p_state->b_seen && !p_state->b_timed_out && (0u != timeout)
            && (now_us >= p_state->last_us)
            && ((now_us - p_state->last_us) > timeout))
        {
            p_state->b_timed_out = true;
            p_state->b_gap       = true;
            g_stats.timeouts++;
            report_reasons(IEC_RULE_TIMING);
        }
    }
}

/*!
 * @brief Report the reasons of the last frame or timeout.
 *
 * @return The reason bits.
 */
uint32_t
iec_rules_latest_reasons (void)
{
    return (g_stats.last_reasons);
}

/*!
 * @brief Decide whether a profile's next window must run the model.
 *
 * @param[in] profile The profile index from iec_rules_observe().
 * @param[in] now_us  The current time.
 *
 * @return True if the model must run.
 */
bool
iec_rules_model_required (uint32_t profile, uint64_t now_us)
{
    return (iec_rules_window_required(profile, now_us, 0u));
}

/*!
 * @brief Decide whether a completed window must run the model.
 *
 * @par
 * Unknown streams always run the model. Every decision is counted.
 *
 * @param[in] profile        The profile index from iec_rules_observe().
 * @param[in] now_us         The current time.
 * @param[in] window_reasons The reasons of the window's frames.
 *
 * @return True if the model must run.
 */
bool
iec_rules_window_required (uint32_t profile, uint64_t now_us,
                           uint32_t window_reasons)
{
    bool b_run = true;

    if (profile < g_profile_count)
    {
        rule_state_t * const p_state = &g_states[profile];

        b_run = !can_skip_model(profile, now_us, window_reasons);

        if (b_run)
        {
            p_state->since_audit   = 0u;
            p_state->last_model_us = now_us;
        }
        else
        {
            p_state->since_audit++;
        }
    }

    if (b_run)
    {
        g_stats.model_run++;
    }
    else
    {
        g_stats.model_skipped++;
    }

    return (b_run);
}

/*!
 * @brief Record the model's verdict for a profile.
 *
 * @param[in] profile     The profile index.
 * @param[in] b_malicious True if the window was scored as malicious.
 */
void
iec_rules_model_result (uint32_t profile, bool b_malicious)
{
    if (profile < g_profile_count)
    {
        g_states[profile].b_scored    = true;
        g_states[profile].b_malicious = b_malicious;
    }
}

/*!
 * @brief Copy the rule statistics.
 *
 * @param[out] p_stats Receives the statistics; may be NULL.
 */
void
iec_rules_stats (iec_rules_stats_t * p_stats)
{
    if (NULL != p_stats)
    {
        *p_stats = g_stats;
    }
}

/*!
 * @brief Add reasons to the statistics.
 *
 * @param[in] reasons The reason bits.
 */
static void
report_reasons (uint32_t reasons)
{
    g_stats.last_reasons = reasons;
    g_stats.seen_reasons |= reasons;

    if (0u != reasons)
    {
        g_stats.flagged++;
    }
}

/*!
 * @brief Compare counted bytes with a C string.
 *
 * @param[in] p_bytes The bytes; may be NULL.
 * @param[in] count   The number of bytes.
 * @param[in] p_text  The string; may be NULL.
 *
 * @return True if both exist and are equal.
 */
static bool
text_equals (uint8_t const * p_bytes, size_t count, char const * p_text)
{
    return ((NULL != p_text) && (NULL != p_bytes) && (strlen(p_text) == count)
            && (0 == memcmp(p_bytes, p_text, count)));
}

/*!
 * @brief Check that a profile is complete and consistent.
 *
 * @param[in] p_profile The profile.
 *
 * @return True if the profile is valid.
 */
static bool
profile_is_valid (iec_rules_profile_t const * p_profile)
{
    bool b_valid =
        (p_profile->protocol <= IEC_RULES_PROTOCOL_SV)
        && (NULL != p_profile->p_id) && (strlen(p_profile->p_id) > 0u)
        && (strlen(p_profile->p_id) <= MAXIMUM_ID_LENGTH)
        && (p_profile->audit_windows > 0u) && (p_profile->audit_us > 0u)
        && (0u == (p_profile->source[0] & MAC_GROUP_BIT))
        && (0u != (p_profile->destination[0] & MAC_GROUP_BIT))
        && ((0u == p_profile->max_interval_us)
            || (p_profile->min_interval_us <= p_profile->max_interval_us));

    if (IEC_RULES_PROTOCOL_GOOSE == p_profile->protocol)
    {
        b_valid = b_valid && (NULL != p_profile->p_dataset)
               && ('\0' != p_profile->p_dataset[0]);
    }
    else
    {
        b_valid = b_valid && (p_profile->sv_modulus > MINIMUM_SV_MODULUS)
               && (p_profile->sv_modulus <= MAXIMUM_SV_MODULUS)
               && (p_profile->sv_frame_step > 0u)
               && (p_profile->sv_frame_step < p_profile->sv_modulus);
    }

    return (b_valid);
}

/*!
 * @brief Check whether two profiles describe the same stream.
 *
 * @param[in] p_first  One profile.
 * @param[in] p_second The other profile.
 *
 * @return True if the profiles collide.
 */
static bool
profiles_collide (iec_rules_profile_t const * p_first,
                  iec_rules_profile_t const * p_second)
{
    return ((p_first->protocol == p_second->protocol)
            && (p_first->appid == p_second->appid)
            && (0
                == memcmp(p_first->destination, p_second->destination,
                          IEC_RULES_MAC_BYTES))
            && (0 == strcmp(p_first->p_id, p_second->p_id)));
}

/*!
 * @brief Find the profile of a frame's stream.
 *
 * @param[in] p_frame The frame fields.
 *
 * @return The profile index, or g_profile_count if there is none.
 */
static size_t
find_profile (iec_rules_frame_t const * p_frame)
{
    size_t slot      = 0u;
    bool   b_is_done = false;

    while (!b_is_done && (slot < g_profile_count))
    {
        iec_rules_profile_t const * const p_profile = &gp_configuration[slot];

        if ((p_profile->protocol == p_frame->protocol)
            && (p_profile->appid == p_frame->appid)
            && (0
                == memcmp(p_profile->destination, p_frame->p_destination,
                          IEC_RULES_MAC_BYTES))
            && (text_equals(p_frame->p_id, p_frame->id_length,
                            p_profile->p_id)))
        {
            b_is_done = true;
        }
        else
        {
            ++slot;
        }
    }

    return (slot);
}

/*!
 * @brief Check a frame of a profiled stream and update its baseline.
 *
 * @param[in] slot    The profile index.
 * @param[in] p_frame The frame fields.
 * @param[in] reasons The reasons found so far.
 *
 * @return All the frame's reasons.
 */
static uint32_t
check_known_frame (size_t slot, iec_rules_frame_t const * p_frame,
                   uint32_t reasons)
{
    iec_rules_profile_t const * const p_profile = &gp_configuration[slot];
    rule_state_t * const              p_state   = &g_states[slot];

    if (p_profile->b_allow_test)
    {
        reasons &= ~IEC_RULE_TEST;
    }

    reasons |= profile_reasons(p_profile, p_frame);

    if (p_state->b_gap)
    {
        reasons |= IEC_RULE_CAPTURE_GAP;
    }

    if (p_state->b_seen)
    {
        reasons |= timing_reasons(p_profile, p_state, p_frame);
        reasons |= counter_reasons(p_profile, p_state, p_frame);
    }

    // An untrusted frame cannot change the baseline, but its reasons stay in
    // the rolling window so that they force the model to run.
    p_state->reasons[p_state->next] = reasons;
    p_state->next = (p_state->next + 1u) % REASON_WINDOW_FRAMES;

    if ((0u == (reasons & UNTRUSTED_REASONS))
        && (!p_state->b_seen || (p_frame->timestamp_us >= p_state->last_us)))
    {
        update_baseline(p_state, p_frame);
    }

    return (reasons);
}

/*!
 * @brief Compare a frame's identity and configuration with its profile.
 *
 * @param[in] p_profile The profile.
 * @param[in] p_frame   The frame fields.
 *
 * @return The reasons found.
 */
static uint32_t
profile_reasons (iec_rules_profile_t const * p_profile,
                 iec_rules_frame_t const *   p_frame)
{
    uint32_t reasons = 0u;

    if (0 != memcmp(p_profile->source, p_frame->p_source, IEC_RULES_MAC_BYTES))
    {
        reasons |= IEC_RULE_SOURCE;
    }

    if (p_profile->conf_rev != p_frame->conf_rev)
    {
        reasons |= IEC_RULE_CONFIG;
    }

    if (IEC_RULES_PROTOCOL_GOOSE == p_frame->protocol)
    {
        if ((!text_equals(p_frame->p_dataset, p_frame->dataset_length,
                          p_profile->p_dataset))
            || (p_profile->entries != p_frame->entries))
        {
            reasons |= IEC_RULE_CONFIG;
        }

        if (0u == p_frame->ttl_ms)
        {
            reasons |= IEC_RULE_STRUCTURE;
        }
    }
    else
    {
        if (SINGLE_ASDU != p_frame->asdu_count)
        {
            reasons |= IEC_RULE_UNSUPPORTED;
        }

        if (p_frame->counter >= p_profile->sv_modulus)
        {
            reasons |= IEC_RULE_COUNTER;
        }
    }

    return (reasons);
}

/*!
 * @brief Check the time since the stream's previous trusted frame.
 *
 * @param[in] p_profile The profile.
 * @param[in] p_state   The stream baseline.
 * @param[in] p_frame   The frame fields.
 *
 * @return IEC_RULE_TIMING or 0.
 */
static uint32_t
timing_reasons (iec_rules_profile_t const * p_profile,
                rule_state_t const * p_state, iec_rules_frame_t const * p_frame)
{
    uint32_t reasons = 0u;

    if (p_frame->timestamp_us < p_state->last_us)
    {
        reasons = IEC_RULE_TIMING;
    }
    else
    {
        uint64_t const elapsed = p_frame->timestamp_us - p_state->last_us;

        // The cast is safe: widening before the multiply avoids overflow.
        if ((elapsed < p_profile->min_interval_us)
            || ((0u != p_profile->max_interval_us)
                && (elapsed > p_profile->max_interval_us))
            || ((IEC_RULES_PROTOCOL_GOOSE == p_frame->protocol)
                && (elapsed
                    > ((uint64_t) p_state->ttl_ms * MICROSECONDS_PER_MS))))
        {
            reasons = IEC_RULE_TIMING;
        }
    }

    return (reasons);
}

/*!
 * @brief Check the stream counters against the previous trusted frame.
 *
 * @par
 * GOOSE: a new stNum may follow missed retransmissions, so sqNum need not be
 * 0; within one stNum, sqNum must advance and the payload must not change.
 * SV: smpCnt must advance by the frame step, modulo the profile modulus.
 * Wraps and restarts are anomalies, not verdicts.
 *
 * @param[in] p_profile The profile.
 * @param[in] p_state   The stream baseline.
 * @param[in] p_frame   The frame fields.
 *
 * @return The reasons found.
 */
static uint32_t
counter_reasons (iec_rules_profile_t const * p_profile,
                 rule_state_t const *        p_state,
                 iec_rules_frame_t const *   p_frame)
{
    uint32_t reasons = 0u;

    if (IEC_RULES_PROTOCOL_GOOSE == p_frame->protocol)
    {
        uint32_t const delta = p_frame->counter - p_state->counter;

        if (0u == delta)
        {
            uint32_t const sq_delta = p_frame->sequence - p_state->sequence;

            if ((0u == sq_delta) || (sq_delta >= COUNTER_BACKWARD_FROM))
            {
                reasons |= IEC_RULE_COUNTER;
            }

            if (p_frame->data_hash != p_state->data_hash)
            {
                reasons |= IEC_RULE_DATA_WITHOUT_STATE;
            }
        }
        else if (delta >= COUNTER_BACKWARD_FROM)
        {
            reasons |= IEC_RULE_COUNTER;
        }
        else
        {
            // A forward stNum step is normal.
        }
    }
    else if (p_frame->smp_synch != p_state->synch)
    {
        reasons |= IEC_RULE_TIMING;
    }
    else if ((p_frame->counter >= p_profile->sv_modulus)
             || (p_frame->counter
                 != ((p_state->counter + p_profile->sv_frame_step)
                     % p_profile->sv_modulus)))
    {
        reasons |= IEC_RULE_COUNTER;
    }
    else
    {
        // The SV counter is in step.
    }

    return (reasons);
}

/*!
 * @brief Make a trusted frame the stream's new baseline.
 *
 * @param[out] p_state The stream baseline.
 * @param[in]  p_frame The frame fields.
 */
static void
update_baseline (rule_state_t * p_state, iec_rules_frame_t const * p_frame)
{
    p_state->b_seen      = true;
    p_state->last_us     = p_frame->timestamp_us;
    p_state->counter     = p_frame->counter;
    p_state->sequence    = p_frame->sequence;
    p_state->data_hash   = p_frame->data_hash;
    p_state->ttl_ms      = p_frame->ttl_ms;
    p_state->synch       = p_frame->smp_synch;
    p_state->b_gap       = false;
    p_state->b_timed_out = false;
}

/*!
 * @brief Work out how long a stream may stay silent.
 *
 * @par
 * GOOSE uses the last timeAllowedToLive, SV the maximum interval; a
 * configured maximum interval is used if it is shorter.
 *
 * @param[in] slot The profile index.
 *
 * @return The timeout, or 0 if the stream has none.
 */
static uint64_t
stream_timeout_us (size_t slot)
{
    iec_rules_profile_t const * const p_profile = &gp_configuration[slot];
    uint64_t                          timeout   = p_profile->max_interval_us;

    if (IEC_RULES_PROTOCOL_GOOSE == p_profile->protocol)
    {
        // The cast is safe: widening before the multiply avoids overflow.
        timeout = (uint64_t) g_states[slot].ttl_ms * MICROSECONDS_PER_MS;
    }

    if ((0u != p_profile->max_interval_us)
        && ((0u == timeout) || (p_profile->max_interval_us < timeout)))
    {
        timeout = p_profile->max_interval_us;
    }

    return (timeout);
}

/*!
 * @brief Check whether a clean window of a known stream may skip the model.
 *
 * @param[in] slot           The profile index.
 * @param[in] now_us         The current time.
 * @param[in] window_reasons The reasons of the window's frames.
 *
 * @return True if the model may be skipped.
 */
static bool
can_skip_model (size_t slot, uint64_t now_us, uint32_t window_reasons)
{
    iec_rules_profile_t const * const p_profile = &gp_configuration[slot];
    rule_state_t const * const        p_state   = &g_states[slot];
    uint32_t                          reasons   = 0u;
    size_t                            index     = 0u;

    for (index = 0u; index < REASON_WINDOW_FRAMES; ++index)
    {
        reasons |= p_state->reasons[index];
    }

    return (gb_gated && p_state->b_scored && !p_state->b_malicious
            && !p_state->b_gap && p_state->b_seen && (0u == reasons)
            && (0u == window_reasons)
            && (p_state->since_audit < (p_profile->audit_windows - 1u))
            && (now_us >= p_state->last_model_us)
            && ((now_us - p_state->last_model_us) < p_profile->audit_us));
}

/*** end of file ***/
