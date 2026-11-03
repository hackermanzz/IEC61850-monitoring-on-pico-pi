/** @file iec_rules.h
 *
 * @brief IEC 61850 rule checks: compares each GOOSE and SV frame with a
 * trusted stream profile, independently of the models.
 *
 * @par
 * A rule finding is an anomaly, not proof of an attack. Profiles come from
 * trusted deployment configuration and are never learned from packets.
 *
 * @par
 * Only the analysis task may call these functions. Call
 * iec_rules_configure() and iec_rules_reset() only before analysis starts.
 */
#ifndef IEC_RULES_H
#define IEC_RULES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Reason bits reported by iec_rules_observe() and iec_rules_poll().
//
#define IEC_RULE_STRUCTURE          (1u << 0)
#define IEC_RULE_UNCONFIGURED       (1u << 1)
#define IEC_RULE_SOURCE             (1u << 2)
#define IEC_RULE_CONFIG             (1u << 3)
#define IEC_RULE_TEST               (1u << 4)
#define IEC_RULE_COMMISSION         (1u << 5)
#define IEC_RULE_COUNTER            (1u << 6)
#define IEC_RULE_DATA_WITHOUT_STATE (1u << 7)
#define IEC_RULE_TIMING             (1u << 8)
#define IEC_RULE_CAPTURE_GAP        (1u << 9)
#define IEC_RULE_UNSUPPORTED        (1u << 10)

#define IEC_RULE_MAX_PROFILES (5u)
#define IEC_RULE_NO_PROFILE   (UINT32_MAX)

// Values of the protocol fields below.
//
#define IEC_RULES_PROTOCOL_GOOSE (0u)
#define IEC_RULES_PROTOCOL_SV    (1u)

#define IEC_RULES_MAC_BYTES (6u)

/*!
 * @brief One trusted stream, from the SCD/SCL file or a verified lab set-up.
 *
 * @par
 * Strings are compared byte for byte, not by hash. Set every field before
 * allowing the model to be skipped. SV checks support one ASDU per frame,
 * with an explicit counter modulus and step.
 */
typedef struct
{
    uint32_t     protocol;
    uint32_t     conf_rev;
    uint32_t     entries;
    uint32_t     sv_modulus;
    uint32_t     sv_frame_step;
    uint32_t     min_interval_us;
    uint32_t     max_interval_us;
    uint32_t     audit_windows;
    uint32_t     audit_us;
    uint16_t     appid;
    uint8_t      source[IEC_RULES_MAC_BYTES];
    uint8_t      destination[IEC_RULES_MAC_BYTES];
    char const * p_id;      // GOOSE gocbRef or SV svID.
    char const * p_dataset; // GOOSE datSet; NULL for SV.
    bool         b_allow_test;
} iec_rules_profile_t;

/*!
 * @brief The fields of one parsed frame that the rules check.
 *
 * @par
 * The pointers borrow the frame and are only valid during
 * iec_rules_observe(); no pointer is kept. data_hash detects payload
 * differences only; it does not authenticate.
 */
typedef struct
{
    uint32_t        protocol;
    uint32_t        conf_rev;
    uint32_t        entries;
    uint32_t        counter;
    uint32_t        sequence;
    uint32_t        ttl_ms;
    uint32_t        data_hash;
    uint32_t        smp_synch;
    uint32_t        asdu_count;
    uint32_t        semantic_reasons;
    uint64_t        timestamp_us;
    uint16_t        appid;
    uint8_t const * p_source;
    uint8_t const * p_destination;
    uint8_t const * p_id;
    uint8_t const * p_dataset;
    size_t          id_length;
    size_t          dataset_length;
    bool            b_test;
    bool            b_needs_commission;
} iec_rules_frame_t;

/*!
 * @brief Rule statistics, published in the analysis status.
 */
typedef struct
{
    uint32_t frames;
    uint32_t flagged;
    uint32_t parse_errors;
    uint32_t timeouts;
    uint32_t model_run;
    uint32_t model_skipped;
    uint32_t last_reasons;
    uint32_t seen_reasons;
} iec_rules_stats_t;

bool iec_rules_configure(iec_rules_profile_t const * p_profiles, size_t count,
                         bool b_gate);
void iec_rules_reset(void);
void iec_rules_capture_gap(void);
void iec_rules_parse_error(bool b_unsupported);
uint32_t iec_rules_observe(iec_rules_frame_t const * p_frame);
void     iec_rules_poll(uint64_t now_us);
bool     iec_rules_model_required(uint32_t profile, uint64_t now_us);
bool     iec_rules_window_required(uint32_t profile, uint64_t now_us,
                                   uint32_t window_reasons);
uint32_t iec_rules_latest_reasons(void);
void     iec_rules_model_result(uint32_t profile, bool b_malicious);
void     iec_rules_stats(iec_rules_stats_t * p_stats);
uint32_t iec_rules_hash(uint8_t const * p_bytes, size_t count);

#endif /* IEC_RULES_H */

/*** end of file ***/
