#ifndef MONITOR_IEC_RULES_H
#define MONITOR_IEC_RULES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Independent of model inputs. An anomaly is not proof of an attack. */
enum {
    IEC_RULE_STRUCTURE = 1u << 0,
    IEC_RULE_UNCONFIGURED = 1u << 1,
    IEC_RULE_SOURCE = 1u << 2,
    IEC_RULE_CONFIG = 1u << 3,
    IEC_RULE_TEST = 1u << 4,
    IEC_RULE_COMMISSION = 1u << 5,
    IEC_RULE_COUNTER = 1u << 6,
    IEC_RULE_DATA_WITHOUT_STATE = 1u << 7,
    IEC_RULE_TIMING = 1u << 8,
    IEC_RULE_CAPTURE_GAP = 1u << 9,
    IEC_RULE_UNSUPPORTED = 1u << 10
};
#define IEC_RULE_MAX_PROFILES 5u
#define IEC_RULE_NO_PROFILE UINT32_MAX

/* Trusted, immutable deployment configuration, never learned from packets.
 * protocol: 0 GOOSE, 1 SV. Strings are exact byte comparisons, not hashes.
 * Set every field for a stream before allowing inference skipping.
 * SV gating initially supports one ASDU, with explicit modulus/frame step. */
typedef struct {
    uint32_t protocol, conf_rev, entries;
    uint32_t sv_modulus, sv_frame_step;
    uint32_t min_interval_us, max_interval_us;
    uint32_t audit_windows, audit_us;
    uint16_t appid;
    uint8_t source[6], destination[6];
    const char *id;      /* gocbRef or svID */
    const char *dataset; /* GOOSE datSet; NULL for SV */
    bool allow_test;
} iec_rule_profile_t;

/* Borrowed views: valid only during observe(). No packet pointers are retained.
 * GOOSE payload fingerprint detects differences, not authenticated equality.
 * semantic_reasons is supplied by the existing bounded parser. */
typedef struct {
    uint32_t protocol, conf_rev, entries, counter, sequence;
    uint32_t ttl_ms, data_hash, smp_synch, asdu_count, semantic_reasons;
    uint64_t timestamp_us;
    uint16_t appid;
    const uint8_t *source, *destination, *id, *dataset;
    size_t id_length, dataset_length;
    bool test, needs_commission;
} iec_rule_frame_t;

typedef struct {
    uint32_t frames, flagged, parse_errors, timeouts;
    uint32_t model_run, model_skipped, last_reasons, seen_reasons;
} iec_rule_stats_t;

/* Single owner: S3. configure/reset only before analysis starts. Invalid
 * profiles disable skipping globally; unknown frames always require the model.
 * gate=false is the default baseline: rules observe, every model window runs. */
bool iec_rules_configure(const iec_rule_profile_t *profiles, size_t count, bool gate);
void iec_rules_reset(void);
void iec_rules_capture_gap(void);
void iec_rules_parse_error(bool unsupported);
uint32_t iec_rules_observe(const iec_rule_frame_t *frame);
void iec_rules_poll(uint64_t now_us);
bool iec_rules_model_required(uint32_t profile, uint64_t now_us);
bool iec_rules_window_required(uint32_t profile, uint64_t now_us, uint32_t reasons);
uint32_t iec_rules_latest_reasons(void);
void iec_rules_model_result(uint32_t profile, bool malicious);
void iec_rules_stats(iec_rule_stats_t *out);
uint32_t iec_rules_hash(const uint8_t *bytes, size_t count);

#endif
