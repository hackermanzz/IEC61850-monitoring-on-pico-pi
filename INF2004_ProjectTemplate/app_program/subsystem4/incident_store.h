#ifndef MONITOR_INCIDENT_STORE_H
#define MONITOR_INCIDENT_STORE_H

#include "../subsystem3/analyzer.h"

#ifndef MONITOR_INCIDENT_SLOTS
#define MONITOR_INCIDENT_SLOTS 2u
#endif
#define MONITOR_EVIDENCE_PACKETS ANALYZER_BATCH_FRAME_COUNT

typedef enum {
    INCIDENT_OPEN, INCIDENT_SAFE, INCIDENT_STALE, INCIDENT_CAPTURE_LOSS,
    INCIDENT_INVALID_SCORE
} incident_close_t;

typedef struct {
    bool used, complete, truncated, exported;
    uint64_t id, start_us, end_us;
    analyzer_protocol_t protocol;
    uint32_t stream_key, malicious_windows, omitted_windows;
    uint16_t appid;
    float score;
    incident_close_t closure;
    uint8_t packet_count;
} monitor_incident_info_t;

typedef struct {
    uint32_t episodes, malicious_windows, lost_episodes, omitted_windows;
    uint32_t invalid_scores, evidence_failures;
    uint32_t active_streams;
} monitor_incident_stats_t;

typedef struct {
    bool malicious, new_episode, retained;
    uint64_t id;
} monitor_incident_outcome_t;

typedef bool (*monitor_evidence_copy_t)(size_t, uint8_t *, size_t,
                                       analyzer_packet_metadata_t *);

/* Single owner: analysis task. Readers/SD must request copies from that task.
 * No pointer into the capture pool is retained here. */
void monitor_incident_init(uint32_t session);
monitor_incident_outcome_t monitor_incident_observe(
    const analyzer_result_t *result, monitor_evidence_copy_t copy);
void monitor_incident_expire(uint64_t now_us);
void monitor_incident_reset_stream(analyzer_protocol_t protocol,
                                   uint32_t stream_key, uint16_t appid,
                                   uint64_t now_us);
void monitor_incident_stats(monitor_incident_stats_t *out);
bool monitor_incident_peek(size_t slot, monitor_incident_info_t *out);
bool monitor_incident_read(size_t slot, size_t packet,
                          analyzer_packet_metadata_t *metadata,
                          uint8_t *bytes, size_t capacity);
bool monitor_incident_ack(size_t slot, uint64_t matching_id);
/* A durable SD acknowledgment may arrive before episode closure. Mark it then,
 * but release storage only after the episode completes, with slot+ID matched. */
bool monitor_incident_export_ack(size_t slot, uint64_t matching_id);
#endif
