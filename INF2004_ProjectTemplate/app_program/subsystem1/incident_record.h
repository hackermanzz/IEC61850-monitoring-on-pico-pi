#ifndef MONITOR_INCIDENT_RECORD_H
#define MONITOR_INCIDENT_RECORD_H
#include "../subsystem4/incident_store.h"

#define MONITOR_STORAGE_QUEUE_DEPTH 2u
#define MONITOR_RECORD_LINE_CAPACITY 512u
typedef struct {
    uint64_t timestamp_us;
    uint32_t capture_sequence, counter_1, counter_2;
    uint32_t values[6]; /* exact IEEE-754 bits for SV; values[0]=0/1 for GOOSE */
    uint16_t frame_length;
    uint8_t source[6], destination[6];
    uint8_t value_format; /* 0 unavailable, 1 boolean, 2 six float32 values */
} monitor_record_packet_t;

typedef struct {
    uint64_t incident_id;
    uint32_t protocol, stream_key, probability_bits, rule_reasons;
    uint16_t appid;
    /* flags: 1 raw retained, 2 values missing, 4 first positive window only,
     * 8 SV values from first ASDU only. No closure/later-window summary. */
    uint8_t packet_count, flags, stream_id_length, evidence_slot;
    uint8_t stream_id[ANALYZER_STREAM_ID_CAPACITY];
    monitor_record_packet_t packets[ANALYZER_BATCH_FRAME_COUNT];
} monitor_incident_record_t;

/* Called synchronously by S3 during the completed snapshot lifetime. The
 * returned object contains only copies and can be queued to the SD owner. */
bool monitor_record_capture(const analyzer_result_t *result,
                            const monitor_incident_outcome_t *outcome,
                            monitor_incident_record_t *record);
const char *monitor_record_csv_header(void);
size_t monitor_record_csv_line(const monitor_incident_record_t *record,
                               size_t packet, char *output, size_t capacity);
#endif
