#ifndef MONITOR_STATUS_H
#define MONITOR_STATUS_H
#include <stdint.h>
#include "subsystem4/incident_store.h"
#include "subsystem3/iec_rules.h"
#include "subsystem2/rmii_capture_hw.h"
#include "subsystem1/storage_writer.h"
typedef struct {
    uint32_t heartbeat, isr_count, rx_frames, bad_crc, non_iec_dropped;
    uint32_t pool_empty, rx_overrun, dma_full, send_failed, cleanup_failed;
    uint32_t decode_last_us, decode_max_us;
    uint32_t phy_found, phy_address, link_up, last_seq, fault;
    uint32_t start_attempts, recoveries;
    rmii_hw_phy_diag_t phy;
    uint16_t sample_words_last, decoded_bytes_last;
    uint32_t short_captures;
} monitor_capture_stats_t;
typedef struct {
    uint32_t heartbeat, received, accepted, rejected, predictions;
    uint32_t sequence_gaps, missing_frames, stream_resets;
    uint32_t analysis_max_us, cleanup_failed, summary_dropped, notification_dropped;
    uint32_t receive_errors, fault;
    uint32_t storage_dropped;
    monitor_incident_stats_t incidents;
    iec_rule_stats_t rules;
} monitor_analysis_stats_t;
typedef struct {
    uint32_t configured, utc_ready, wifi_up, busy;
    uint32_t succeeded, failed, expired, result, http_status;
    uint32_t tls_bytes, tls_peak_bytes, tls_allocation_failures;
} monitor_network_stats_t;

typedef struct {
    uint32_t owner, task_id, total_bytes, paint_prefix, written_lower, bottom_touched;
    int32_t error;
} monitor_stack_stats_t;
typedef struct {
    uint32_t source; /* 2 capture, 3 analysis, 5 notifications, 6 stacks, 1 storage */
    uint64_t generated_us;
    union {
        monitor_capture_stats_t capture;
        monitor_analysis_stats_t analysis;
        monitor_network_stats_t network;
        monitor_stack_stats_t stack;
        monitor_storage_stats_t storage;
    } data;
} monitor_status_message_t;
#endif
