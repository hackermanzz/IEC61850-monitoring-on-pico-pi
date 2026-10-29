/* Fixed-capacity grouped incident evidence API. */
#ifndef PICO_IEC61850_INCIDENT_H
#define PICO_IEC61850_INCIDENT_H

#include "analyzer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define INCIDENT_MAXIMUM_CONTAINERS (4u)
#define INCIDENT_MAXIMUM_BATCHES_PER_CONTAINER (8u)
#define INCIDENT_MAXIMUM_PACKETS (8u)
#define INCIDENT_MAXIMUM_FRAME_LENGTH (1518u)
#define INCIDENT_SESSION_ID_CAPACITY (9u)

typedef enum
{
    INCIDENT_CLOSURE_NONE = 0,
    INCIDENT_CLOSURE_SAFE_PREDICTION,
    INCIDENT_CLOSURE_STALE_SCORE,
    INCIDENT_CLOSURE_CAPTURE_GAP,
    INCIDENT_CLOSURE_INVALID_SCORE,
    INCIDENT_CLOSURE_EVIDENCE_LOSS
} incident_closure_reason_t;

typedef analyzer_packet_metadata_t incident_packet_metadata_t;

typedef struct
{
    analyzer_protocol_t        protocol;
    uint32_t                   stream_key;
    uint16_t                   appid;
    uint64_t                   window_start_us;
    uint64_t                   window_end_us;
    float                      raw_score;
    uint8_t                    packet_count;
    incident_packet_metadata_t packets[4];
} incident_batch_summary_t;

typedef struct
{
    bool                      used;
    bool                      complete;
    bool                      truncated;
    uint64_t                  id;
    uint64_t                  start_us;
    uint64_t                  end_us;
    float                     goose_score;
    float                     sv_score;
    uint32_t                  batch_count;
    uint32_t                  packet_count;
    uint32_t                  lost_batches;
    uint32_t                  lost_packets;
    incident_closure_reason_t closure_reason;
} incident_container_info_t;

typedef struct
{
    uint32_t session_id;
    uint32_t next_sequence;
    uint64_t active_container_id_wide;
    uint32_t completed_containers;
    uint32_t lost_containers;
    uint32_t lost_batches;
    uint32_t lost_packets;
} incident_status_t;

void incident_initialize (uint32_t session_id);
void incident_capture_gap (uint64_t timestamp_us);
/*
 * Incident state is fixed-capacity and has no internal locking. Call these
 * APIs serially from one core; do not call them from an ISR or concurrently.
 */
void incident_observe_prediction (const analyzer_result_t * result,
                                  const uint8_t * const *   frames,
                                  const size_t *            frame_lengths);
bool incident_peek (size_t container_index, incident_container_info_t * info);
bool incident_read_batch (size_t container_index, size_t batch_index,
                          incident_batch_summary_t * batch);
bool incident_read_packet (size_t container_index, size_t packet_index,
                           incident_packet_metadata_t * metadata,
                           uint8_t * frame, size_t capacity);
bool incident_acknowledge (size_t container_index, uint64_t matching_id);
void incident_observe_analyzer_prediction (const analyzer_result_t * result);
void incident_check_stale (uint64_t now_us);
void incident_get_status (incident_status_t * status);

#endif
