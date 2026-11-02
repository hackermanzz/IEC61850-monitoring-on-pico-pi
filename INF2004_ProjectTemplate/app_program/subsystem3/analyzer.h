/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Public C types and functions for the IEC 61850 analyzer module.
 */

#ifndef PICO_IEC61850_ANALYZER_H
#define PICO_IEC61850_ANALYZER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ANALYZER_GOOSE_TEXT_CAPACITY (64u)
#define ANALYZER_GOOSE_DATA_PREVIEW_CAPACITY (24u)
#define ANALYZER_FEATURE_CAPACITY (8u)
#define ANALYZER_BATCH_FRAME_COUNT (4u)
#define ANALYZER_STREAM_ID_CAPACITY (64u)
#define ANALYZER_MAXIMUM_FRAME_LENGTH (1518u)
/* Preserve baseline capacity and all four raw frames. Expanding stream count
 * requires a measured RAM budget; metadata-only evidence is not equivalent. */
#ifndef ANALYZER_MAXIMUM_GOOSE_STREAMS
#define ANALYZER_MAXIMUM_GOOSE_STREAMS (4u)
#endif
#ifndef ANALYZER_MAXIMUM_SV_STREAMS
#define ANALYZER_MAXIMUM_SV_STREAMS (1u)
#endif
/* 0: keep only the newest raw frame of a scored window as evidence;
 *   the other three window frames are kept as metadata.
 * 1 (default): all four raw frames of a scored window are available. Three
 * waiting slots per stream and one shared completion slot avoid duplicates. */
#ifndef ANALYZER_STORE_WINDOW_FRAMES
#define ANALYZER_STORE_WINDOW_FRAMES (1)
#endif
/* Index of the newest frame inside a four frame window. */
#define ANALYZER_NEWEST_FRAME_INDEX (ANALYZER_BATCH_FRAME_COUNT - 1u)

typedef enum
{
    ANALYZER_PROTOCOL_GOOSE          = 0,
    ANALYZER_PROTOCOL_SAMPLED_VALUES = 1
} analyzer_protocol_t;

typedef struct
{
    uint64_t            timestamp_us;
    uint32_t            capture_sequence;
    uint32_t            counter_1;
    uint32_t            counter_2;
    uint16_t            frame_length;
    uint16_t            appid;
    analyzer_protocol_t protocol;
    uint32_t            stream_key;
    uint8_t             source_mac[6];
    uint8_t             destination_mac[6];
    uint8_t             stream_id_length;
    uint8_t             stream_id[ANALYZER_STREAM_ID_CAPACITY];
} analyzer_packet_metadata_t;

/* One parsed IEC 61850 frame and, when ready, its four-frame prediction. */
typedef struct
{
    analyzer_protocol_t        protocol;
    uint32_t                   stream_key;
    uint16_t                   appid;
    uint64_t                   timestamp_us;
    uint32_t                   counter_1;
    uint32_t                   counter_2;
    bool                       prediction_ready;
    /* A completed window may deliberately have no score in optional gated
     * mode. Never interpret inference_skipped as a benign prediction. */
    bool                       window_ready;
    bool                       inference_skipped;
    uint32_t                   rule_reasons; /* OR of the four scored-window frames */
    uint8_t                    warmup_remaining;
    uint8_t                    primary_label;
    float                      primary_probability;
    bool                       secondary_valid;
    uint8_t                    secondary_label;
    float                      secondary_probability;
    bool                       label_changed;
    /* True when this frame's stream was reset because a capture gap
     * overlapped it and its own counter showed lost frames (FR8). The
     * Incident Manager must drop this stream's previous vote. */
    bool                       stream_reset;
    uint8_t                    batch_frame_count;
    analyzer_packet_metadata_t batch_packets[ANALYZER_BATCH_FRAME_COUNT];
    uint8_t                    feature_count;
    float                      features[ANALYZER_FEATURE_CAPACITY];
    char                       goose_gocb_ref[ANALYZER_GOOSE_TEXT_CAPACITY];
    char                       goose_dataset[ANALYZER_GOOSE_TEXT_CAPACITY];
    char                       goose_go_id[ANALYZER_GOOSE_TEXT_CAPACITY];
    uint32_t                   goose_ttl_ms;
    uint32_t                   goose_conf_rev;
    uint32_t                   goose_num_entries;
    bool                       goose_simulation;
    bool                       goose_nds_com;
    uint8_t                    goose_timestamp[8];
    uint8_t                    goose_timestamp_length;
    uint16_t                   goose_all_data_length;
    uint8_t goose_all_data_preview[ANALYZER_GOOSE_DATA_PREVIEW_CAPACITY];
    uint8_t goose_all_data_preview_length;
} analyzer_result_t;

typedef struct
{
    uint32_t unsupported_streams;
    uint32_t unsupported_sv_asdu;
    uint32_t malformed_frames;
    uint32_t gaps_noted;      /* capture gaps reported by the caller */
    uint32_t streams_kept;    /* gap suspect streams whose counter was fine */
    uint32_t streams_reset;   /* gap suspect streams that really lost frames */
} analyzer_diagnostics_t;

/* Clear every stream. Use at start up only. */
void analyzer_reset (void);
/*
 * Tell the analyzer that the capture sequence number jumped (frames were
 * dropped before analysis). Every active stream becomes "gap suspect". On its
 * next frame each stream checks its own counter (GOOSE stNum/sqNum, SV
 * smpCnt): if it is continuous the window is kept, otherwise only that
 * stream is reset and result->stream_reset is set. Replaces the old global
 * analyzer_reset() on every gap, which let one burst blind every stream.
 */
void analyzer_note_capture_gap (void);
/* Return true for a parsed GOOSE or SV frame, including batch warm-up frames.
 */
bool analyzer_process_ethernet_frame (const uint8_t * frame, size_t length,
                                      uint64_t            timestamp_us,
                                      analyzer_result_t * result);
bool analyzer_process_ethernet_capture (const uint8_t * frame, size_t length,
                                        uint64_t            timestamp_us,
                                        uint32_t            capture_sequence,
                                        analyzer_result_t * result);
bool analyzer_process_ethernet_replay (const uint8_t * frame, size_t length,
                                       uint64_t            timestamp_us,
                                       analyzer_result_t * result);
/*
 * Copy one full packet from the latest completed batch. Call immediately
 * after prediction_ready and before any later analyzer processing call or
 * analyzer_reset(). The snapshot belongs to the Stream Analysis task: only
 * that task may call the analyzer, so no lock is needed.
 * Input bytes have already been copied; the caller may reuse the input buffer.
 * With ANALYZER_STORE_WINDOW_FRAMES == 0 only ANALYZER_NEWEST_FRAME_INDEX
 * has bytes; the other indexes return false (use the metadata call below).
 */
bool analyzer_copy_last_batch_frame (size_t index, uint8_t * output,
                                     size_t                       capacity,
                                     analyzer_packet_metadata_t * metadata);
/* Metadata (time, counters, MACs, stream id) of any frame of the latest
 * completed batch. Always available for all four indexes. */
bool analyzer_copy_last_batch_metadata (size_t                       index,
                                        analyzer_packet_metadata_t * metadata);
typedef struct {
    uint32_t bits[6];
    uint8_t format; /* 1 GOOSE boolean, 2 SV six model-channel float32 bits */
} analyzer_packet_values_t;
/* S3 only: selected values from the same four-frame evidence snapshot, copied
 * without retaining a raw packet pointer or allocating another frame buffer. */
bool analyzer_copy_last_batch_values(size_t index, analyzer_packet_values_t *out);
void analyzer_get_diagnostics (analyzer_diagnostics_t * diagnostics);
bool analyzer_copy_last_batch_features (float * output, size_t capacity,
                                        size_t *              count,
                                        analyzer_protocol_t * protocol);

#endif
