/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file analyzer.h
 *
 * @brief IEC 61850 analyzer: parses GOOSE and SV frames, keeps a bounded
 * history per stream and scores four-frame windows with the generated
 * models.
 *
 * @par
 * Only the analysis task may call these functions, so they need no lock.
 */
#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ANALYZER_GOOSE_TEXT_CAPACITY         (64u)
#define ANALYZER_GOOSE_DATA_PREVIEW_CAPACITY (24u)
#define ANALYZER_FEATURE_CAPACITY            (8u)
#define ANALYZER_BATCH_FRAME_COUNT           (4u)
#define ANALYZER_STREAM_ID_CAPACITY          (64u)
#define ANALYZER_MAXIMUM_FRAME_LENGTH        (1518u)
#define ANALYZER_MAC_BYTES                   (6u)
#define ANALYZER_GOOSE_TIMESTAMP_BYTES       (8u)
#define ANALYZER_VALUE_WORDS                 (6u)

// NOTE: The stream counts keep the measured RAM budget. Raising them needs a
// new RAM measurement; keeping only metadata is not equivalent evidence.
//
#ifndef ANALYZER_MAXIMUM_GOOSE_STREAMS
#define ANALYZER_MAXIMUM_GOOSE_STREAMS (4u)
#endif

#ifndef ANALYZER_MAXIMUM_SV_STREAMS
#define ANALYZER_MAXIMUM_SV_STREAMS (1u)
#endif

// 1 (default): all four raw frames of a scored window are kept. Each stream
// has three waiting slots and the scored stream shares one completion slot,
// so no frame is stored twice.
// 0: only the newest raw frame of a scored window is kept; the other three
// are kept as metadata only.
//
#ifndef ANALYZER_STORE_WINDOW_FRAMES
#define ANALYZER_STORE_WINDOW_FRAMES (1)
#endif

// Index of the newest frame in a four-frame window.
//
#define ANALYZER_NEWEST_FRAME_INDEX (ANALYZER_BATCH_FRAME_COUNT - 1u)

// Values of analyzer_packet_values_t.format.
//
#define ANALYZER_VALUES_GOOSE_BOOLEAN (1u)
#define ANALYZER_VALUES_SV_FLOAT_BITS (2u)

typedef enum
{
    ANALYZER_PROTOCOL_GOOSE          = 0,
    ANALYZER_PROTOCOL_SAMPLED_VALUES = 1
} analyzer_protocol_t;

/*!
 * @brief Time, counters, addresses and stream ID of one window frame.
 */
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
    uint8_t             source_mac[ANALYZER_MAC_BYTES];
    uint8_t             destination_mac[ANALYZER_MAC_BYTES];
    uint8_t             stream_id_length;
    uint8_t             stream_id[ANALYZER_STREAM_ID_CAPACITY];
} analyzer_packet_metadata_t;

/*!
 * @brief One parsed GOOSE or SV frame and, when ready, its window score.
 *
 * @par
 * NOTE: The member names are shared with the storage, health and alarm
 * modules.
 */
typedef struct
{
    analyzer_protocol_t protocol;
    uint32_t            stream_key;
    uint16_t            appid;
    uint64_t            timestamp_us;
    uint32_t            counter_1;
    uint32_t            counter_2;
    bool                prediction_ready;

    // WARNING: With gating on, a completed window may have no score. Never
    // read inference_skipped as a benign result.
    bool     window_ready;
    bool     inference_skipped;
    uint32_t rule_reasons; // OR of the four window frames.
    uint8_t  warmup_remaining;
    uint8_t  primary_label;
    float    primary_probability;
    bool     secondary_valid;
    uint8_t  secondary_label;
    float    secondary_probability;
    bool     label_changed;

    // True when a capture gap overlapped this stream and its own counter
    // showed lost frames (FR8). The incident store must then drop the
    // stream's previous vote.
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
    uint8_t                    goose_timestamp[ANALYZER_GOOSE_TIMESTAMP_BYTES];
    uint8_t                    goose_timestamp_length;
    uint16_t                   goose_all_data_length;
    uint8_t goose_all_data_preview[ANALYZER_GOOSE_DATA_PREVIEW_CAPACITY];
    uint8_t goose_all_data_preview_length;
} analyzer_result_t;

/*!
 * @brief Analyzer error counters.
 */
typedef struct
{
    uint32_t unsupported_streams;
    uint32_t unsupported_sv_asdu;
    uint32_t malformed_frames;
    uint32_t gaps_noted;    // Capture gaps reported by the caller.
    uint32_t streams_kept;  // Gap-suspect streams whose counter was fine.
    uint32_t streams_reset; // Gap-suspect streams that really lost frames.
} analyzer_diagnostics_t;

/*!
 * @brief Selected values of one window frame, for the incident record.
 */
typedef struct
{
    uint32_t bits[ANALYZER_VALUE_WORDS];
    uint8_t  format; // ANALYZER_VALUES_GOOSE_BOOLEAN or _SV_FLOAT_BITS.
} analyzer_packet_values_t;

void analyzer_reset(void);
void analyzer_note_capture_gap(void);
bool analyzer_process_frame(uint8_t const * p_frame, size_t length,
                            uint64_t            timestamp_us,
                            analyzer_result_t * p_result);
bool analyzer_process_capture(uint8_t const * p_frame, size_t length,
                              uint64_t timestamp_us, uint32_t capture_sequence,
                              analyzer_result_t * p_result);
bool analyzer_process_replay(uint8_t const * p_frame, size_t length,
                             uint64_t            timestamp_us,
                             analyzer_result_t * p_result);
bool analyzer_copy_batch_frame(size_t index, uint8_t * p_output,
                               size_t                       capacity,
                               analyzer_packet_metadata_t * p_metadata);
bool analyzer_copy_batch_metadata(size_t                       index,
                                  analyzer_packet_metadata_t * p_metadata);
bool analyzer_copy_batch_values(size_t                     index,
                                analyzer_packet_values_t * p_values);
void analyzer_get_diagnostics(analyzer_diagnostics_t * p_diagnostics);
bool analyzer_copy_batch_features(float * p_output, size_t capacity,
                                  size_t *              p_count,
                                  analyzer_protocol_t * p_protocol);

#endif /* ANALYZER_H */

/*** end of file ***/
