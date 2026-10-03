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

typedef enum
{
    ANALYZER_PROTOCOL_GOOSE          = 0,
    ANALYZER_PROTOCOL_SAMPLED_VALUES = 1
} analyzer_protocol_t;

/* One parsed IEC 61850 frame and, when ready, its four-frame prediction. */
typedef struct
{
    analyzer_protocol_t protocol;
    uint32_t            stream_key;
    uint16_t            appid;
    uint32_t            counter_1;
    uint32_t            counter_2;
    bool                prediction_ready;
    uint8_t             warmup_remaining;
    uint8_t             primary_label;
    float               primary_probability;
    bool                secondary_valid;
    uint8_t             secondary_label;
    float               secondary_probability;
    bool                label_changed;
    uint8_t             feature_count;
    float               features[ANALYZER_FEATURE_CAPACITY];
    char                goose_gocb_ref[ANALYZER_GOOSE_TEXT_CAPACITY];
    char                goose_dataset[ANALYZER_GOOSE_TEXT_CAPACITY];
    char                goose_go_id[ANALYZER_GOOSE_TEXT_CAPACITY];
    uint32_t            goose_ttl_ms;
    uint32_t            goose_conf_rev;
    uint32_t            goose_num_entries;
    bool                goose_simulation;
    bool                goose_nds_com;
    uint8_t             goose_timestamp[8];
    uint8_t             goose_timestamp_length;
    uint16_t            goose_all_data_length;
    uint8_t goose_all_data_preview[ANALYZER_GOOSE_DATA_PREVIEW_CAPACITY];
    uint8_t goose_all_data_preview_length;
} analyzer_result_t;

typedef struct
{
    uint32_t unsupported_streams;
    uint32_t unsupported_sv_asdu;
    uint32_t malformed_frames;
} analyzer_diagnostics_t;

/* Clear per-stream feature history after a capture sequence gap. */
void analyzer_reset (void);
/* Return true for a parsed GOOSE or SV frame, including batch warm-up frames.
 */
bool analyzer_process_ethernet_frame (const uint8_t * frame, size_t length,
                                      uint64_t            timestamp_us,
                                      analyzer_result_t * result);
void analyzer_get_diagnostics (analyzer_diagnostics_t * diagnostics);
bool analyzer_copy_last_batch_features (float * output, size_t capacity,
                                        size_t *              count,
                                        analyzer_protocol_t * protocol);

#endif
