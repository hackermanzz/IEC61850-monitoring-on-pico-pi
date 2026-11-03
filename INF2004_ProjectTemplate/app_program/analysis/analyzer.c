/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file analyzer.c
 *
 * @brief IEC 61850 analyzer: bounded parsing of GOOSE and SV frames, per
 * stream feature histories, and scoring of four-frame windows.
 *
 * @par
 * Each frame is parsed with bounds checks only (no allocation), checked by
 * the rule engine, and turned into one row of features. Every four frames,
 * with a stride of two, the rows are aggregated and scored by the generated
 * random-forest model of the frame's protocol.
 *
 * @par
 * The parsers return as soon as input is found to be malformed (see the
 * deviations in docs/coding_standard.md).
 */

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "analyzer.h"
#include "generated_batch_models.h"
#include "iec_rules.h"
#include "rule_profiles.h"

// Stream and window sizes.
//
#define GOOSE_ETHERTYPE           (0x88B8u)
#define SV_ETHERTYPE              (0x88BAu)
#define MAXIMUM_ASDUS             (14u)
#define MAXIMUM_GOOSE_STREAMS     (ANALYZER_MAXIMUM_GOOSE_STREAMS)
#define MAXIMUM_STREAM_ID_LENGTH  (ANALYZER_STREAM_ID_CAPACITY)
#define MAC_ADDRESS_LENGTH        (ANALYZER_MAC_BYTES)
#define GOOSE_FEATURE_COUNT       (13u)
#define SV_FEATURE_COUNT          (18u)
#define GOOSE_BATCH_FEATURE_COUNT (52u)
#define SV_BATCH_FEATURE_COUNT    (72u)
#define FLOAT32_SIZE              (4u)

// BER encoding.
//
#define BER_MAX_LENGTH_OCTETS           (sizeof(size_t))
#define BER_UNSIGNED_INTEGER_MAX_OCTETS (5u)
#define BER_TAG_HIGH_BIT_MASK           (0x80u)
#define BER_LENGTH_OCTET_MASK           (0x7Fu)
#define BER_TLV_HEADER_SIZE             (2u)
#define BITS_PER_BYTE                   (8u)
#define BYTE_MASK                       (0xFFu)
#define BE32_BYTE_0_SHIFT               (24u)
#define BE32_BYTE_1_SHIFT               (16u)
#define BE32_BYTE_2_SHIFT               (8u)
#define CONTEXT_TAG_BASE                (0x80u)

// Ethernet and IEC 61850 framing.
//
#define ETHERNET_HEADER_SIZE         (14u)
#define ETHERNET_TYPE_FIELD_OFFSET   (12u)
#define VLAN_TAG_HEADER_SIZE         (4u)
#define VLAN_TYPE_FIELD_OFFSET       (2u)
#define MAXIMUM_VLAN_TAGS            (2u)
#define ETHERNET_VLAN_8021Q_TYPE     (0x8100u)
#define ETHERNET_VLAN_8021AD_TYPE    (0x88A8u)
#define ETHERNET_VLAN_QINQ_TYPE      (0x9100u)
#define IEC61850_APDU_MINIMUM_LENGTH (10u)
#define IEC61850_APDU_OFFSET         (8u)
#define IEC61850_APDU_LENGTH_OFFSET  (2u)
#define IEC61850_RESERVED1_OFFSET    (4u)
#define IEC61850_SIMULATE_BIT        (0x80u)
#define MAXIMUM_ENCODED_ASDU_COUNT   (256u)

// GOOSE tags. Each context tag 0x80 + n sets bit n of the "seen" mask;
// allData sets bit 11.
//
#define GOOSE_APDU_TAG                   (0x61u)
#define GOOSE_TAG_GOCB_REF               (0x80u)
#define GOOSE_TAG_TIME_ALLOWED_TO_LIVE   (0x81u)
#define GOOSE_TAG_DATASET                (0x82u)
#define GOOSE_TAG_GO_ID                  (0x83u)
#define GOOSE_TAG_TIMESTAMP              (0x84u)
#define GOOSE_TAG_STATE_NUMBER           (0x85u)
#define GOOSE_TAG_SEQUENCE_NUMBER        (0x86u)
#define GOOSE_TAG_SIMULATION             (0x87u)
#define GOOSE_TAG_CONFIGURATION_REVISION (0x88u)
#define GOOSE_TAG_NEEDS_COMMISSIONING    (0x89u)
#define GOOSE_TAG_NUMBER_OF_ENTRIES      (0x8Au)
#define GOOSE_TAG_ALL_DATA               (0xABu)
#define GOOSE_BOOLEAN_DATA_TAG           (0x83u)
#define GOOSE_ALL_DATA_BIT               (1u << 11)

// Every GOOSE field except goID, simulation and ndsCom.
//
#define GOOSE_REQUIRED_FIELDS (0xD77u)

// SV tags. In an ASDU each context tag 0x80 + n sets bit n of the "seen"
// mask.
//
#define SV_APDU_TAG                   (0x60u)
#define BER_SEQUENCE_TAG              (0x30u)
#define SV_SEQUENCE_TAG               (0xA2u)
#define SV_TAG_COUNT                  (0x80u)
#define SV_TAG_IDENTIFIER             (0x80u)
#define SV_TAG_SAMPLE_COUNT           (0x82u)
#define SV_TAG_CONFIGURATION_REVISION (0x83u)
#define SV_TAG_SAMPLE_SYNCHRONIZATION (0x85u)
#define SV_TAG_SEQUENCE_DATA          (0x87u)
#define SV_TAG_LAST_KNOWN             (0x88u)
#define SV_SAMPLE_COUNT_BYTES         (2u)
#define SV_CONFIGURATION_BYTES        (4u)
#define SV_SYNCHRONIZATION_BYTES      (1u)
#define SV_SEEN_COUNT                 (1u)
#define SV_SEEN_SEQUENCE              (2u)

// svID, smpCnt, confRev, smpSynch and seqData.
//
#define SV_REQUIRED_FIELDS (0xADu)

// Feature arithmetic.
//
#define BATCH_FEATURES_PER_METRIC (4u)
#define METRIC_MEAN               (0u)
#define METRIC_MAXIMUM            (1u)
#define METRIC_LAST               (2u)
#define METRIC_STANDARD_DEVIATION (3u)
#define INTEGER_MIDPOINT_DIVISOR  (2u)
#define FLOAT_MIDPOINT_RATIO      (0.5f)
#define SECONDS_PER_MICROSECOND   (1.0e-6f)
#define UINT32_RANGE              (INT64_C(4294967296))
#define FNV_OFFSET_BASIS          (UINT32_C(2166136261))
#define FNV_PRIME                 (UINT32_C(16777619))
#define ASCII_PRINTABLE_MINIMUM   (32u)
#define ASCII_PRINTABLE_MAXIMUM   (127u)
#define GOOSE_NEW_EVENT_MAX_SQ    (1u)

// Values the generated models were trained with.
//
#define EXPECTED_BATCH_FRAME_COUNT     (4u)
#define EXPECTED_BATCH_STRIDE          (2u)
#define EXPECTED_SV_CHANNEL_COUNT      (6u)
#define EXPECTED_WAVE_HISTORY_SAMPLES  (128u)
#define EXPECTED_TIMING_HISTORY_FRAMES (32u)

enum goose_feature_index
{
    GOOSE_FEATURE_INTERVAL_SECONDS = 0,
    GOOSE_FEATURE_INTERVAL_RATIO,
    GOOSE_FEATURE_ST_NUMBER_DELTA,
    GOOSE_FEATURE_ST_NUMBER_ROLLBACK,
    GOOSE_FEATURE_ST_NUMBER_JUMP,
    GOOSE_FEATURE_SQ_NUMBER_DELTA,
    GOOSE_FEATURE_SQ_NUMBER_ROLLBACK,
    GOOSE_FEATURE_SOURCE_CHANGED,
    GOOSE_FEATURE_HISTORY_AVAILABLE,
    GOOSE_FEATURE_SV_AGE_SECONDS,
    GOOSE_FEATURE_BOOLEAN_VALUE,
    GOOSE_FEATURE_BOOLEAN_MISSING,
    GOOSE_FEATURE_BOOLEAN_CHANGED
};

enum sv_feature_index
{
    SV_FEATURE_INTERVAL_SECONDS = 0,
    SV_FEATURE_INTERVAL_RATIO,
    SV_FEATURE_GOOSE_AGE_SECONDS,
    SV_FEATURE_ASDU_COUNT,
    SV_FEATURE_COUNTER_BACK,
    SV_FEATURE_COUNTER_REPEAT,
    SV_FEATURE_COUNTER_GAP,
    SV_FEATURE_COUNTER_DELTA_MAXIMUM,
    SV_FEATURE_WAVE_RELATIVE_CHANGE_MEAN,
    SV_FEATURE_WAVE_RELATIVE_CHANGE_MAXIMUM,
    SV_FEATURE_WAVE_JUMP_FRACTION,
    SV_FEATURE_WAVE_PLATEAU_FRACTION,
    SV_FEATURE_WAVE_JUMP_COUNT,
    SV_FEATURE_WAVE_HISTORY_COVERAGE,
    SV_FEATURE_WAVE_ROBUST_RATIO,
    SV_FEATURE_CHANNEL_RANGE_MEAN,
    SV_FEATURE_CHANNEL_RANGE_MAXIMUM,
    SV_FEATURE_SOURCE_CHANGED
};

_Static_assert(PICO_ML_BATCH_SIZE_FRAMES == EXPECTED_BATCH_FRAME_COUNT,
               "the models score four-frame windows");
_Static_assert(PICO_ML_BATCH_STRIDE_FRAMES == EXPECTED_BATCH_STRIDE,
               "the models use a window stride of two");
_Static_assert(PICO_ML_BATCH_SV_CHANNEL_COUNT == EXPECTED_SV_CHANNEL_COUNT,
               "the SV model uses six channels");
_Static_assert(PICO_ML_BATCH_WAVE_HISTORY_SAMPLES
                   == EXPECTED_WAVE_HISTORY_SAMPLES,
               "the SV model uses a 128-sample wave history");
_Static_assert(PICO_ML_BATCH_TIMING_HISTORY_FRAMES
                   == EXPECTED_TIMING_HISTORY_FRAMES,
               "the models use a 32-frame timing history");

/*!
 * @brief A generated model: scores one row of window features.
 */
typedef float (*batch_predictor_t)(float const * p_features);

/*!
 * @brief The payload of an Ethernet frame after any VLAN tags.
 */
typedef struct
{
    uint16_t        type;
    uint8_t const * p_data;
    size_t          length;
} ethernet_payload_t;

/*!
 * @brief One BER tag-length-value element.
 */
typedef struct
{
    uint8_t         tag;
    uint8_t const * p_value;
    size_t          length;
    uint8_t const * p_next;
} analyzer_tlv_t;

/*!
 * @brief The fields of one GOOSE PDU; pointers borrow the frame.
 */
typedef struct
{
    uint16_t        appid;
    uint8_t const * p_gocb_ref;
    size_t          gocb_ref_length;
    uint8_t const * p_dataset;
    size_t          dataset_length;
    uint8_t const * p_go_id;
    size_t          go_id_length;
    uint8_t const * p_timestamp;
    size_t          timestamp_length;
    uint8_t const * p_all_data;
    size_t          all_data_length;
    uint32_t        ttl_ms;
    uint32_t        st_num;
    uint32_t        sq_num;
    uint32_t        conf_rev;
    uint32_t        num_entries;
    bool            b_simulation;
    bool            b_nds_com;
    uint32_t        rule_reasons;
} goose_fields_t;

/*!
 * @brief The fields of one SV ASDU; pointers borrow the frame.
 */
typedef struct
{
    uint8_t const * p_sv_id;
    size_t          sv_id_length;
    uint32_t        smp_cnt;
    uint32_t        conf_rev;
    uint32_t        smp_synch;
    uint8_t const * p_seq_data;
    size_t          seq_data_length;
    uint32_t        rule_reasons;
} sv_asdu_t;

/*!
 * @brief The fields of one SV PDU.
 */
typedef struct
{
    sv_asdu_t asdus[MAXIMUM_ASDUS];
    uint16_t  appid;
    uint32_t  no_asdu;
    size_t    asdu_count;
    uint32_t  rule_reasons;
} sv_fields_t;

/*!
 * @brief What identifies a stream: destination, APPID and gocbRef or svID.
 */
typedef struct
{
    uint8_t  destination_mac[MAC_ADDRESS_LENGTH];
    uint16_t appid;
    size_t   stream_id_length;
    uint8_t  stream_id[MAXIMUM_STREAM_ID_LENGTH];
} stream_identity_t;

/*!
 * @brief The history and window of one GOOSE stream.
 */
typedef struct
{
    bool              b_used;
    uint32_t          key;
    stream_identity_t identity;
    float             previous_intervals[PICO_ML_BATCH_TIMING_HISTORY_FRAMES];
    size_t            interval_count;
    size_t            interval_next;
    uint64_t          timestamp_us;
    uint32_t          st_num;
    uint32_t          sq_num;
    bool              b_has_time;
    bool              b_has_st;
    bool              b_has_sq;
    bool              b_has_source;
    bool              b_has_boolean;
    uint8_t           source[MAC_ADDRESS_LENGTH];
    uint8_t           boolean_value;
    float             batch[PICO_ML_BATCH_SIZE_FRAMES][GOOSE_FEATURE_COUNT];
    uint32_t          batch_rule_reasons[ANALYZER_BATCH_FRAME_COUNT];
    analyzer_packet_metadata_t batch_packets[ANALYZER_BATCH_FRAME_COUNT];
#if ANALYZER_STORE_WINDOW_FRAMES
    uint8_t batch_frames[ANALYZER_BATCH_FRAME_COUNT - 1u]
                        [ANALYZER_MAXIMUM_FRAME_LENGTH];
#endif
    size_t  batch_count;
    bool    b_has_prediction;
    uint8_t previous_label;
    bool    b_gap_suspect;
} goose_state_t;

/*!
 * @brief The history and window of one SV stream.
 */
typedef struct
{
    bool              b_used;
    uint32_t          key;
    stream_identity_t identity;
    float             previous_intervals[PICO_ML_BATCH_TIMING_HISTORY_FRAMES];
    size_t            interval_count;
    size_t            interval_next;
    uint64_t          timestamp_us;
    bool              b_has_time;
    bool              b_has_source;
    uint8_t           source[MAC_ADDRESS_LENGTH];
    uint32_t          counters[MAXIMUM_ASDUS];
    bool              b_has_counter[MAXIMUM_ASDUS];
    float             wave[MAXIMUM_ASDUS][PICO_ML_BATCH_SV_CHANNEL_COUNT]
                          [PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
    uint16_t          wave_count[MAXIMUM_ASDUS][PICO_ML_BATCH_SV_CHANNEL_COUNT];
    uint16_t          wave_next[MAXIMUM_ASDUS][PICO_ML_BATCH_SV_CHANNEL_COUNT];
    float             wave_deltas[PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
    size_t            wave_delta_count;
    size_t            wave_delta_next;
    float             batch[PICO_ML_BATCH_SIZE_FRAMES][SV_FEATURE_COUNT];
    uint32_t          batch_rule_reasons[ANALYZER_BATCH_FRAME_COUNT];
    analyzer_packet_metadata_t batch_packets[ANALYZER_BATCH_FRAME_COUNT];
#if ANALYZER_STORE_WINDOW_FRAMES
    uint8_t batch_frames[ANALYZER_BATCH_FRAME_COUNT - 1u]
                        [ANALYZER_MAXIMUM_FRAME_LENGTH];
#endif
    size_t  batch_count;
    bool    b_has_prediction;
    uint8_t previous_label;
    bool    b_gap_suspect;
} sv_state_t;

/*!
 * @brief Intermediate SV counter and waveform measurements of one frame.
 */
typedef struct
{
    uint32_t back;
    uint32_t repeat;
    uint32_t gap;
    uint32_t jumps;
    uint32_t flat;
    uint32_t value_count;
    float    delta_max;
    size_t   change_count;
    size_t   previous_wave_count;
    float    robust;
    float    change_sum;
    float    change_max;
    float    ranges[PICO_ML_BATCH_SV_CHANNEL_COUNT];
    float    range_sum;
    float    range_max;
} sv_batch_metrics_t;

// Stream histories and cross-protocol times.
//
static goose_state_t g_goose_states[MAXIMUM_GOOSE_STREAMS];
static sv_state_t    g_sv_states[ANALYZER_MAXIMUM_SV_STREAMS];
static uint64_t      g_latest_goose_us;
static uint64_t      g_latest_sv_us;
static bool          gb_have_latest_goose;
static bool          gb_have_latest_sv;

// Error counters.
//
static uint32_t g_unsupported_streams;
static uint32_t g_unsupported_sv_asdu;
static uint32_t g_malformed_frames;
static bool     gb_unsupported_parse;
static uint32_t g_gaps_noted;
static uint32_t g_streams_kept;
static uint32_t g_streams_reset;

// Scratch buffers, too big for the task stack.
//
static float g_median_scratch[PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
static float g_timing_scratch[PICO_ML_BATCH_TIMING_HISTORY_FRAMES];
static float g_sv_changes[MAXIMUM_ASDUS * PICO_ML_BATCH_SV_CHANNEL_COUNT];
static float g_sv_channel_values[PICO_ML_BATCH_SV_CHANNEL_COUNT][MAXIMUM_ASDUS];
static float g_sv_history_scratch[PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];

// The latest completed window.
//
static float               g_last_batch_features[SV_BATCH_FEATURE_COUNT];
static size_t              g_last_batch_feature_count;
static analyzer_protocol_t g_last_batch_protocol = ANALYZER_PROTOCOL_GOOSE;
static analyzer_packet_metadata_t
    g_last_batch_packets[ANALYZER_BATCH_FRAME_COUNT];

#if ANALYZER_STORE_WINDOW_FRAMES
// Each stream holds three waiting frames; only the stream being scored needs
// a fourth, kept here so that the caller may reuse its input at once. The
// first three slots of a completed window stay untouched until the next
// processing call, so the incident store can copy them first.
//
static uint8_t   g_completed_newest_frame[ANALYZER_MAXIMUM_FRAME_LENGTH];
static uint8_t * gp_completed_window_frames;

// NOTE: A macro, because GOOSE and SV states are different types.
//
#define STATE_FRAMES(p_state) (&(p_state)->batch_frames[0][0])
#else
// The newest frame of the latest scored window (the frame being processed
// when the window completed). The other window frames survive as metadata.
//
static uint8_t g_last_newest_frame[ANALYZER_MAXIMUM_FRAME_LENGTH];

#define STATE_FRAMES(p_state) ((uint8_t *) NULL)
#endif

// The frame being processed.
//
static uint8_t const * gp_current_frame;
static size_t          g_current_frame_length;
static uint32_t        g_current_capture_sequence;
static uint32_t        g_legacy_capture_sequence;

static void  record_batch_packet(analyzer_packet_metadata_t * p_packets,
                                 uint8_t * p_frames, size_t batch_index,
                                 analyzer_result_t const * p_result,
                                 stream_identity_t const * p_identity);
static void  advance_completed_window(void);
static float maximum_float(float left, float right);
static float minimum_float(float left, float right);

static uint16_t read_be16(uint8_t const * p_value);
static bool     read_ber_uint(uint8_t const * p_value, size_t length,
                              uint32_t * p_output);
static bool     read_ber_boolean(uint8_t const * p_value, size_t length,
                                 bool * pb_output);
static bool     read_tlv(uint8_t const * p_cursor, uint8_t const * p_end,
                         analyzer_tlv_t * p_output);
static bool     find_ethernet_payload(uint8_t const * p_frame, size_t length,
                                      ethernet_payload_t * p_output);
static bool     read_apdu(ethernet_payload_t const * p_payload, uint8_t tag,
                          analyzer_tlv_t * p_apdu, uint32_t * p_reasons);
static uint32_t goose_field_bit(uint8_t tag);
static bool     parse_goose_field(analyzer_tlv_t const * p_field,
                                  goose_fields_t * p_fields, bool * pb_have_ref,
                                  bool * pb_have_st_num, bool * pb_have_sq_num);
static size_t   count_data_entries(goose_fields_t * p_fields);
static bool     parse_goose(ethernet_payload_t const * p_payload,
                            goose_fields_t *           p_output);
static bool     parse_sv_asdu(analyzer_tlv_t const * p_raw, sv_asdu_t * p_asdu);
static bool parse_sv_asdus(uint8_t const * p_sequence, size_t sequence_length,
                           sv_fields_t * p_fields);
static bool parse_sv(ethernet_payload_t const * p_payload,
                     sv_fields_t *              p_output);

static uint32_t batch_hash(uint16_t appid, uint8_t const * p_stream_id,
                           size_t          stream_id_length,
                           uint8_t const * p_destination);
static bool     identity_matches(stream_identity_t const * p_identity,
                                 uint16_t appid, uint8_t const * p_stream_id,
                                 size_t          stream_id_length,
                                 uint8_t const * p_destination);
static goose_state_t * goose_state_for(uint16_t        appid,
                                       uint8_t const * p_stream_id,
                                       size_t          stream_id_length,
                                       uint8_t const * p_destination,
                                       uint32_t        key);
static sv_state_t * sv_state_for(uint16_t appid, uint8_t const * p_stream_id,
                                 size_t          stream_id_length,
                                 uint8_t const * p_destination, uint32_t key);

static float select_median_upper(size_t count, size_t target);
static float batch_median(float const * p_values, size_t count);
static float ring_median(float const * p_values, size_t capacity, size_t count,
                         size_t next);

static void push_interval(float * p_values, size_t capacity, size_t * p_count,
                          size_t * p_next, float interval);

static void
save_completed_batch_snapshot(analyzer_packet_metadata_t * p_packets,
                              uint8_t *                    p_raw_frames,
                              analyzer_result_t *          p_result);
static void aggregate_batch(float const * p_batch, size_t feature_count,
                            float * p_output);
static void advance_batch(float * p_batch, size_t feature_count,
                          size_t *                     p_batch_count,
                          analyzer_packet_metadata_t * p_packets,
                          uint32_t *                   p_batch_rules);
static void
predict_batch(float * p_batch, size_t feature_count, size_t * p_batch_count,
              float const * p_frame, analyzer_result_t * p_result,
              uint8_t * p_previous_label, bool * pb_has_prediction,
              float threshold, batch_predictor_t p_predict, size_t output_count,
              analyzer_packet_metadata_t * p_packets, uint8_t * p_raw_frames,
              uint32_t rule_profile, uint32_t * p_batch_rules);

static void copy_printable(char * p_output, size_t capacity,
                           uint8_t const * p_input, size_t input_length);
static void wave_push(float * p_values, uint16_t * p_count, uint16_t * p_next,
                      float value);

static uint32_t read_be32_float_bits(uint8_t const * p_value);
static float    float_from_bits(uint32_t bits);

static float goose_predict(float const * p_features);
static float sv_predict(float const * p_features);

static void populate_goose_result(goose_fields_t const * p_fields, uint32_t key,
                                  analyzer_result_t * p_result);
static bool read_goose_boolean(goose_fields_t const * p_fields,
                               bool *                 pb_value);
static void calculate_goose_features(
    goose_state_t * p_state, goose_fields_t const * p_fields,
    uint8_t const * p_source, uint64_t timestamp_us,
    float p_features[GOOSE_FEATURE_COUNT], float * p_delta_seconds,
    bool * pb_boolean_valid, bool * pb_boolean_value);
static void update_goose_state(goose_state_t *        p_state,
                               goose_fields_t const * p_fields,
                               uint8_t const * p_source, uint64_t timestamp_us,
                               float delta_seconds, bool b_boolean_valid,
                               bool b_boolean_value);

static bool goose_counter_continuous(goose_state_t const *  p_state,
                                     goose_fields_t const * p_fields);
static bool sv_counter_continuous(sv_state_t const *  p_state,
                                  sv_fields_t const * p_fields);
static void reset_goose_stream(goose_state_t * p_state);
static void reset_sv_stream(sv_state_t * p_state);
static bool
process_goose_batch(uint8_t const * p_source, uint8_t const * p_destination,
                    goose_fields_t const * p_fields, uint64_t timestamp_us,
                    analyzer_result_t * p_result, uint32_t rule_profile);

static bool  validate_sv_payload(sv_fields_t const * p_fields,
                                 size_t *            p_required_length);
static float wave_relative_change(sv_state_t const * p_state, size_t asdu_index,
                                  size_t channel, float current);
static void  collect_sv_samples(sv_state_t *         p_state,
                                sv_fields_t const *  p_fields,
                                sv_batch_metrics_t * p_metrics);
static void  summarize_sv_history(sv_state_t *         p_state,
                                  sv_batch_metrics_t * p_metrics);
static void  calculate_sv_channel_ranges(size_t               asdu_count,
                                         sv_batch_metrics_t * p_metrics);
static void  calculate_sv_features(sv_state_t const *  p_state,
                                   sv_fields_t const * p_fields,
                                   uint8_t const *     p_source,
                                   uint64_t timestamp_us, float delta_seconds,
                                   float                      ratio,
                                   sv_batch_metrics_t const * p_metrics,
                                   float p_features[SV_FEATURE_COUNT]);
static void  update_sv_state(sv_state_t * p_state, uint8_t const * p_source,
                             uint64_t timestamp_us, float delta_seconds);

static bool
analyze_sv_state(sv_state_t * p_state, uint32_t key, uint8_t const * p_source,
                 sv_fields_t const * p_fields, uint64_t timestamp_us,
                 analyzer_result_t * p_result, uint32_t rule_profile);
static bool
process_sv_batch(uint8_t const * p_source, uint8_t const * p_destination,
                 sv_fields_t const * p_fields, uint64_t timestamp_us,
                 analyzer_result_t * p_result, uint32_t rule_profile);

static uint8_t const * batch_frame_bytes(size_t index);

static bool values_from_goose(ethernet_payload_t const * p_payload,
                              analyzer_packet_values_t * p_values);
static bool values_from_sv(ethernet_payload_t const * p_payload,
                           analyzer_packet_values_t * p_values);
static bool analyze_goose_frame(ethernet_payload_t const * p_payload,
                                uint8_t const *            p_source,
                                uint8_t const *            p_destination,
                                uint64_t                   timestamp_us,
                                analyzer_result_t *        p_result);
static bool analyze_sv_frame(ethernet_payload_t const * p_payload,
                             uint8_t const *            p_source,
                             uint8_t const *            p_destination,
                             uint64_t                   timestamp_us,
                             analyzer_result_t *        p_result);
static bool is_simulated(ethernet_payload_t const * p_payload);
static bool process_frame(uint8_t const * p_frame, size_t length,
                          uint64_t timestamp_us, analyzer_result_t * p_result);

/*!
 * @brief Clear every stream and load the rule profiles.
 *
 * @par
 * Use at start-up only.
 */
void
analyzer_reset (void)
{
    size_t                            profile_count = 0u;
    iec_rules_profile_t const * const p_profiles =
        rule_profiles_table(&profile_count);

    // The result is not needed: an invalid table disables every profile, so
    // every window still runs the model.
    (void) iec_rules_configure(p_profiles, profile_count,
                               (0 != IEC_RULE_GATE_ENABLED));
    memset(g_goose_states, 0, sizeof(g_goose_states));
    memset(g_sv_states, 0, sizeof(g_sv_states));
    g_latest_goose_us          = 0u;
    g_latest_sv_us             = 0u;
    gb_have_latest_goose       = false;
    gb_have_latest_sv          = false;
    g_last_batch_feature_count = 0u;
#if ANALYZER_STORE_WINDOW_FRAMES
    gp_completed_window_frames = NULL;
#endif
    gb_unsupported_parse = false;
}

/*!
 * @brief Note that the capture sequence number jumped.
 *
 * @par
 * Frames were dropped before analysis, so every active stream becomes "gap
 * suspect". On its next frame each stream checks its own counter (GOOSE
 * stNum/sqNum, SV smpCnt): if it is continuous the window is kept, otherwise
 * only that stream is reset and the result's stream_reset is set. This
 * avoids one burst of loss blinding every stream.
 */
void
analyzer_note_capture_gap (void)
{
    size_t index = 0u;

    iec_rules_capture_gap();

    ++g_gaps_noted;

    for (index = 0u; index < MAXIMUM_GOOSE_STREAMS; ++index)
    {
        if (g_goose_states[index].b_used)
        {
            g_goose_states[index].b_gap_suspect = true;
        }
    }

    for (index = 0u; index < ANALYZER_MAXIMUM_SV_STREAMS; ++index)
    {
        if (g_sv_states[index].b_used)
        {
            g_sv_states[index].b_gap_suspect = true;
        }
    }
}

/*!
 * @brief Analyse one frame with an automatic capture sequence number.
 *
 * @param[in]  p_frame      The Ethernet frame without FCS.
 * @param[in]  length       The frame length.
 * @param[in]  timestamp_us The capture time.
 * @param[out] p_result     Receives the parse and window result.
 *
 * @return True for a parsed GOOSE or SV frame, including warm-up frames.
 */
bool
analyzer_process_frame (uint8_t const * p_frame, size_t length,
                        uint64_t timestamp_us, analyzer_result_t * p_result)
{
    return (analyzer_process_replay(p_frame, length, timestamp_us, p_result));
}

/*!
 * @brief Analyse one captured frame.
 *
 * @param[in]  p_frame          The Ethernet frame without FCS. It is copied
 *                              as needed, so it may be reused on return.
 * @param[in]  length           The frame length.
 * @param[in]  timestamp_us     The capture time.
 * @param[in]  capture_sequence The capture sequence number of the frame.
 * @param[out] p_result         Receives the parse and window result.
 *
 * @return True for a parsed GOOSE or SV frame, including warm-up frames.
 */
bool
analyzer_process_capture (uint8_t const * p_frame, size_t length,
                          uint64_t timestamp_us, uint32_t capture_sequence,
                          analyzer_result_t * p_result)
{
    bool b_parsed = false;

    advance_completed_window();
    gp_current_frame           = p_frame;
    g_current_frame_length     = length;
    g_current_capture_sequence = capture_sequence;
    b_parsed         = process_frame(p_frame, length, timestamp_us, p_result);
    gp_current_frame = NULL;
    g_current_frame_length = 0u;

    return (b_parsed);
}

/*!
 * @brief Analyse one replayed frame, numbering it automatically.
 *
 * @param[in]  p_frame      The Ethernet frame without FCS.
 * @param[in]  length       The frame length.
 * @param[in]  timestamp_us The capture time.
 * @param[out] p_result     Receives the parse and window result.
 *
 * @return True for a parsed GOOSE or SV frame, including warm-up frames.
 */
bool
analyzer_process_replay (uint8_t const * p_frame, size_t length,
                         uint64_t timestamp_us, analyzer_result_t * p_result)
{
    return (analyzer_process_capture(p_frame, length, timestamp_us,
                                     ++g_legacy_capture_sequence, p_result));
}

/*!
 * @brief Copy one raw frame of the latest completed window.
 *
 * @par
 * Call right after a result with prediction_ready, before the next
 * processing call or analyzer_reset(). With ANALYZER_STORE_WINDOW_FRAMES 0
 * only ANALYZER_NEWEST_FRAME_INDEX has bytes; use
 * analyzer_copy_batch_metadata() for the others.
 *
 * @param[in]  index      The window frame index.
 * @param[out] p_output   Receives the frame bytes.
 * @param[in]  capacity   The size of p_output.
 * @param[out] p_metadata Receives the frame metadata; may be NULL.
 *
 * @return True if the frame was copied.
 */
bool
analyzer_copy_batch_frame (size_t index, uint8_t * p_output, size_t capacity,
                           analyzer_packet_metadata_t * p_metadata)
{
    uint8_t const * p_source = NULL;
    size_t          length   = 0u;
    bool            b_copied = false;

    if ((index < ANALYZER_BATCH_FRAME_COUNT) && (NULL != p_output)
        && (0u != g_last_batch_feature_count))
    {
        length = g_last_batch_packets[index].frame_length;

        if ((capacity >= length) && (0u != length))
        {
            p_source = batch_frame_bytes(index);
        }
    }

    if (NULL != p_source)
    {
        memcpy(p_output, p_source, length);

        if (NULL != p_metadata)
        {
            *p_metadata = g_last_batch_packets[index];
        }

        b_copied = true;
    }

    return (b_copied);
}

/*!
 * @brief Copy the metadata of one frame of the latest completed window.
 *
 * @par
 * Available for all four indexes.
 *
 * @param[in]  index      The window frame index.
 * @param[out] p_metadata Receives the metadata.
 *
 * @return True if the metadata was copied.
 */
bool
analyzer_copy_batch_metadata (size_t                       index,
                              analyzer_packet_metadata_t * p_metadata)
{
    bool b_copied = false;

    if ((index < ANALYZER_BATCH_FRAME_COUNT) && (NULL != p_metadata)
        && (0u != g_last_batch_feature_count))
    {
        *p_metadata = g_last_batch_packets[index];
        b_copied    = true;
    }

    return (b_copied);
}

/*!
 * @brief Copy selected values of one frame of the latest completed window.
 *
 * @par
 * The values are read again from the stored frame, so no raw packet
 * pointer is kept and no extra frame buffer is needed.
 *
 * @param[in]  index    The window frame index.
 * @param[out] p_values Receives the values; zeroed on failure.
 *
 * @return True if the values were copied.
 */
bool
analyzer_copy_batch_values (size_t index, analyzer_packet_values_t * p_values)
{
    uint8_t const *    p_bytes  = NULL;
    ethernet_payload_t payload  = {0};
    bool               b_copied = false;

    if ((NULL != p_values) && (index < ANALYZER_BATCH_FRAME_COUNT)
        && (0u != g_last_batch_feature_count))
    {
        memset(p_values, 0, sizeof(*p_values));
        p_bytes = batch_frame_bytes(index);
    }

    if ((NULL != p_bytes)
        && find_ethernet_payload(
            p_bytes, g_last_batch_packets[index].frame_length, &payload))
    {
        if (GOOSE_ETHERTYPE == payload.type)
        {
            b_copied = values_from_goose(&payload, p_values);
        }
        else if (SV_ETHERTYPE == payload.type)
        {
            b_copied = values_from_sv(&payload, p_values);
        }
        else
        {
            // Neither GOOSE nor SV: there are no values to copy.
        }
    }

    return (b_copied);
}

/*!
 * @brief Copy the analyzer error counters.
 *
 * @param[out] p_diagnostics Receives the counters; may be NULL.
 */
void
analyzer_get_diagnostics (analyzer_diagnostics_t * p_diagnostics)
{
    if (NULL != p_diagnostics)
    {
        p_diagnostics->unsupported_streams = g_unsupported_streams;
        p_diagnostics->unsupported_sv_asdu = g_unsupported_sv_asdu;
        p_diagnostics->malformed_frames    = g_malformed_frames;
        p_diagnostics->gaps_noted          = g_gaps_noted;
        p_diagnostics->streams_kept        = g_streams_kept;
        p_diagnostics->streams_reset       = g_streams_reset;
    }
}

/*!
 * @brief Copy the aggregated features of the latest scored window.
 *
 * @param[out] p_output   Receives the features.
 * @param[in]  capacity   The number of floats p_output holds.
 * @param[out] p_count    Receives the feature count; may be NULL.
 * @param[out] p_protocol Receives the window protocol; may be NULL.
 *
 * @return True if the features were copied.
 */
bool
analyzer_copy_batch_features (float * p_output, size_t capacity,
                              size_t *              p_count,
                              analyzer_protocol_t * p_protocol)
{
    bool b_copied = false;

    if (NULL != p_count)
    {
        *p_count = g_last_batch_feature_count;
    }

    if (NULL != p_protocol)
    {
        *p_protocol = g_last_batch_protocol;
    }

    if ((NULL != p_output) && (0u != g_last_batch_feature_count)
        && (capacity >= g_last_batch_feature_count))
    {
        memcpy(p_output, g_last_batch_features,
               g_last_batch_feature_count * sizeof(float));
        b_copied = true;
    }

    return (b_copied);
}

/*!
 * @brief Store the metadata, and if wanted the bytes, of the current frame
 *        in a stream's window.
 *
 * @param[out] p_packets   The stream's window metadata.
 * @param[out] p_frames    The stream's waiting frame slots; may be NULL.
 * @param[in]  batch_index The frame's position in the window.
 * @param[in]  p_result    The frame's result.
 * @param[in]  p_identity  The stream identity.
 */
static void
record_batch_packet (analyzer_packet_metadata_t * p_packets, uint8_t * p_frames,
                     size_t batch_index, analyzer_result_t const * p_result,
                     stream_identity_t const * p_identity)
{
    analyzer_packet_metadata_t * p_metadata = NULL;

    if ((NULL != p_packets) && (batch_index < ANALYZER_BATCH_FRAME_COUNT)
        && (NULL != p_result) && (NULL != gp_current_frame)
        && (g_current_frame_length <= ANALYZER_MAXIMUM_FRAME_LENGTH)
        && (NULL != p_identity))
    {
        p_metadata = &p_packets[batch_index];
        memset(p_metadata, 0, sizeof(*p_metadata));
        p_metadata->timestamp_us     = p_result->timestamp_us;
        p_metadata->capture_sequence = g_current_capture_sequence;
        p_metadata->counter_1        = p_result->counter_1;
        p_metadata->counter_2        = p_result->counter_2;

        // The casts are safe: the frame length is at most
        // ANALYZER_MAXIMUM_FRAME_LENGTH and the stream ID at most
        // ANALYZER_STREAM_ID_CAPACITY.
        p_metadata->frame_length     = (uint16_t) g_current_frame_length;
        p_metadata->appid            = p_result->appid;
        p_metadata->protocol         = p_result->protocol;
        p_metadata->stream_key       = p_result->stream_key;
        p_metadata->stream_id_length = (uint8_t) p_identity->stream_id_length;
        memcpy(p_metadata->stream_id, p_identity->stream_id,
               p_identity->stream_id_length);
        memcpy(p_metadata->source_mac, gp_current_frame + MAC_ADDRESS_LENGTH,
               MAC_ADDRESS_LENGTH);
        memcpy(p_metadata->destination_mac, gp_current_frame,
               MAC_ADDRESS_LENGTH);

        if (NULL != p_frames)
        {
#if ANALYZER_STORE_WINDOW_FRAMES
            uint8_t * const p_destination =
                (ANALYZER_NEWEST_FRAME_INDEX == batch_index)
                    ? g_completed_newest_frame
                    : (p_frames
                       + (batch_index * ANALYZER_MAXIMUM_FRAME_LENGTH));

            memcpy(p_destination, gp_current_frame, g_current_frame_length);
#endif
        }
    }
}

/*!
 * @brief Move the last completed window on by the stride, at the start of
 *        the next processing call.
 *
 * @par
 * With a four-frame window and a stride of two, the stream keeps frames 2
 * and 3. Frame 3 lives in the shared completion slot, not past slot 2.
 */
static void
advance_completed_window (void)
{
#if ANALYZER_STORE_WINDOW_FRAMES
    if (NULL != gp_completed_window_frames)
    {
        memmove(gp_completed_window_frames,
                gp_completed_window_frames
                    + (EXPECTED_BATCH_STRIDE * ANALYZER_MAXIMUM_FRAME_LENGTH),
                ANALYZER_MAXIMUM_FRAME_LENGTH);
        memcpy(gp_completed_window_frames + ANALYZER_MAXIMUM_FRAME_LENGTH,
               g_completed_newest_frame, ANALYZER_MAXIMUM_FRAME_LENGTH);
        gp_completed_window_frames = NULL;
    }
#endif
}

/*!
 * @brief Return the larger of two floats.
 *
 * @param[in] left  One value.
 * @param[in] right The other value.
 *
 * @return The larger value.
 */
static float
maximum_float (float left, float right)
{
    return ((left > right) ? left : right);
}

/*!
 * @brief Return the smaller of two floats.
 *
 * @param[in] left  One value.
 * @param[in] right The other value.
 *
 * @return The smaller value.
 */
static float
minimum_float (float left, float right)
{
    return ((left < right) ? left : right);
}

/*!
 * @brief Read a big-endian 16-bit value.
 *
 * @param[in] p_value The two bytes.
 *
 * @return The value.
 */
static uint16_t
read_be16 (uint8_t const * p_value)
{
    // The casts are safe: two bytes always fit in 16 bits.
    return ((uint16_t) (((uint32_t) p_value[0] << BITS_PER_BYTE)
                        | (uint32_t) p_value[1]));
}

/*!
 * @brief Read a BER-encoded unsigned integer of up to 32 bits.
 *
 * @param[in]  p_value  The content octets.
 * @param[in]  length   The number of content octets.
 * @param[out] p_output Receives the value.
 *
 * @return False if the encoding is empty, too long or negative.
 */
static bool
read_ber_uint (uint8_t const * p_value, size_t length, uint32_t * p_output)
{
    size_t   index                 = 0u;
    bool     b_has_sign_protection = false;
    uint32_t parsed                = 0u;

    if ((NULL == p_value) || (NULL == p_output) || (0u == length)
        || (length > BER_UNSIGNED_INTEGER_MAX_OCTETS))
    {
        return (false);
    }

    // A five-octet encoding must start with a 0x00 sign octet.
    b_has_sign_protection = (BER_UNSIGNED_INTEGER_MAX_OCTETS == length);

    if (b_has_sign_protection)
    {
        if (0u != p_value[0])
        {
            return (false);
        }

        ++p_value;
        --length;
    }
    else if (0u != (p_value[0] & BER_TAG_HIGH_BIT_MASK))
    {
        return (false);
    }
    else
    {
        // A positive value without a sign octet.
    }

    for (index = 0u; index < length; ++index)
    {
        parsed = (parsed << BITS_PER_BYTE) | p_value[index];
    }

    *p_output = parsed;

    return (true);
}

/*!
 * @brief Read a one-octet BER boolean.
 *
 * @param[in]  p_value   The content octets.
 * @param[in]  length    The number of content octets.
 * @param[out] pb_output Receives the value.
 *
 * @return False if the encoding is not one octet long.
 */
static bool
read_ber_boolean (uint8_t const * p_value, size_t length, bool * pb_output)
{
    bool b_ok = false;

    if ((NULL != p_value) && (NULL != pb_output) && (1u == length))
    {
        *pb_output = (0u != p_value[0]);
        b_ok       = true;
    }

    return (b_ok);
}

/*!
 * @brief Read one BER tag-length-value element.
 *
 * @param[in]  p_cursor The first octet of the element.
 * @param[in]  p_end    One past the last octet that may be read.
 * @param[out] p_output Receives the element.
 *
 * @return False if the element does not fit before p_end.
 */
static bool
read_tlv (uint8_t const * p_cursor, uint8_t const * p_end,
          analyzer_tlv_t * p_output)
{
    size_t  available    = 0u;
    size_t  length       = 0u;
    uint8_t first_length = 0u;

    if ((NULL == p_cursor) || (NULL == p_end) || (NULL == p_output)
        || (p_end < p_cursor))
    {
        return (false);
    }

    // The cast is safe: p_end is not before p_cursor.
    available = (size_t) (p_end - p_cursor);

    if (available < BER_TLV_HEADER_SIZE)
    {
        return (false);
    }

    p_output->tag = *p_cursor;
    ++p_cursor;
    first_length = *p_cursor;
    ++p_cursor;

    if (0u == (first_length & BER_TAG_HIGH_BIT_MASK))
    {
        length = first_length;
    }
    else
    {
        // The casts are safe: the octet count is seven bits and p_end is not
        // before p_cursor.
        size_t const octets = (size_t) (first_length & BER_LENGTH_OCTET_MASK);
        size_t       index  = 0u;

        if ((0u == octets) || (octets > BER_MAX_LENGTH_OCTETS)
            || ((size_t) (p_end - p_cursor) < octets))
        {
            return (false);
        }

        for (index = 0u; index < octets; ++index)
        {
            if (length > (SIZE_MAX >> BITS_PER_BYTE))
            {
                return (false);
            }

            length = (length << BITS_PER_BYTE) | p_cursor[index];
        }

        p_cursor += octets;
    }

    // The cast is safe: p_end is checked not to be before p_cursor first.
    if ((p_end < p_cursor) || (length > (size_t) (p_end - p_cursor)))
    {
        return (false);
    }

    p_output->p_value = p_cursor;
    p_output->length  = length;
    p_output->p_next  = p_cursor + length;

    return (true);
}

/*!
 * @brief Find the EtherType and payload after up to two VLAN tags.
 *
 * @param[in]  p_frame  The Ethernet frame.
 * @param[in]  length   The frame length.
 * @param[out] p_output Receives the payload.
 *
 * @return False if the frame is too short.
 */
static bool
find_ethernet_payload (uint8_t const * p_frame, size_t length,
                       ethernet_payload_t * p_output)
{
    uint16_t type           = 0u;
    size_t   payload_offset = ETHERNET_HEADER_SIZE;
    size_t   tag_count      = 0u;

    if ((NULL == p_frame) || (NULL == p_output)
        || (length < ETHERNET_HEADER_SIZE))
    {
        return (false);
    }

    type = read_be16(p_frame + ETHERNET_TYPE_FIELD_OFFSET);

    for (tag_count = 0u; (tag_count < MAXIMUM_VLAN_TAGS)
                         && ((ETHERNET_VLAN_8021Q_TYPE == type)
                             || (ETHERNET_VLAN_8021AD_TYPE == type)
                             || (ETHERNET_VLAN_QINQ_TYPE == type));
         ++tag_count)
    {
        if ((payload_offset > length)
            || ((length - payload_offset) < VLAN_TAG_HEADER_SIZE))
        {
            return (false);
        }

        type = read_be16(p_frame + payload_offset + VLAN_TYPE_FIELD_OFFSET);
        payload_offset += VLAN_TAG_HEADER_SIZE;
    }

    p_output->type   = type;
    p_output->p_data = p_frame + payload_offset;
    p_output->length = length - payload_offset;

    return (true);
}

/*!
 * @brief Check the IEC 61850 header of a GOOSE or SV payload and read its
 *        APDU element.
 *
 * @param[in]     p_payload The Ethernet payload; may be NULL.
 * @param[in]     tag       The expected APDU tag.
 * @param[out]    p_apdu    Receives the APDU element.
 * @param[in,out] p_reasons Gets a structure finding if bytes follow the APDU.
 *
 * @return False if the header is malformed or the tag is wrong.
 */
static bool
read_apdu (ethernet_payload_t const * p_payload, uint8_t tag,
           analyzer_tlv_t * p_apdu, uint32_t * p_reasons)
{
    uint16_t        apdu_length = 0u;
    uint8_t const * p_end       = NULL;
    bool            b_ok        = false;

    if ((NULL != p_payload)
        && (p_payload->length >= IEC61850_APDU_MINIMUM_LENGTH))
    {
        apdu_length =
            read_be16(p_payload->p_data + IEC61850_APDU_LENGTH_OFFSET);

        if ((apdu_length >= IEC61850_APDU_MINIMUM_LENGTH)
            && (apdu_length <= p_payload->length))
        {
            p_end = p_payload->p_data + apdu_length;
            b_ok  = read_tlv(p_payload->p_data + IEC61850_APDU_OFFSET, p_end,
                             p_apdu)
                 && (tag == p_apdu->tag);
        }
    }

    if (b_ok && (p_apdu->p_next != p_end))
    {
        *p_reasons |= IEC_RULE_STRUCTURE;
    }

    return (b_ok);
}

/*!
 * @brief Give the "seen" bit of a GOOSE field tag.
 *
 * @param[in] tag The field tag.
 *
 * @return The bit, or 0 for an unknown tag.
 */
static uint32_t
goose_field_bit (uint8_t tag)
{
    uint32_t bit = 0u;

    if (GOOSE_TAG_ALL_DATA == tag)
    {
        bit = GOOSE_ALL_DATA_BIT;
    }
    else if ((tag >= CONTEXT_TAG_BASE) && (tag <= GOOSE_TAG_NUMBER_OF_ENTRIES))
    {
        bit = 1u << (tag - CONTEXT_TAG_BASE);
    }
    else
    {
        // An unknown tag has no bit.
    }

    return (bit);
}

/*!
 * @brief Store one GOOSE PDU field.
 *
 * @param[in]  p_field        The field element.
 * @param[out] p_fields       The PDU fields.
 * @param[out] pb_have_ref    Set when gocbRef is found.
 * @param[out] pb_have_st_num Set when stNum is found.
 * @param[out] pb_have_sq_num Set when sqNum is found.
 *
 * @return False if a numeric or boolean field is badly encoded.
 */
static bool
parse_goose_field (analyzer_tlv_t const * p_field, goose_fields_t * p_fields,
                   bool * pb_have_ref, bool * pb_have_st_num,
                   bool * pb_have_sq_num)
{
    bool b_ok = true;

    switch (p_field->tag)
    {
        case GOOSE_TAG_GOCB_REF:
            p_fields->p_gocb_ref      = p_field->p_value;
            p_fields->gocb_ref_length = p_field->length;
            *pb_have_ref              = true;
            break;

        case GOOSE_TAG_TIME_ALLOWED_TO_LIVE:
            b_ok = read_ber_uint(p_field->p_value, p_field->length,
                                 &p_fields->ttl_ms);
            break;

        case GOOSE_TAG_DATASET:
            p_fields->p_dataset      = p_field->p_value;
            p_fields->dataset_length = p_field->length;
            break;

        case GOOSE_TAG_GO_ID:
            p_fields->p_go_id      = p_field->p_value;
            p_fields->go_id_length = p_field->length;
            break;

        case GOOSE_TAG_TIMESTAMP:
            p_fields->p_timestamp      = p_field->p_value;
            p_fields->timestamp_length = p_field->length;
            break;

        case GOOSE_TAG_STATE_NUMBER:
            b_ok = read_ber_uint(p_field->p_value, p_field->length,
                                 &p_fields->st_num);

            if (b_ok)
            {
                *pb_have_st_num = true;
            }
            break;

        case GOOSE_TAG_SEQUENCE_NUMBER:
            b_ok = read_ber_uint(p_field->p_value, p_field->length,
                                 &p_fields->sq_num);

            if (b_ok)
            {
                *pb_have_sq_num = true;
            }
            break;

        case GOOSE_TAG_SIMULATION:
            b_ok = read_ber_boolean(p_field->p_value, p_field->length,
                                    &p_fields->b_simulation);
            break;

        case GOOSE_TAG_CONFIGURATION_REVISION:
            b_ok = read_ber_uint(p_field->p_value, p_field->length,
                                 &p_fields->conf_rev);
            break;

        case GOOSE_TAG_NEEDS_COMMISSIONING:
            b_ok = read_ber_boolean(p_field->p_value, p_field->length,
                                    &p_fields->b_nds_com);
            break;

        case GOOSE_TAG_NUMBER_OF_ENTRIES:
            b_ok = read_ber_uint(p_field->p_value, p_field->length,
                                 &p_fields->num_entries);
            break;

        case GOOSE_TAG_ALL_DATA:
            p_fields->p_all_data      = p_field->p_value;
            p_fields->all_data_length = p_field->length;
            break;

        default:
            // Unknown fields are flagged by the caller.
            break;
    }

    return (b_ok);
}

/*!
 * @brief Count the data elements in a GOOSE allData field.
 *
 * @param[in,out] p_fields The PDU fields; a structure finding is added if an
 *                         element is badly encoded.
 *
 * @return The number of well-formed elements.
 */
static size_t
count_data_entries (goose_fields_t * p_fields)
{
    size_t entries = 0u;

    if (NULL != p_fields->p_all_data)
    {
        uint8_t const *       p_item  = p_fields->p_all_data;
        uint8_t const * const p_limit = p_item + p_fields->all_data_length;
        bool                  b_ok    = true;

        while (b_ok && (p_item < p_limit))
        {
            analyzer_tlv_t value = {0};

            b_ok = read_tlv(p_item, p_limit, &value);

            if (b_ok)
            {
                entries++;
                p_item = value.p_next;
            }
            else
            {
                p_fields->rule_reasons |= IEC_RULE_STRUCTURE;
            }
        }
    }

    return (entries);
}

/*!
 * @brief Parse a GOOSE APDU.
 *
 * @par
 * Fails only if the frame cannot be read safely or misses gocbRef, stNum or
 * sqNum. Other problems are reported as rule reasons.
 *
 * @param[in]  p_payload The Ethernet payload.
 * @param[out] p_output  Receives the PDU fields.
 *
 * @return True if the PDU was parsed.
 */
static bool
parse_goose (ethernet_payload_t const * p_payload, goose_fields_t * p_output)
{
    analyzer_tlv_t  pdu           = {0};
    goose_fields_t  fields        = {0};
    bool            b_have_ref    = false;
    bool            b_have_st_num = false;
    bool            b_have_sq_num = false;
    uint8_t const * p_cursor      = NULL;
    uint8_t const * p_pdu_end     = NULL;
    uint32_t        seen          = 0u;

    if ((NULL == p_output)
        || (!read_apdu(p_payload, GOOSE_APDU_TAG, &pdu, &fields.rule_reasons)))
    {
        return (false);
    }

    fields.appid = read_be16(p_payload->p_data);

    p_cursor  = pdu.p_value;
    p_pdu_end = pdu.p_value + pdu.length;

    while (p_cursor < p_pdu_end)
    {
        analyzer_tlv_t field = {0};
        uint32_t       bit   = 0u;

        if (!read_tlv(p_cursor, p_pdu_end, &field))
        {
            return (false);
        }

        bit = goose_field_bit(field.tag);

        if (0u == bit)
        {
            fields.rule_reasons |= IEC_RULE_UNSUPPORTED;
        }

        if (0u != (seen & bit))
        {
            fields.rule_reasons |= IEC_RULE_STRUCTURE;
        }

        seen |= bit;

        if (!parse_goose_field(&field, &fields, &b_have_ref, &b_have_st_num,
                               &b_have_sq_num))
        {
            return (false);
        }

        p_cursor = field.p_next;
    }

    if (!b_have_ref || !b_have_st_num || !b_have_sq_num)
    {
        return (false);
    }

    if ((GOOSE_REQUIRED_FIELDS != (seen & GOOSE_REQUIRED_FIELDS))
        || (ANALYZER_GOOSE_TIMESTAMP_BYTES != fields.timestamp_length))
    {
        fields.rule_reasons |= IEC_RULE_STRUCTURE;
    }

    if (count_data_entries(&fields) != fields.num_entries)
    {
        fields.rule_reasons |= IEC_RULE_STRUCTURE;
    }

    *p_output = fields;

    return (true);
}

/*!
 * @brief Parse one SV ASDU.
 *
 * @param[in]  p_raw  The ASDU sequence element.
 * @param[out] p_asdu Receives the ASDU fields; its rule_reasons gets any
 *                    findings.
 *
 * @return True if svID, smpCnt and seqData were found.
 */
static bool
parse_sv_asdu (analyzer_tlv_t const * p_raw, sv_asdu_t * p_asdu)
{
    bool                  b_have_id          = false;
    bool                  b_have_count_field = false;
    uint8_t const *       p_field_cursor     = p_raw->p_value;
    uint8_t const * const p_raw_end          = p_raw->p_value + p_raw->length;
    uint32_t              seen               = 0u;

    if (BER_SEQUENCE_TAG != p_raw->tag)
    {
        return (false);
    }

    while (p_field_cursor < p_raw_end)
    {
        analyzer_tlv_t field = {0};
        uint32_t       bit   = 0u;

        if (!read_tlv(p_field_cursor, p_raw_end, &field))
        {
            return (false);
        }

        if ((field.tag >= CONTEXT_TAG_BASE) && (field.tag <= SV_TAG_LAST_KNOWN))
        {
            bit = 1u << (field.tag - CONTEXT_TAG_BASE);
        }

        if (0u == bit)
        {
            p_asdu->rule_reasons |= IEC_RULE_UNSUPPORTED;
        }

        if (0u != (seen & bit))
        {
            p_asdu->rule_reasons |= IEC_RULE_STRUCTURE;
        }

        seen |= bit;

        if (((SV_TAG_SAMPLE_COUNT == field.tag)
             && (SV_SAMPLE_COUNT_BYTES != field.length))
            || ((SV_TAG_CONFIGURATION_REVISION == field.tag)
                && (SV_CONFIGURATION_BYTES != field.length))
            || ((SV_TAG_SAMPLE_SYNCHRONIZATION == field.tag)
                && (SV_SYNCHRONIZATION_BYTES != field.length)))
        {
            p_asdu->rule_reasons |= IEC_RULE_STRUCTURE;
        }

        if (SV_TAG_IDENTIFIER == field.tag)
        {
            p_asdu->p_sv_id      = field.p_value;
            p_asdu->sv_id_length = field.length;
            b_have_id            = true;
        }
        else if (SV_TAG_SAMPLE_COUNT == field.tag)
        {
            if (!read_ber_uint(field.p_value, field.length, &p_asdu->smp_cnt))
            {
                return (false);
            }

            b_have_count_field = true;
        }
        else if (SV_TAG_CONFIGURATION_REVISION == field.tag)
        {
            if (!read_ber_uint(field.p_value, field.length, &p_asdu->conf_rev))
            {
                return (false);
            }
        }
        else if (SV_TAG_SAMPLE_SYNCHRONIZATION == field.tag)
        {
            if (!read_ber_uint(field.p_value, field.length, &p_asdu->smp_synch))
            {
                return (false);
            }
        }
        else if (SV_TAG_SEQUENCE_DATA == field.tag)
        {
            p_asdu->p_seq_data      = field.p_value;
            p_asdu->seq_data_length = field.length;
        }
        else
        {
            // Other fields are not used.
        }

        p_field_cursor = field.p_next;
    }

    if (SV_REQUIRED_FIELDS != (seen & SV_REQUIRED_FIELDS))
    {
        p_asdu->rule_reasons |= IEC_RULE_STRUCTURE;
    }

    return (b_have_id && b_have_count_field && (NULL != p_asdu->p_seq_data));
}

/*!
 * @brief Parse the ASDUs of an SV PDU.
 *
 * @param[in]     p_sequence      The ASDU sequence contents.
 * @param[in]     sequence_length The length of the sequence contents.
 * @param[in,out] p_fields        The PDU fields; receives the ASDUs.
 *
 * @return True if every ASDU was parsed and the count matches noASDU.
 */
static bool
parse_sv_asdus (uint8_t const * p_sequence, size_t sequence_length,
                sv_fields_t * p_fields)
{
    uint8_t const *       p_cursor = p_sequence;
    uint8_t const * const p_end    = p_sequence + sequence_length;

    while (p_cursor < p_end)
    {
        analyzer_tlv_t raw = {0};

        if ((!read_tlv(p_cursor, p_end, &raw)) || (BER_SEQUENCE_TAG != raw.tag)
            || (p_fields->asdu_count >= MAXIMUM_ASDUS))
        {
            return (false);
        }

        if (!parse_sv_asdu(&raw, &p_fields->asdus[p_fields->asdu_count]))
        {
            return (false);
        }

        p_fields->rule_reasons |=
            p_fields->asdus[p_fields->asdu_count].rule_reasons;
        ++p_fields->asdu_count;
        p_cursor = raw.p_next;
    }

    return (p_fields->asdu_count == p_fields->no_asdu);
}

/*!
 * @brief Parse an SV APDU.
 *
 * @par
 * Sets gb_unsupported_parse if the frame is valid but has more ASDUs than
 * the analyzer supports.
 *
 * @param[in]  p_payload The Ethernet payload.
 * @param[out] p_output  Receives the PDU fields.
 *
 * @return True if the PDU was parsed.
 */
static bool
parse_sv (ethernet_payload_t const * p_payload, sv_fields_t * p_output)
{
    analyzer_tlv_t  apdu            = {0};
    sv_fields_t     fields          = {0};
    bool            b_have_count    = false;
    uint8_t const * p_sequence      = NULL;
    size_t          sequence_length = 0u;
    uint8_t const * p_cursor        = NULL;
    uint8_t const * p_apdu_end      = NULL;
    uint32_t        seen            = 0u;

    gb_unsupported_parse = false;

    if ((NULL == p_output)
        || (!read_apdu(p_payload, SV_APDU_TAG, &apdu, &fields.rule_reasons)))
    {
        return (false);
    }

    fields.appid = read_be16(p_payload->p_data);

    p_cursor   = apdu.p_value;
    p_apdu_end = apdu.p_value + apdu.length;

    while (p_cursor < p_apdu_end)
    {
        analyzer_tlv_t field = {0};

        if (!read_tlv(p_cursor, p_apdu_end, &field))
        {
            return (false);
        }

        if (SV_TAG_COUNT == field.tag)
        {
            if (0u != (seen & SV_SEEN_COUNT))
            {
                fields.rule_reasons |= IEC_RULE_STRUCTURE;
            }

            seen |= SV_SEEN_COUNT;

            if (!read_ber_uint(field.p_value, field.length, &fields.no_asdu))
            {
                return (false);
            }

            b_have_count = true;
        }
        else if (SV_SEQUENCE_TAG == field.tag)
        {
            if (0u != (seen & SV_SEEN_SEQUENCE))
            {
                fields.rule_reasons |= IEC_RULE_STRUCTURE;
            }

            seen |= SV_SEEN_SEQUENCE;
            p_sequence      = field.p_value;
            sequence_length = field.length;
        }
        else
        {
            fields.rule_reasons |= IEC_RULE_UNSUPPORTED;
        }

        p_cursor = field.p_next;
    }

    if (!b_have_count || (0u == fields.no_asdu)
        || (fields.no_asdu > MAXIMUM_ENCODED_ASDU_COUNT)
        || (NULL == p_sequence))
    {
        return (false);
    }

    if (fields.no_asdu > MAXIMUM_ASDUS)
    {
        ++g_unsupported_sv_asdu;
        gb_unsupported_parse = true;
        return (false);
    }

    if (!parse_sv_asdus(p_sequence, sequence_length, &fields))
    {
        return (false);
    }

    *p_output = fields;

    return (true);
}

/*!
 * @brief Hash a stream identity with 32-bit FNV-1a.
 *
 * @param[in] appid            The APPID.
 * @param[in] p_stream_id      The gocbRef or svID bytes.
 * @param[in] stream_id_length The ID length.
 * @param[in] p_destination    The destination MAC address.
 *
 * @return The stream key.
 */
static uint32_t
batch_hash (uint16_t appid, uint8_t const * p_stream_id,
            size_t stream_id_length, uint8_t const * p_destination)
{
    uint32_t hash  = FNV_OFFSET_BASIS;
    size_t   index = 0u;

    for (index = 0u; index < MAC_ADDRESS_LENGTH; ++index)
    {
        hash = (hash ^ p_destination[index]) * FNV_PRIME;
    }

    // The casts are safe: they select one byte of the APPID.
    hash = (hash ^ (uint8_t) (appid >> BITS_PER_BYTE)) * FNV_PRIME;
    hash = (hash ^ (uint8_t) (appid & BYTE_MASK)) * FNV_PRIME;

    for (index = 0u; index < stream_id_length; ++index)
    {
        hash = (hash ^ p_stream_id[index]) * FNV_PRIME;
    }

    return (hash);
}

/*!
 * @brief Compare a stored stream identity with a frame's identity.
 *
 * @param[in] p_identity       The stored identity.
 * @param[in] appid            The frame APPID.
 * @param[in] p_stream_id      The frame gocbRef or svID.
 * @param[in] stream_id_length The ID length.
 * @param[in] p_destination    The frame destination MAC address.
 *
 * @return True if they are the same stream.
 */
static bool
identity_matches (stream_identity_t const * p_identity, uint16_t appid,
                  uint8_t const * p_stream_id, size_t stream_id_length,
                  uint8_t const * p_destination)
{
    return ((p_identity->appid == appid)
            && (p_identity->stream_id_length == stream_id_length)
            && (0
                == memcmp(p_identity->destination_mac, p_destination,
                          MAC_ADDRESS_LENGTH))
            && ((0u == stream_id_length)
                || (0
                    == memcmp(p_identity->stream_id, p_stream_id,
                              stream_id_length))));
}

/*!
 * @brief Find a GOOSE stream's state, or claim a free one.
 *
 * @param[in] appid            The APPID.
 * @param[in] p_stream_id      The gocbRef.
 * @param[in] stream_id_length The gocbRef length.
 * @param[in] p_destination    The destination MAC address.
 * @param[in] key              The stream key for a new state.
 *
 * @return The state, or NULL if the ID is too long or every slot is taken.
 */
static goose_state_t *
goose_state_for (uint16_t appid, uint8_t const * p_stream_id,
                 size_t stream_id_length, uint8_t const * p_destination,
                 uint32_t key)
{
    goose_state_t * p_free_state = NULL;
    size_t          index        = 0u;

    if (NULL == p_stream_id)
    {
        return (NULL);
    }

    if (stream_id_length > MAXIMUM_STREAM_ID_LENGTH)
    {
        ++g_unsupported_streams;
        return (NULL);
    }

    for (index = 0u; index < MAXIMUM_GOOSE_STREAMS; ++index)
    {
        goose_state_t * const p_state = &g_goose_states[index];

        if (p_state->b_used
            && identity_matches(&p_state->identity, appid, p_stream_id,
                                stream_id_length, p_destination))
        {
            return (p_state);
        }

        if (!p_state->b_used && (NULL == p_free_state))
        {
            p_free_state = p_state;
        }
    }

    if (NULL == p_free_state)
    {
        ++g_unsupported_streams;
        return (NULL);
    }

    memset(p_free_state, 0, sizeof(*p_free_state));
    p_free_state->b_used                    = true;
    p_free_state->key                       = key;
    p_free_state->identity.appid            = appid;
    p_free_state->identity.stream_id_length = stream_id_length;
    memcpy(p_free_state->identity.destination_mac, p_destination,
           MAC_ADDRESS_LENGTH);

    if (0u != stream_id_length)
    {
        memcpy(p_free_state->identity.stream_id, p_stream_id, stream_id_length);
    }

    return (p_free_state);
}

/*!
 * @brief Find an SV stream's state, or claim a free one.
 *
 * @param[in] appid            The APPID.
 * @param[in] p_stream_id      The svID.
 * @param[in] stream_id_length The svID length.
 * @param[in] p_destination    The destination MAC address.
 * @param[in] key              The stream key for a new state.
 *
 * @return The state, or NULL if the ID is too long or every slot is taken.
 */
static sv_state_t *
sv_state_for (uint16_t appid, uint8_t const * p_stream_id,
              size_t stream_id_length, uint8_t const * p_destination,
              uint32_t key)
{
    sv_state_t * p_free_state = NULL;
    size_t       index        = 0u;

    if (NULL == p_stream_id)
    {
        return (NULL);
    }

    if (stream_id_length > MAXIMUM_STREAM_ID_LENGTH)
    {
        ++g_unsupported_streams;
        return (NULL);
    }

    for (index = 0u; index < ANALYZER_MAXIMUM_SV_STREAMS; ++index)
    {
        sv_state_t * const p_state = &g_sv_states[index];

        if (p_state->b_used
            && identity_matches(&p_state->identity, appid, p_stream_id,
                                stream_id_length, p_destination))
        {
            return (p_state);
        }

        if (!p_state->b_used && (NULL == p_free_state))
        {
            p_free_state = p_state;
        }
    }

    if (NULL == p_free_state)
    {
        ++g_unsupported_streams;
        return (NULL);
    }

    memset(p_free_state, 0, sizeof(*p_free_state));
    p_free_state->b_used                    = true;
    p_free_state->key                       = key;
    p_free_state->identity.appid            = appid;
    p_free_state->identity.stream_id_length = stream_id_length;
    memcpy(p_free_state->identity.destination_mac, p_destination,
           MAC_ADDRESS_LENGTH);

    if (0u != stream_id_length)
    {
        memcpy(p_free_state->identity.stream_id, p_stream_id, stream_id_length);
    }

    return (p_free_state);
}

/*!
 * @brief Select the target-th smallest value of g_median_scratch.
 *
 * @par
 * Quickselect with Hoare partitioning; reorders g_median_scratch.
 *
 * @param[in] count  The number of values, at least 1.
 * @param[in] target The index wanted in sorted order.
 *
 * @return The selected value.
 */
static float
select_median_upper (size_t count, size_t target)
{
    size_t left    = 0u;
    size_t right   = count - 1u;
    bool   b_stuck = false;

    while (!b_stuck && (left < right))
    {
        float const pivot =
            g_median_scratch[left
                             + ((right - left) / INTEGER_MIDPOINT_DIVISOR)];
        size_t lower = left;
        size_t upper = right;

        while (lower <= upper)
        {
            while ((lower <= right) && (g_median_scratch[lower] < pivot))
            {
                ++lower;
            }

            while (g_median_scratch[upper] > pivot)
            {
                if (0u == upper)
                {
                    break;
                }

                --upper;
            }

            if (lower <= upper)
            {
                float const temporary   = g_median_scratch[lower];
                g_median_scratch[lower] = g_median_scratch[upper];
                g_median_scratch[upper] = temporary;
                ++lower;

                if (0u == upper)
                {
                    break;
                }

                --upper;
            }
        }

        if (target <= upper)
        {
            right = upper;
        }
        else if (target >= lower)
        {
            left = lower;
        }
        else
        {
            b_stuck = true;
        }
    }

    return (g_median_scratch[target]);
}

/*!
 * @brief Return the median of up to PICO_ML_BATCH_WAVE_HISTORY_SAMPLES
 *        values.
 *
 * @param[in] p_values The values; not changed.
 * @param[in] count    The number of values; larger counts are clipped.
 *
 * @return The median, or 0 if there are no values.
 */
static float
batch_median (float const * p_values, size_t count)
{
    float median = 0.0f;

    if (count > PICO_ML_BATCH_WAVE_HISTORY_SAMPLES)
    {
        count = PICO_ML_BATCH_WAVE_HISTORY_SAMPLES;
    }

    if ((0u != count) && (NULL != p_values))
    {
        memcpy(g_median_scratch, p_values, count * sizeof(float));

        if (0u != (count & 1u))
        {
            median =
                select_median_upper(count, count / INTEGER_MIDPOINT_DIVISOR);
        }
        else
        {
            // After selecting the upper middle, every value below it is no
            // larger, so the lower middle is their maximum.
            size_t const middle = count / INTEGER_MIDPOINT_DIVISOR;
            float const  upper  = select_median_upper(count, middle);
            float        lower  = g_median_scratch[0];
            size_t       index  = 0u;

            for (index = 1u; index < middle; ++index)
            {
                lower = maximum_float(lower, g_median_scratch[index]);
            }

            median = (lower + upper) * FLOAT_MIDPOINT_RATIO;
        }
    }

    return (median);
}

/*!
 * @brief Return the median of the newest values of a ring buffer.
 *
 * @param[in] p_values The ring buffer.
 * @param[in] capacity The ring size, at most
 *                     PICO_ML_BATCH_TIMING_HISTORY_FRAMES.
 * @param[in] count    The number of stored values.
 * @param[in] next     The next write index.
 *
 * @return The median, or 0 if the arguments are inconsistent.
 */
static float
ring_median (float const * p_values, size_t capacity, size_t count, size_t next)
{
    float  median = 0.0f;
    size_t index  = 0u;

    if ((count <= capacity)
        && (capacity <= PICO_ML_BATCH_TIMING_HISTORY_FRAMES))
    {
        for (index = 0u; index < count; ++index)
        {
            g_timing_scratch[index] =
                p_values[((next + capacity) - count + index) % capacity];
        }

        median = batch_median(g_timing_scratch, count);
    }

    return (median);
}

/*!
 * @brief Add a frame interval to a ring buffer.
 *
 * @param[out]    p_values The ring buffer.
 * @param[in]     capacity The ring size.
 * @param[in,out] p_count  The number of stored values.
 * @param[in,out] p_next   The next write index.
 * @param[in]     interval The interval in seconds.
 */
static void
push_interval (float * p_values, size_t capacity, size_t * p_count,
               size_t * p_next, float interval)
{
    if ((NULL != p_values) && (NULL != p_count) && (NULL != p_next)
        && (0u != capacity) && (*p_next < capacity))
    {
        p_values[*p_next] = interval;
        *p_next           = (*p_next + 1u) % capacity;

        if (*p_count < capacity)
        {
            ++(*p_count);
        }
    }
}

/*!
 * @brief Publish a completed window's metadata and frames.
 *
 * @param[in]  p_packets    The window metadata.
 * @param[in]  p_raw_frames The stream's waiting frame slots; may be NULL.
 * @param[out] p_result     Receives the window metadata.
 */
static void
save_completed_batch_snapshot (analyzer_packet_metadata_t * p_packets,
                               uint8_t *                    p_raw_frames,
                               analyzer_result_t *          p_result)
{
    size_t index = 0u;

    p_result->batch_frame_count = ANALYZER_BATCH_FRAME_COUNT;
#if ANALYZER_STORE_WINDOW_FRAMES
    gp_completed_window_frames = p_raw_frames;
#else
    // The cast marks a parameter only this configuration does not use.
    (void) p_raw_frames;
#endif

    for (index = 0u; index < ANALYZER_BATCH_FRAME_COUNT; ++index)
    {
        p_result->batch_packets[index] = p_packets[index];
        g_last_batch_packets[index]    = p_packets[index];
    }

#if !ANALYZER_STORE_WINDOW_FRAMES
    if ((NULL != gp_current_frame)
        && (g_current_frame_length <= ANALYZER_MAXIMUM_FRAME_LENGTH))
    {
        memcpy(g_last_newest_frame, gp_current_frame, g_current_frame_length);
    }
#endif
}

/*!
 * @brief Turn a window of feature rows into the model input.
 *
 * @par
 * Each feature gives four model inputs: the window mean, maximum, newest
 * value and population standard deviation.
 *
 * @param[in]  p_batch       The window rows.
 * @param[in]  feature_count The features per row.
 * @param[out] p_output      Receives feature_count * 4 model inputs.
 */
static void
aggregate_batch (float const * p_batch, size_t feature_count, float * p_output)
{
    size_t feature     = 0u;
    size_t frame_index = 0u;

    for (feature = 0u; feature < feature_count; ++feature)
    {
        float        sum               = 0.0f;
        float        maximum           = p_batch[feature];
        float        squared_delta_sum = 0.0f;
        size_t const base              = feature * BATCH_FEATURES_PER_METRIC;

        for (frame_index = 0u; frame_index < PICO_ML_BATCH_SIZE_FRAMES;
             ++frame_index)
        {
            float const value =
                p_batch[(frame_index * feature_count) + feature];
            sum += value;
            maximum = maximum_float(maximum, value);
        }

        // The cast is safe: the window size is a small constant.
        p_output[base + METRIC_MEAN] = sum / (float) PICO_ML_BATCH_SIZE_FRAMES;
        p_output[base + METRIC_MAXIMUM] = maximum;
        p_output[base + METRIC_LAST] =
            p_batch[((PICO_ML_BATCH_SIZE_FRAMES - 1u) * feature_count)
                    + feature];

        for (frame_index = 0u; frame_index < PICO_ML_BATCH_SIZE_FRAMES;
             ++frame_index)
        {
            float const delta = p_batch[(frame_index * feature_count) + feature]
                              - p_output[base + METRIC_MEAN];
            squared_delta_sum += delta * delta;
        }

        // The cast is safe: the window size is a small constant.
        p_output[base + METRIC_STANDARD_DEVIATION] =
            sqrtf(squared_delta_sum / (float) PICO_ML_BATCH_SIZE_FRAMES);
    }
}

/*!
 * @brief Move a stream's window on by the stride.
 *
 * @par
 * The raw frame bytes move at the next processing call, so all four frames
 * of the completed window stay available until then.
 *
 * @param[in,out] p_batch       The window rows.
 * @param[in]     feature_count The features per row.
 * @param[in,out] p_batch_count The number of rows in the window.
 * @param[in,out] p_packets     The window metadata.
 * @param[in,out] p_batch_rules The window rule reasons.
 */
static void
advance_batch (float * p_batch, size_t feature_count, size_t * p_batch_count,
               analyzer_packet_metadata_t * p_packets, uint32_t * p_batch_rules)
{
    size_t frame_index = 0u;

    *p_batch_count -= PICO_ML_BATCH_STRIDE_FRAMES;

    for (frame_index = 0u; frame_index < *p_batch_count; ++frame_index)
    {
        memmove(
            p_batch + (frame_index * feature_count),
            p_batch
                + ((frame_index + PICO_ML_BATCH_STRIDE_FRAMES) * feature_count),
            feature_count * sizeof(float));
    }

    for (frame_index = 0u; frame_index < *p_batch_count; ++frame_index)
    {
        memmove(p_packets + frame_index,
                p_packets + frame_index + PICO_ML_BATCH_STRIDE_FRAMES,
                sizeof(*p_packets));
        p_batch_rules[frame_index] =
            p_batch_rules[frame_index + PICO_ML_BATCH_STRIDE_FRAMES];
    }
}

/*!
 * @brief Add a feature row to a stream's window and score full windows.
 *
 * @par
 * Every frame still updates the histories and every window advances. With
 * gating on, only the aggregation and model can be skipped, and a skipped
 * window is never treated as benign.
 *
 * @param[in,out] p_batch           The window rows.
 * @param[in]     feature_count     The features per row.
 * @param[in,out] p_batch_count     The number of rows in the window.
 * @param[in]     p_frame           The new row.
 * @param[out]    p_result          Receives the window result.
 * @param[in,out] p_previous_label  The stream's previous label.
 * @param[in,out] pb_has_prediction Whether the stream has been scored.
 * @param[in]     threshold         The malicious probability threshold.
 * @param[in]     p_predict         The model.
 * @param[in]     output_count      The number of model inputs.
 * @param[in,out] p_packets         The window metadata.
 * @param[in]     p_raw_frames      The waiting frame slots; may be NULL.
 * @param[in]     rule_profile      The stream's rule profile.
 * @param[in,out] p_batch_rules     The window rule reasons.
 */
static void
predict_batch (float * p_batch, size_t feature_count, size_t * p_batch_count,
               float const * p_frame, analyzer_result_t * p_result,
               uint8_t * p_previous_label, bool * pb_has_prediction,
               float threshold, batch_predictor_t p_predict,
               size_t output_count, analyzer_packet_metadata_t * p_packets,
               uint8_t * p_raw_frames, uint32_t rule_profile,
               uint32_t * p_batch_rules)
{
    float    output[SV_BATCH_FEATURE_COUNT] = {0.0f};
    uint32_t window_reasons                 = 0u;
    size_t   frame_index                    = 0u;

    if ((NULL == p_batch) || (NULL == p_batch_count) || (NULL == p_frame)
        || (NULL == p_result) || (NULL == p_previous_label)
        || (NULL == pb_has_prediction) || (NULL == p_predict)
        || (0u == feature_count) || (NULL == p_packets)
        || (feature_count > SV_FEATURE_COUNT)
        || (*p_batch_count >= PICO_ML_BATCH_SIZE_FRAMES))
    {
        return;
    }

    memcpy(p_batch + (*p_batch_count * feature_count), p_frame,
           feature_count * sizeof(float));
    p_batch_rules[*p_batch_count] = iec_rules_latest_reasons();
    ++(*p_batch_count);

    if (*p_batch_count < PICO_ML_BATCH_SIZE_FRAMES)
    {
        // The cast is safe: fewer than four frames remain.
        p_result->warmup_remaining =
            (uint8_t) (PICO_ML_BATCH_SIZE_FRAMES - *p_batch_count);
        return;
    }

    if ((output_count > SV_BATCH_FEATURE_COUNT)
        || (output_count != (feature_count * BATCH_FEATURES_PER_METRIC)))
    {
        *p_batch_count = 0u;
        return;
    }

    p_result->window_ready = true;

    for (frame_index = 0u; frame_index < ANALYZER_BATCH_FRAME_COUNT;
         ++frame_index)
    {
        window_reasons |= p_batch_rules[frame_index];
    }

    p_result->rule_reasons = window_reasons;

    if (!iec_rules_window_required(rule_profile, p_result->timestamp_us,
                                   window_reasons))
    {
        p_result->inference_skipped = true;
        g_last_batch_feature_count  = 0u;
        save_completed_batch_snapshot(p_packets, p_raw_frames, p_result);
    }
    else
    {
        float   probability = 0.0f;
        uint8_t label       = 0u;

        aggregate_batch(p_batch, feature_count, output);
        probability = p_predict(output);
        label       = (probability >= threshold) ? 1u : 0u;
        memcpy(g_last_batch_features, output, output_count * sizeof(float));
        g_last_batch_feature_count    = output_count;
        g_last_batch_protocol         = p_result->protocol;
        p_result->prediction_ready    = true;
        p_result->primary_probability = probability;
        p_result->primary_label       = label;
        p_result->label_changed =
            (!*pb_has_prediction) || (label != *p_previous_label);
        save_completed_batch_snapshot(p_packets, p_raw_frames, p_result);
        *pb_has_prediction = true;
        *p_previous_label  = label;

        // A non-finite score counts as malicious for the rules.
        iec_rules_model_result(rule_profile,
                               (0u != label) || (!isfinite(probability)));
    }

    advance_batch(p_batch, feature_count, p_batch_count, p_packets,
                  p_batch_rules);
}

/*!
 * @brief Copy bytes as a printable C string, replacing other characters
 *        with '.'.
 *
 * @param[out] p_output     The string.
 * @param[in]  capacity     The string buffer size.
 * @param[in]  p_input      The bytes; may be NULL.
 * @param[in]  input_length The number of bytes.
 */
static void
copy_printable (char * p_output, size_t capacity, uint8_t const * p_input,
                size_t input_length)
{
    size_t copy_length = 0u;
    size_t index       = 0u;

    if ((NULL != p_output) && (0u != capacity))
    {
        copy_length = (NULL == p_input) ? 0u : input_length;

        if (copy_length >= capacity)
        {
            copy_length = capacity - 1u;
        }

        for (index = 0u; index < copy_length; ++index)
        {
            // The cast is safe: the byte is printable ASCII.
            p_output[index] = ((p_input[index] >= ASCII_PRINTABLE_MINIMUM)
                               && (p_input[index] < ASCII_PRINTABLE_MAXIMUM))
                                ? (char) p_input[index]
                                : '.';
        }

        p_output[copy_length] = '\0';
    }
}

/*!
 * @brief Add a sample to a wave history ring buffer.
 *
 * @param[out]    p_values The ring buffer.
 * @param[in,out] p_count  The number of stored samples.
 * @param[in,out] p_next   The next write index.
 * @param[in]     value    The sample.
 */
static void
wave_push (float * p_values, uint16_t * p_count, uint16_t * p_next, float value)
{
    if ((NULL != p_values) && (NULL != p_count) && (NULL != p_next)
        && (*p_next < PICO_ML_BATCH_WAVE_HISTORY_SAMPLES))
    {
        p_values[*p_next] = value;

        // The cast is safe: the index is below the history size.
        *p_next =
            (uint16_t) ((*p_next + 1u) % PICO_ML_BATCH_WAVE_HISTORY_SAMPLES);

        if (*p_count < PICO_ML_BATCH_WAVE_HISTORY_SAMPLES)
        {
            ++(*p_count);
        }
    }
}

/*!
 * @brief Read the bits of a big-endian 32-bit float.
 *
 * @param[in] p_value The four bytes.
 *
 * @return The bits.
 */
static uint32_t
read_be32_float_bits (uint8_t const * p_value)
{
    // The casts widen each byte before it is shifted.
    return (((uint32_t) p_value[0] << BE32_BYTE_0_SHIFT)
            | ((uint32_t) p_value[1] << BE32_BYTE_1_SHIFT)
            | ((uint32_t) p_value[2] << BE32_BYTE_2_SHIFT)
            | (uint32_t) p_value[3]);
}

/*!
 * @brief Reinterpret 32 bits as a float.
 *
 * @param[in] bits The bits.
 *
 * @return The float.
 */
static float
float_from_bits (uint32_t bits)
{
    float value = 0.0f;

    memcpy(&value, &bits, sizeof(value));

    return (value);
}

/*!
 * @brief Score a GOOSE window with the generated model.
 *
 * @param[in] p_features The model inputs.
 *
 * @return The malicious probability.
 */
static float
goose_predict (float const * p_features)
{
    return (pico_ml_batch_predict_goose(p_features));
}

/*!
 * @brief Score an SV window with the generated model.
 *
 * @param[in] p_features The model inputs.
 *
 * @return The malicious probability.
 */
static float
sv_predict (float const * p_features)
{
    return (pico_ml_batch_predict_sv(p_features));
}

/*!
 * @brief Fill a result with a GOOSE frame's identity and fields.
 *
 * @param[in]  p_fields The PDU fields.
 * @param[in]  key      The stream key.
 * @param[out] p_result The result; cleared first.
 */
static void
populate_goose_result (goose_fields_t const * p_fields, uint32_t key,
                       analyzer_result_t * p_result)
{
    memset(p_result, 0, sizeof(*p_result));
    p_result->protocol   = ANALYZER_PROTOCOL_GOOSE;
    p_result->appid      = p_fields->appid;
    p_result->stream_key = key;
    p_result->counter_1  = p_fields->st_num;
    p_result->counter_2  = p_fields->sq_num;
    copy_printable(p_result->goose_gocb_ref, sizeof(p_result->goose_gocb_ref),
                   p_fields->p_gocb_ref, p_fields->gocb_ref_length);
    copy_printable(p_result->goose_dataset, sizeof(p_result->goose_dataset),
                   p_fields->p_dataset, p_fields->dataset_length);
    copy_printable(p_result->goose_go_id, sizeof(p_result->goose_go_id),
                   p_fields->p_go_id, p_fields->go_id_length);
    p_result->goose_ttl_ms      = p_fields->ttl_ms;
    p_result->goose_conf_rev    = p_fields->conf_rev;
    p_result->goose_num_entries = p_fields->num_entries;
    p_result->goose_simulation  = p_fields->b_simulation;
    p_result->goose_nds_com     = p_fields->b_nds_com;

    if ((NULL != p_fields->p_timestamp) && (0u != p_fields->timestamp_length))
    {
        size_t const copy_length =
            (p_fields->timestamp_length < sizeof(p_result->goose_timestamp))
                ? p_fields->timestamp_length
                : sizeof(p_result->goose_timestamp);

        memcpy(p_result->goose_timestamp, p_fields->p_timestamp, copy_length);

        // The cast is safe: copy_length is at most 8.
        p_result->goose_timestamp_length = (uint8_t) copy_length;
    }

    if (NULL != p_fields->p_all_data)
    {
        size_t const copy_length = (p_fields->all_data_length
                                    < sizeof(p_result->goose_all_data_preview))
                                     ? p_fields->all_data_length
                                     : sizeof(p_result->goose_all_data_preview);

        // The casts are safe: the length is clipped to UINT16_MAX, and
        // copy_length is at most the preview size.
        p_result->goose_all_data_length =
            (p_fields->all_data_length > UINT16_MAX)
                ? UINT16_MAX
                : (uint16_t) p_fields->all_data_length;
        memcpy(p_result->goose_all_data_preview, p_fields->p_all_data,
               copy_length);
        p_result->goose_all_data_preview_length = (uint8_t) copy_length;
    }
}

/*!
 * @brief Read the first allData element of a GOOSE PDU as a boolean.
 *
 * @param[in]  p_fields The PDU fields.
 * @param[out] pb_value Receives the value.
 *
 * @return False if the first element is not a boolean.
 */
static bool
read_goose_boolean (goose_fields_t const * p_fields, bool * pb_value)
{
    analyzer_tlv_t data_field = {0};
    bool           b_ok       = false;

    if ((NULL != p_fields->p_all_data) && (0u != p_fields->all_data_length)
        && read_tlv(p_fields->p_all_data,
                    p_fields->p_all_data + p_fields->all_data_length,
                    &data_field)
        && (GOOSE_BOOLEAN_DATA_TAG == data_field.tag)
        && (0u != data_field.length))
    {
        *pb_value = (0u != data_field.p_value[data_field.length - 1u]);
        b_ok      = true;
    }

    return (b_ok);
}

/*!
 * @brief Work out the feature row of a GOOSE frame.
 *
 * @param[in]  p_state          The stream history.
 * @param[in]  p_fields         The PDU fields.
 * @param[in]  p_source         The source MAC address.
 * @param[in]  timestamp_us     The capture time.
 * @param[out] p_features       Receives the feature row.
 * @param[out] p_delta_seconds  Receives the time since the last frame.
 * @param[out] pb_boolean_valid Receives whether allData holds a boolean.
 * @param[out] pb_boolean_value Receives that boolean.
 */
static void
calculate_goose_features (goose_state_t *        p_state,
                          goose_fields_t const * p_fields,
                          uint8_t const * p_source, uint64_t timestamp_us,
                          float   p_features[GOOSE_FEATURE_COUNT],
                          float * p_delta_seconds, bool * pb_boolean_valid,
                          bool * pb_boolean_value)
{
    // The casts are safe: times and counters are converted to float or
    // widened to signed 64 bits before they are subtracted.
    bool const b_boolean_valid = read_goose_boolean(p_fields, pb_boolean_value);
    float const delta_seconds =
        p_state->b_has_time ? ((float) (timestamp_us - p_state->timestamp_us)
                               * SECONDS_PER_MICROSECOND)
                            : 0.0f;
    float const prior_interval = ring_median(
        p_state->previous_intervals, PICO_ML_BATCH_TIMING_HISTORY_FRAMES,
        p_state->interval_count, p_state->interval_next);
    float const ratio =
        (prior_interval > 0.0f) ? (delta_seconds / prior_interval) : 1.0f;
    bool const b_source_changed =
        p_state->b_has_source
        && (0 != memcmp(p_state->source, p_source, MAC_ADDRESS_LENGTH));
    int64_t const st_delta =
        p_state->b_has_st
            ? ((int64_t) p_fields->st_num - (int64_t) p_state->st_num)
            : 0;
    int64_t const sequence_delta =
        (p_state->b_has_sq && (p_fields->st_num == p_state->st_num))
            ? ((int64_t) p_fields->sq_num - (int64_t) p_state->sq_num)
            : 0;
    float age_seconds = PICO_ML_BATCH_TIMING_MISSING_AGE_SECONDS;

    if (gb_have_latest_sv && (timestamp_us >= g_latest_sv_us))
    {
        age_seconds =
            (float) (timestamp_us - g_latest_sv_us) * SECONDS_PER_MICROSECOND;
    }
    else if (gb_have_latest_sv)
    {
        age_seconds = 0.0f;
    }
    else
    {
        // No SV frame yet: keep the "missing" age.
    }

    p_features[GOOSE_FEATURE_INTERVAL_SECONDS]   = delta_seconds;
    p_features[GOOSE_FEATURE_INTERVAL_RATIO]     = ratio;
    p_features[GOOSE_FEATURE_ST_NUMBER_DELTA]    = fabsf((float) st_delta);
    p_features[GOOSE_FEATURE_ST_NUMBER_ROLLBACK] = (st_delta < 0) ? 1.0f : 0.0f;
    p_features[GOOSE_FEATURE_ST_NUMBER_JUMP] =
        (st_delta > PICO_ML_BATCH_COUNTER_MAX_STNUM_STEP) ? 1.0f : 0.0f;
    p_features[GOOSE_FEATURE_SQ_NUMBER_DELTA] = fabsf((float) sequence_delta);
    p_features[GOOSE_FEATURE_SQ_NUMBER_ROLLBACK] =
        (sequence_delta < 0) ? 1.0f : 0.0f;
    p_features[GOOSE_FEATURE_SOURCE_CHANGED] = b_source_changed ? 1.0f : 0.0f;
    p_features[GOOSE_FEATURE_HISTORY_AVAILABLE] =
        (p_state->b_has_time && p_state->b_has_st) ? 1.0f : 0.0f;
    p_features[GOOSE_FEATURE_SV_AGE_SECONDS] = age_seconds;
    p_features[GOOSE_FEATURE_BOOLEAN_VALUE] =
        (b_boolean_valid && *pb_boolean_value) ? 1.0f : 0.0f;
    p_features[GOOSE_FEATURE_BOOLEAN_MISSING] = b_boolean_valid ? 0.0f : 1.0f;

    // The cast is safe: a bool is stored as 0 or 1.
    p_features[GOOSE_FEATURE_BOOLEAN_CHANGED] =
        (p_state->b_has_boolean && b_boolean_valid
         && (p_state->boolean_value != (uint8_t) *pb_boolean_value))
            ? 1.0f
            : 0.0f;
    *p_delta_seconds  = delta_seconds;
    *pb_boolean_valid = b_boolean_valid;
}

/*!
 * @brief Remember a GOOSE frame in its stream history.
 *
 * @param[out] p_state         The stream history.
 * @param[in]  p_fields        The PDU fields.
 * @param[in]  p_source        The source MAC address.
 * @param[in]  timestamp_us    The capture time.
 * @param[in]  delta_seconds   The time since the last frame.
 * @param[in]  b_boolean_valid Whether allData holds a boolean.
 * @param[in]  b_boolean_value That boolean.
 */
static void
update_goose_state (goose_state_t * p_state, goose_fields_t const * p_fields,
                    uint8_t const * p_source, uint64_t timestamp_us,
                    float delta_seconds, bool b_boolean_valid,
                    bool b_boolean_value)
{
    if (p_state->b_has_time && (delta_seconds > 0.0f))
    {
        push_interval(
            p_state->previous_intervals, PICO_ML_BATCH_TIMING_HISTORY_FRAMES,
            &p_state->interval_count, &p_state->interval_next, delta_seconds);
    }

    p_state->timestamp_us = timestamp_us;
    p_state->b_has_time   = true;
    p_state->st_num       = p_fields->st_num;
    p_state->sq_num       = p_fields->sq_num;
    p_state->b_has_st     = true;
    p_state->b_has_sq     = true;
    memcpy(p_state->source, p_source, MAC_ADDRESS_LENGTH);
    p_state->b_has_source = true;

    if (b_boolean_valid)
    {
        // The cast is safe: a bool is stored as 0 or 1.
        p_state->boolean_value = (uint8_t) b_boolean_value;
        p_state->b_has_boolean = true;
    }

    g_latest_goose_us    = timestamp_us;
    gb_have_latest_goose = true;
}

/*!
 * @brief Check a gap-suspect GOOSE stream's counters (Tribunal 1, FR8).
 *
 * @par
 * A counter jump without a capture gap is never reset here: that jump is
 * attack evidence and must be scored.
 *
 * @param[in] p_state  The stream history.
 * @param[in] p_fields The PDU fields.
 *
 * @return True if no frame of this stream was lost.
 */
static bool
goose_counter_continuous (goose_state_t const *  p_state,
                          goose_fields_t const * p_fields)
{
    bool b_continuous = true;

    if (p_state->b_has_st && p_state->b_has_sq)
    {
        if (p_fields->st_num == p_state->st_num)
        {
            b_continuous = (p_fields->sq_num == (p_state->sq_num + 1u));
        }
        else
        {
            // A new event: stNum steps by one and sqNum restarts at 0 or 1.
            b_continuous = (p_fields->st_num == (p_state->st_num + 1u))
                        && (p_fields->sq_num <= GOOSE_NEW_EVENT_MAX_SQ);
        }
    }

    return (b_continuous);
}

/*!
 * @brief Check a gap-suspect SV stream's counter (Tribunal 1, FR8).
 *
 * @param[in] p_state  The stream history.
 * @param[in] p_fields The PDU fields.
 *
 * @return True if no frame of this stream was lost.
 */
static bool
sv_counter_continuous (sv_state_t const * p_state, sv_fields_t const * p_fields)
{
    // The casts are safe: the ASDU count is at most MAXIMUM_ASDUS, and the
    // counters are widened to signed 64 bits before they are subtracted.
    uint32_t const expected_step = (uint32_t) p_fields->asdu_count;
    uint32_t const current       = p_fields->asdus[0].smp_cnt;
    bool           b_continuous  = true;

    if (p_state->b_has_counter[0])
    {
        int64_t const delta =
            (int64_t) current - (int64_t) p_state->counters[0];

        // A normal step, or smpCnt wrapped to 0 at the end of the second.
        b_continuous = (delta == (int64_t) expected_step)
                    || ((delta < 0) && (current < expected_step));
    }

    return (b_continuous);
}

/*!
 * @brief Clear a GOOSE stream's history but keep its identity.
 *
 * @param[in,out] p_state The stream history.
 */
static void
reset_goose_stream (goose_state_t * p_state)
{
    uint32_t const          key      = p_state->key;
    stream_identity_t const identity = p_state->identity;

    memset(p_state, 0, sizeof(*p_state));
    p_state->b_used   = true;
    p_state->key      = key;
    p_state->identity = identity;
}

/*!
 * @brief Clear an SV stream's history but keep its identity.
 *
 * @param[in,out] p_state The stream history.
 */
static void
reset_sv_stream (sv_state_t * p_state)
{
    uint32_t const          key      = p_state->key;
    stream_identity_t const identity = p_state->identity;

    memset(p_state, 0, sizeof(*p_state));
    p_state->b_used   = true;
    p_state->key      = key;
    p_state->identity = identity;
}

/*!
 * @brief Add a parsed GOOSE frame to its stream and window.
 *
 * @param[in]  p_source      The source MAC address.
 * @param[in]  p_destination The destination MAC address.
 * @param[in]  p_fields      The PDU fields.
 * @param[in]  timestamp_us  The capture time.
 * @param[out] p_result      Receives the result.
 * @param[in]  rule_profile  The stream's rule profile.
 *
 * @return False if the stream has no slot or time went backwards.
 */
static bool
process_goose_batch (uint8_t const * p_source, uint8_t const * p_destination,
                     goose_fields_t const * p_fields, uint64_t timestamp_us,
                     analyzer_result_t * p_result, uint32_t rule_profile)
{
    uint32_t const key = batch_hash(p_fields->appid, p_fields->p_gocb_ref,
                                    p_fields->gocb_ref_length, p_destination);
    goose_state_t * const p_state =
        goose_state_for(p_fields->appid, p_fields->p_gocb_ref,
                        p_fields->gocb_ref_length, p_destination, key);
    float  features[GOOSE_FEATURE_COUNT] = {0.0f};
    float  delta_seconds                 = 0.0f;
    bool   b_boolean_valid               = false;
    bool   b_boolean_value               = false;
    size_t feature_index                 = 0u;
    bool   b_stream_reset                = false;
    bool   b_processed                   = false;

    if ((NULL != p_state) && p_state->b_gap_suspect)
    {
        p_state->b_gap_suspect = false;

        if (goose_counter_continuous(p_state, p_fields))
        {
            ++g_streams_kept;
        }
        else
        {
            reset_goose_stream(p_state);
            ++g_streams_reset;
            b_stream_reset = true;
        }
    }

    if (NULL == p_state)
    {
        if (!gb_have_latest_goose || (timestamp_us > g_latest_goose_us))
        {
            g_latest_goose_us = timestamp_us;
        }

        gb_have_latest_goose = true;
    }
    else if (p_state->b_has_time && (timestamp_us < p_state->timestamp_us))
    {
        ++g_malformed_frames;
    }
    else
    {
        populate_goose_result(p_fields, key, p_result);
        p_result->stream_reset = b_stream_reset;
        p_result->timestamp_us = timestamp_us;
        calculate_goose_features(p_state, p_fields, p_source, timestamp_us,
                                 features, &delta_seconds, &b_boolean_valid,
                                 &b_boolean_value);
        update_goose_state(p_state, p_fields, p_source, timestamp_us,
                           delta_seconds, b_boolean_valid, b_boolean_value);
        record_batch_packet(p_state->batch_packets, STATE_FRAMES(p_state),
                            p_state->batch_count, p_result, &p_state->identity);
        predict_batch(
            &p_state->batch[0][0], GOOSE_FEATURE_COUNT, &p_state->batch_count,
            features, p_result, &p_state->previous_label,
            &p_state->b_has_prediction, PICO_ML_BATCH_GOOSE_THRESHOLD,
            goose_predict, GOOSE_BATCH_FEATURE_COUNT, p_state->batch_packets,
            STATE_FRAMES(p_state), rule_profile, p_state->batch_rule_reasons);
        p_result->feature_count = ANALYZER_FEATURE_CAPACITY;

        for (feature_index = 0u; feature_index < ANALYZER_FEATURE_CAPACITY;
             ++feature_index)
        {
            p_result->features[feature_index] = features[feature_index];
        }

        b_processed = true;
    }

    return (b_processed);
}

/*!
 * @brief Check that every ASDU holds finite values for every model channel.
 *
 * @param[in]  p_fields          The PDU fields.
 * @param[out] p_required_length Receives the sample bytes the channels need.
 *
 * @return True if the samples can be used.
 */
static bool
validate_sv_payload (sv_fields_t const * p_fields, size_t * p_required_length)
{
    size_t channel        = 0u;
    size_t maximum_length = 0u;
    size_t asdu_index     = 0u;

    if ((NULL == p_fields) || (NULL == p_required_length)
        || (0u == p_fields->asdu_count)
        || (p_fields->asdu_count > MAXIMUM_ASDUS))
    {
        return (false);
    }

    for (channel = 0u; channel < PICO_ML_BATCH_SV_CHANNEL_COUNT; ++channel)
    {
        // The cast is safe: the offsets are small generated constants.
        size_t const channel_end =
            (size_t) g_pico_ml_batch_sv_channel_offsets[channel] + FLOAT32_SIZE;

        if (channel_end > maximum_length)
        {
            maximum_length = channel_end;
        }
    }

    for (asdu_index = 0u; asdu_index < p_fields->asdu_count; ++asdu_index)
    {
        sv_asdu_t const * const p_asdu = &p_fields->asdus[asdu_index];

        if ((NULL == p_asdu->p_seq_data)
            || (p_asdu->seq_data_length < maximum_length))
        {
            return (false);
        }

        for (channel = 0u; channel < PICO_ML_BATCH_SV_CHANNEL_COUNT; ++channel)
        {
            size_t const offset = g_pico_ml_batch_sv_channel_offsets[channel];

            if (!isfinite(float_from_bits(
                    read_be32_float_bits(p_asdu->p_seq_data + offset))))
            {
                return (false);
            }
        }
    }

    *p_required_length = maximum_length;

    return (true);
}

/*!
 * @brief Measure how far a sample is from its channel's recent median.
 *
 * @param[in] p_state    The stream history.
 * @param[in] asdu_index The ASDU index.
 * @param[in] channel    The model channel.
 * @param[in] current    The new sample.
 *
 * @return The change relative to the median, the channel scale or epsilon,
 *         whichever is largest.
 */
static float
wave_relative_change (sv_state_t const * p_state, size_t asdu_index,
                      size_t channel, float current)
{
    uint16_t const history_count = p_state->wave_count[asdu_index][channel];
    uint16_t const next          = p_state->wave_next[asdu_index][channel];
    size_t         history_index = 0u;
    float          baseline      = 0.0f;

    for (history_index = 0u; history_index < history_count; ++history_index)
    {
        g_sv_history_scratch[history_index] =
            p_state->wave[asdu_index][channel]
                         [((next + PICO_ML_BATCH_WAVE_HISTORY_SAMPLES)
                           - history_count + history_index)
                          % PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
    }

    baseline = batch_median(g_sv_history_scratch, history_count);

    return (fabsf(current - baseline)
            / maximum_float(
                maximum_float(fabsf(baseline),
                              g_pico_ml_batch_sv_relative_scale[channel]),
                PICO_ML_BATCH_WAVE_EPSILON));
}

/*!
 * @brief Measure an SV frame's counters and samples against the history.
 *
 * @param[in,out] p_state   The stream history; receives the new samples.
 * @param[in]     p_fields  The PDU fields.
 * @param[in,out] p_metrics Receives the measurements.
 */
static void
collect_sv_samples (sv_state_t * p_state, sv_fields_t const * p_fields,
                    sv_batch_metrics_t * p_metrics)
{
    size_t asdu_index = 0u;
    size_t channel    = 0u;

    memset(g_sv_changes, 0, sizeof(g_sv_changes));
    memset(g_sv_channel_values, 0, sizeof(g_sv_channel_values));
    memset(g_sv_history_scratch, 0, sizeof(g_sv_history_scratch));

    for (asdu_index = 0u; asdu_index < p_fields->asdu_count; ++asdu_index)
    {
        sv_asdu_t const * const p_asdu = &p_fields->asdus[asdu_index];

        if (p_state->b_has_counter[asdu_index])
        {
            // The casts are safe: the 32-bit difference is widened, folded
            // into the signed 32-bit range and converted to float.
            int64_t counter_delta =
                (int64_t) (p_asdu->smp_cnt - p_state->counters[asdu_index]);
            float absolute_delta = 0.0f;

            if (counter_delta > INT32_MAX)
            {
                counter_delta -= UINT32_RANGE;
            }

            absolute_delta = fabsf((float) counter_delta);
            p_metrics->delta_max =
                maximum_float(p_metrics->delta_max, absolute_delta);
            p_metrics->back += (counter_delta < 0) ? 1u : 0u;
            p_metrics->repeat += (0 == counter_delta) ? 1u : 0u;
            p_metrics->gap +=
                (absolute_delta > PICO_ML_BATCH_COUNTER_MAX_SMP_DELTA) ? 1u
                                                                       : 0u;
        }

        p_state->counters[asdu_index]      = p_asdu->smp_cnt;
        p_state->b_has_counter[asdu_index] = true;

        for (channel = 0u; channel < PICO_ML_BATCH_SV_CHANNEL_COUNT; ++channel)
        {
            size_t const offset  = g_pico_ml_batch_sv_channel_offsets[channel];
            float const  current = float_from_bits(
                read_be32_float_bits(p_asdu->p_seq_data + offset));

            g_sv_channel_values[channel][asdu_index] = current;

            if (0u != p_state->wave_count[asdu_index][channel])
            {
                float const relative_change =
                    wave_relative_change(p_state, asdu_index, channel, current);

                g_sv_changes[p_metrics->change_count] = relative_change;
                p_metrics->change_count++;
                p_metrics->jumps +=
                    (relative_change >= PICO_ML_BATCH_WAVE_RELATIVE_JUMP_LIMIT)
                        ? 1u
                        : 0u;
                p_metrics->flat +=
                    (relative_change
                     <= PICO_ML_BATCH_WAVE_PLATEAU_RELATIVE_LIMIT)
                        ? 1u
                        : 0u;
                ++p_metrics->value_count;
            }

            wave_push(&p_state->wave[asdu_index][channel][0],
                      &p_state->wave_count[asdu_index][channel],
                      &p_state->wave_next[asdu_index][channel], current);
        }
    }
}

/*!
 * @brief Compare this frame's waveform changes with the stream's history
 *        of changes, then add them to it.
 *
 * @param[in,out] p_state   The stream history.
 * @param[in,out] p_metrics The measurements.
 */
static void
summarize_sv_history (sv_state_t * p_state, sv_batch_metrics_t * p_metrics)
{
    size_t history_index = 0u;

    p_metrics->previous_wave_count = p_state->wave_delta_count;

    for (history_index = 0u; history_index < p_state->wave_delta_count;
         ++history_index)
    {
        g_sv_history_scratch[history_index] =
            p_state->wave_deltas[((p_state->wave_delta_next
                                   + PICO_ML_BATCH_WAVE_HISTORY_SAMPLES)
                                  - p_state->wave_delta_count + history_index)
                                 % PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
    }

    p_metrics->robust =
        batch_median(g_sv_history_scratch, p_state->wave_delta_count);

    for (history_index = 0u; history_index < p_metrics->change_count;
         ++history_index)
    {
        p_metrics->change_sum += g_sv_changes[history_index];
        p_metrics->change_max =
            maximum_float(p_metrics->change_max, g_sv_changes[history_index]);
        p_state->wave_deltas[p_state->wave_delta_next] =
            g_sv_changes[history_index];
        p_state->wave_delta_next = (p_state->wave_delta_next + 1u)
                                 % PICO_ML_BATCH_WAVE_HISTORY_SAMPLES;

        if (p_state->wave_delta_count < PICO_ML_BATCH_WAVE_HISTORY_SAMPLES)
        {
            ++p_state->wave_delta_count;
        }
    }
}

/*!
 * @brief Measure the spread of each channel across a frame's ASDUs.
 *
 * @param[in]     asdu_count The number of ASDUs.
 * @param[in,out] p_metrics  Receives the ranges.
 */
static void
calculate_sv_channel_ranges (size_t asdu_count, sv_batch_metrics_t * p_metrics)
{
    size_t channel    = 0u;
    size_t asdu_index = 0u;

    for (channel = 0u; channel < PICO_ML_BATCH_SV_CHANNEL_COUNT; ++channel)
    {
        float channel_values[MAXIMUM_ASDUS] = {0.0f};
        float center                        = 0.0f;
        float low                           = 0.0f;
        float high                          = 0.0f;

        for (asdu_index = 0u; asdu_index < asdu_count; ++asdu_index)
        {
            channel_values[asdu_index] =
                g_sv_channel_values[channel][asdu_index];
        }

        center = fabsf(batch_median(channel_values, asdu_count));
        low    = channel_values[0];
        high   = channel_values[0];

        for (asdu_index = 1u; asdu_index < asdu_count; ++asdu_index)
        {
            low  = minimum_float(low, channel_values[asdu_index]);
            high = maximum_float(high, channel_values[asdu_index]);
        }

        p_metrics->ranges[channel] =
            (high - low)
            / maximum_float(
                maximum_float(center,
                              g_pico_ml_batch_sv_relative_scale[channel]),
                PICO_ML_BATCH_WAVE_EPSILON);
        p_metrics->range_sum += p_metrics->ranges[channel];
        p_metrics->range_max =
            maximum_float(p_metrics->range_max, p_metrics->ranges[channel]);
    }
}

/*!
 * @brief Work out the feature row of an SV frame.
 *
 * @param[in]  p_state       The stream history.
 * @param[in]  p_fields      The PDU fields.
 * @param[in]  p_source      The source MAC address.
 * @param[in]  timestamp_us  The capture time.
 * @param[in]  delta_seconds The time since the last frame.
 * @param[in]  ratio         The interval over the median interval.
 * @param[in]  p_metrics     The measurements.
 * @param[out] p_features    Receives the feature row.
 */
static void
calculate_sv_features (sv_state_t const * p_state, sv_fields_t const * p_fields,
                       uint8_t const * p_source, uint64_t timestamp_us,
                       float delta_seconds, float ratio,
                       sv_batch_metrics_t const * p_metrics,
                       float                      p_features[SV_FEATURE_COUNT])
{
    float age_seconds = PICO_ML_BATCH_TIMING_MISSING_AGE_SECONDS;

    // The casts below are safe: counts and times are converted to float for
    // the model.
    if (gb_have_latest_goose && (timestamp_us >= g_latest_goose_us))
    {
        age_seconds = (float) (timestamp_us - g_latest_goose_us)
                    * SECONDS_PER_MICROSECOND;
    }
    else if (gb_have_latest_goose)
    {
        age_seconds = 0.0f;
    }
    else
    {
        // No GOOSE frame yet: keep the "missing" age.
    }

    p_features[SV_FEATURE_INTERVAL_SECONDS]      = delta_seconds;
    p_features[SV_FEATURE_INTERVAL_RATIO]        = ratio;
    p_features[SV_FEATURE_GOOSE_AGE_SECONDS]     = age_seconds;
    p_features[SV_FEATURE_ASDU_COUNT]            = (float) p_fields->no_asdu;
    p_features[SV_FEATURE_COUNTER_BACK]          = (float) p_metrics->back;
    p_features[SV_FEATURE_COUNTER_REPEAT]        = (float) p_metrics->repeat;
    p_features[SV_FEATURE_COUNTER_GAP]           = (float) p_metrics->gap;
    p_features[SV_FEATURE_COUNTER_DELTA_MAXIMUM] = p_metrics->delta_max;
    p_features[SV_FEATURE_WAVE_RELATIVE_CHANGE_MEAN] =
        (0u != p_metrics->change_count)
            ? (p_metrics->change_sum / (float) p_metrics->change_count)
            : 0.0f;
    p_features[SV_FEATURE_WAVE_RELATIVE_CHANGE_MAXIMUM] = p_metrics->change_max;
    p_features[SV_FEATURE_WAVE_JUMP_FRACTION] =
        (0u != p_metrics->value_count)
            ? ((float) p_metrics->jumps / (float) p_metrics->value_count)
            : 0.0f;
    p_features[SV_FEATURE_WAVE_PLATEAU_FRACTION] =
        (0u != p_metrics->value_count)
            ? ((float) p_metrics->flat / (float) p_metrics->value_count)
            : 0.0f;
    p_features[SV_FEATURE_WAVE_JUMP_COUNT]       = (float) p_metrics->jumps;
    p_features[SV_FEATURE_WAVE_HISTORY_COVERAGE] = minimum_float(
        1.0f, (float) p_metrics->previous_wave_count
                  / (float) PICO_ML_BATCH_WAVE_HISTORY_MIN_SAMPLES);
    p_features[SV_FEATURE_WAVE_ROBUST_RATIO] = minimum_float(
        PICO_ML_BATCH_WAVE_ROBUST_RATIO_CAP,
        p_metrics->change_max
            / maximum_float(p_metrics->robust, PICO_ML_BATCH_WAVE_EPSILON));
    p_features[SV_FEATURE_CHANNEL_RANGE_MEAN] =
        p_metrics->range_sum / (float) PICO_ML_BATCH_SV_CHANNEL_COUNT;
    p_features[SV_FEATURE_CHANNEL_RANGE_MAXIMUM] = p_metrics->range_max;
    p_features[SV_FEATURE_SOURCE_CHANGED] =
        (p_state->b_has_source
         && (0 != memcmp(p_state->source, p_source, MAC_ADDRESS_LENGTH)))
            ? 1.0f
            : 0.0f;
}

/*!
 * @brief Remember an SV frame's time and source in its stream history.
 *
 * @param[out] p_state       The stream history.
 * @param[in]  p_source      The source MAC address.
 * @param[in]  timestamp_us  The capture time.
 * @param[in]  delta_seconds The time since the last frame.
 */
static void
update_sv_state (sv_state_t * p_state, uint8_t const * p_source,
                 uint64_t timestamp_us, float delta_seconds)
{
    if (p_state->b_has_time && (delta_seconds > 0.0f))
    {
        push_interval(
            p_state->previous_intervals, PICO_ML_BATCH_TIMING_HISTORY_FRAMES,
            &p_state->interval_count, &p_state->interval_next, delta_seconds);
    }

    p_state->timestamp_us = timestamp_us;
    p_state->b_has_time   = true;
    memcpy(p_state->source, p_source, MAC_ADDRESS_LENGTH);
    p_state->b_has_source = true;
    g_latest_sv_us        = timestamp_us;
    gb_have_latest_sv     = true;
}

/*!
 * @brief Add a parsed SV frame to its stream's history and window.
 *
 * @param[in,out] p_state      The stream history.
 * @param[in]     key          The stream key.
 * @param[in]     p_source     The source MAC address.
 * @param[in]     p_fields     The PDU fields.
 * @param[in]     timestamp_us The capture time.
 * @param[out]    p_result     Receives the result.
 * @param[in]     rule_profile The stream's rule profile.
 *
 * @return False if time went backwards.
 */
static bool
analyze_sv_state (sv_state_t * p_state, uint32_t key, uint8_t const * p_source,
                  sv_fields_t const * p_fields, uint64_t timestamp_us,
                  analyzer_result_t * p_result, uint32_t rule_profile)
{
    sv_batch_metrics_t metrics                    = {0};
    float              features[SV_FEATURE_COUNT] = {0.0f};
    float              delta_seconds              = 0.0f;
    float              prior_interval             = 0.0f;
    size_t             feature_index              = 0u;
    bool               b_stream_reset             = false;
    bool               b_processed                = false;

    if (p_state->b_gap_suspect)
    {
        p_state->b_gap_suspect = false;

        if (sv_counter_continuous(p_state, p_fields))
        {
            ++g_streams_kept;
        }
        else
        {
            reset_sv_stream(p_state);
            ++g_streams_reset;
            b_stream_reset = true;
        }
    }

    if (p_state->b_has_time && (timestamp_us < p_state->timestamp_us))
    {
        ++g_malformed_frames;
    }
    else
    {
        memset(p_result, 0, sizeof(*p_result));
        p_result->stream_reset = b_stream_reset;
        p_result->protocol     = ANALYZER_PROTOCOL_SAMPLED_VALUES;
        p_result->appid        = p_fields->appid;
        p_result->timestamp_us = timestamp_us;
        p_result->stream_key   = key;
        p_result->counter_1    = p_fields->asdus[0].smp_cnt;

        // The cast is safe: the time difference is converted to float.
        delta_seconds  = p_state->b_has_time
                           ? ((float) (timestamp_us - p_state->timestamp_us)
                              * SECONDS_PER_MICROSECOND)
                           : 0.0f;
        prior_interval = ring_median(
            p_state->previous_intervals, PICO_ML_BATCH_TIMING_HISTORY_FRAMES,
            p_state->interval_count, p_state->interval_next);
        collect_sv_samples(p_state, p_fields, &metrics);
        summarize_sv_history(p_state, &metrics);
        calculate_sv_channel_ranges(p_fields->asdu_count, &metrics);
        calculate_sv_features(
            p_state, p_fields, p_source, timestamp_us, delta_seconds,
            (prior_interval > 0.0f) ? (delta_seconds / prior_interval) : 1.0f,
            &metrics, features);
        update_sv_state(p_state, p_source, timestamp_us, delta_seconds);
        record_batch_packet(p_state->batch_packets, STATE_FRAMES(p_state),
                            p_state->batch_count, p_result, &p_state->identity);
        predict_batch(
            &p_state->batch[0][0], SV_FEATURE_COUNT, &p_state->batch_count,
            features, p_result, &p_state->previous_label,
            &p_state->b_has_prediction, PICO_ML_BATCH_SV_THRESHOLD, sv_predict,
            SV_BATCH_FEATURE_COUNT, p_state->batch_packets,
            STATE_FRAMES(p_state), rule_profile, p_state->batch_rule_reasons);
        p_result->feature_count = ANALYZER_FEATURE_CAPACITY;

        for (feature_index = 0u; feature_index < ANALYZER_FEATURE_CAPACITY;
             ++feature_index)
        {
            p_result->features[feature_index] = features[feature_index];
        }

        b_processed = true;
    }

    return (b_processed);
}

/*!
 * @brief Add a parsed SV frame to its stream and window.
 *
 * @param[in]  p_source      The source MAC address.
 * @param[in]  p_destination The destination MAC address.
 * @param[in]  p_fields      The PDU fields.
 * @param[in]  timestamp_us  The capture time.
 * @param[out] p_result      Receives the result.
 * @param[in]  rule_profile  The stream's rule profile.
 *
 * @return False if the samples are unusable, the stream has no slot or time
 *         went backwards.
 */
static bool
process_sv_batch (uint8_t const * p_source, uint8_t const * p_destination,
                  sv_fields_t const * p_fields, uint64_t timestamp_us,
                  analyzer_result_t * p_result, uint32_t rule_profile)
{
    size_t required_length = 0u;
    bool   b_processed     = false;

    if ((NULL == p_source) || (NULL == p_destination) || (NULL == p_fields)
        || (NULL == p_result) || (0u == p_fields->asdu_count)
        || (p_fields->asdu_count > MAXIMUM_ASDUS)
        || (!validate_sv_payload(p_fields, &required_length)))
    {
        ++g_malformed_frames;
    }
    else
    {
        sv_asdu_t const * const p_first_asdu = &p_fields->asdus[0];
        uint32_t const          key =
            batch_hash(p_fields->appid, p_first_asdu->p_sv_id,
                       p_first_asdu->sv_id_length, p_destination);
        sv_state_t * const p_state =
            sv_state_for(p_fields->appid, p_first_asdu->p_sv_id,
                         p_first_asdu->sv_id_length, p_destination, key);

        if (NULL == p_state)
        {
            if (!gb_have_latest_sv || (timestamp_us > g_latest_sv_us))
            {
                g_latest_sv_us = timestamp_us;
            }

            gb_have_latest_sv = true;
        }
        else
        {
            b_processed =
                analyze_sv_state(p_state, key, p_source, p_fields, timestamp_us,
                                 p_result, rule_profile);
        }
    }

    return (b_processed);
}

/*!
 * @brief Find the stored bytes of one frame of the latest completed window.
 *
 * @param[in] index The window frame index, below ANALYZER_BATCH_FRAME_COUNT.
 *
 * @return The bytes, or NULL if they are not kept.
 */
static uint8_t const *
batch_frame_bytes (size_t index)
{
    uint8_t const * p_bytes = NULL;

#if ANALYZER_STORE_WINDOW_FRAMES
    if (NULL != gp_completed_window_frames)
    {
        p_bytes = (ANALYZER_NEWEST_FRAME_INDEX == index)
                    ? g_completed_newest_frame
                    : (gp_completed_window_frames
                       + (index * ANALYZER_MAXIMUM_FRAME_LENGTH));
    }
#else
    if (ANALYZER_NEWEST_FRAME_INDEX == index)
    {
        p_bytes = g_last_newest_frame;
    }
#endif

    return (p_bytes);
}

/*!
 * @brief Read the boolean value of a stored GOOSE window frame.
 *
 * @param[in]  p_payload The frame payload.
 * @param[out] p_values  Receives the value.
 *
 * @return True if the value was read.
 */
static bool
values_from_goose (ethernet_payload_t const * p_payload,
                   analyzer_packet_values_t * p_values)
{
    goose_fields_t fields  = {0};
    bool           b_value = false;
    bool           b_ok    = false;

    if (parse_goose(p_payload, &fields)
        && read_goose_boolean(&fields, &b_value))
    {
        p_values->bits[0] = b_value ? 1u : 0u;
        p_values->format  = ANALYZER_VALUES_GOOSE_BOOLEAN;
        b_ok              = true;
    }

    return (b_ok);
}

/*!
 * @brief Read the model channel samples of a stored SV window frame.
 *
 * @param[in]  p_payload The frame payload.
 * @param[out] p_values  Receives the float bits of the first ASDU.
 *
 * @return True if the samples were read.
 */
static bool
values_from_sv (ethernet_payload_t const * p_payload,
                analyzer_packet_values_t * p_values)
{
    sv_fields_t fields   = {0};
    size_t      required = 0u;
    size_t      channel  = 0u;
    bool        b_ok     = false;

    if (parse_sv(p_payload, &fields) && validate_sv_payload(&fields, &required))
    {
        for (channel = 0u; channel < PICO_ML_BATCH_SV_CHANNEL_COUNT; ++channel)
        {
            p_values->bits[channel] = read_be32_float_bits(
                fields.asdus[0].p_seq_data
                + g_pico_ml_batch_sv_channel_offsets[channel]);
        }

        p_values->format = ANALYZER_VALUES_SV_FLOAT_BITS;
        b_ok             = true;
    }

    return (b_ok);
}

/*!
 * @brief Read the simulation bit of a GOOSE or SV header.
 *
 * @param[in] p_payload The Ethernet payload, at least
 *                      IEC61850_APDU_MINIMUM_LENGTH bytes.
 *
 * @return True if the frame says it is a test frame.
 */
static bool
is_simulated (ethernet_payload_t const * p_payload)
{
    return (0u
            != (p_payload->p_data[IEC61850_RESERVED1_OFFSET]
                & IEC61850_SIMULATE_BIT));
}

/*!
 * @brief Parse, rule-check and add a GOOSE frame.
 *
 * @param[in]  p_payload     The frame payload.
 * @param[in]  p_source      The source MAC address.
 * @param[in]  p_destination The destination MAC address.
 * @param[in]  timestamp_us  The capture time.
 * @param[out] p_result      Receives the result.
 *
 * @return True if the frame was parsed and added.
 */
static bool
analyze_goose_frame (ethernet_payload_t const * p_payload,
                     uint8_t const * p_source, uint8_t const * p_destination,
                     uint64_t timestamp_us, analyzer_result_t * p_result)
{
    goose_fields_t fields      = {0};
    bool           b_processed = false;

    if (!parse_goose(p_payload, &fields))
    {
        iec_rules_parse_error(false);
        ++g_malformed_frames;
    }
    else
    {
        iec_rules_frame_t const view = {
            .protocol       = IEC_RULES_PROTOCOL_GOOSE,
            .appid          = fields.appid,
            .p_source       = p_source,
            .p_destination  = p_destination,
            .p_id           = fields.p_gocb_ref,
            .id_length      = fields.gocb_ref_length,
            .p_dataset      = fields.p_dataset,
            .dataset_length = fields.dataset_length,
            .conf_rev       = fields.conf_rev,
            .entries        = fields.num_entries,
            .counter        = fields.st_num,
            .sequence       = fields.sq_num,
            .ttl_ms         = fields.ttl_ms,
            .data_hash =
                iec_rules_hash(fields.p_all_data, fields.all_data_length),
            .b_test = fields.b_simulation || is_simulated(p_payload),
            .b_needs_commission = fields.b_nds_com,
            .timestamp_us       = timestamp_us,
            .semantic_reasons   = fields.rule_reasons,
        };
        uint32_t const profile = iec_rules_observe(&view);

        b_processed = process_goose_batch(p_source, p_destination, &fields,
                                          timestamp_us, p_result, profile);
    }

    return (b_processed);
}

/*!
 * @brief Parse, rule-check and add an SV frame.
 *
 * @param[in]  p_payload     The frame payload.
 * @param[in]  p_source      The source MAC address.
 * @param[in]  p_destination The destination MAC address.
 * @param[in]  timestamp_us  The capture time.
 * @param[out] p_result      Receives the result.
 *
 * @return True if the frame was parsed and added.
 */
static bool
analyze_sv_frame (ethernet_payload_t const * p_payload,
                  uint8_t const * p_source, uint8_t const * p_destination,
                  uint64_t timestamp_us, analyzer_result_t * p_result)
{
    sv_fields_t fields      = {0};
    bool        b_processed = false;

    if (!parse_sv(p_payload, &fields))
    {
        iec_rules_parse_error(gb_unsupported_parse);

        if (!gb_unsupported_parse)
        {
            ++g_malformed_frames;
        }

        gb_unsupported_parse = false;
    }
    else
    {
        sv_asdu_t const * const p_first = &fields.asdus[0];

        // The cast is safe: the ASDU count is at most MAXIMUM_ASDUS.
        iec_rules_frame_t const view = {
            .protocol         = IEC_RULES_PROTOCOL_SV,
            .appid            = fields.appid,
            .p_source         = p_source,
            .p_destination    = p_destination,
            .p_id             = p_first->p_sv_id,
            .id_length        = p_first->sv_id_length,
            .conf_rev         = p_first->conf_rev,
            .counter          = p_first->smp_cnt,
            .smp_synch        = p_first->smp_synch,
            .asdu_count       = (uint32_t) fields.asdu_count,
            .b_test           = is_simulated(p_payload),
            .timestamp_us     = timestamp_us,
            .semantic_reasons = fields.rule_reasons,
        };
        uint32_t const profile = iec_rules_observe(&view);

        b_processed = process_sv_batch(p_source, p_destination, &fields,
                                       timestamp_us, p_result, profile);
    }

    return (b_processed);
}

/*!
 * @brief Analyse one Ethernet frame.
 *
 * @param[in]  p_frame      The frame.
 * @param[in]  length       The frame length.
 * @param[in]  timestamp_us The capture time.
 * @param[out] p_result     Receives the result.
 *
 * @return True for a parsed GOOSE or SV frame, including warm-up frames.
 */
static bool
process_frame (uint8_t const * p_frame, size_t length, uint64_t timestamp_us,
               analyzer_result_t * p_result)
{
    ethernet_payload_t payload     = {0};
    bool               b_processed = false;

    if ((NULL == p_frame) || (NULL == p_result)
        || (length < ETHERNET_HEADER_SIZE)
        || (!find_ethernet_payload(p_frame, length, &payload)))
    {
        iec_rules_parse_error(false);
        ++g_malformed_frames;
    }
    else if (GOOSE_ETHERTYPE == payload.type)
    {
        b_processed =
            analyze_goose_frame(&payload, p_frame + MAC_ADDRESS_LENGTH, p_frame,
                                timestamp_us, p_result);
    }
    else if (SV_ETHERTYPE == payload.type)
    {
        b_processed = analyze_sv_frame(&payload, p_frame + MAC_ADDRESS_LENGTH,
                                       p_frame, timestamp_us, p_result);
    }
    else
    {
        // Other EtherTypes are not analysed.
    }

    return (b_processed);
}

/*** end of file ***/
