/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * C implementation of bounded GOOSE and Sampled Values frame analysis.
 */

#include "analyzer.h"

#include "generated_batch_models.h"

#include <math.h>
#include <string.h>

#define GOOSE_ETHERTYPE (0x88b8u)
#define SV_ETHERTYPE (0x88bau)
#define MAXIMUM_ASDUS (14u)
#define MAXIMUM_GOOSE_STREAMS (4u)
#define MAXIMUM_SV_STREAMS (2u)
#define MAXIMUM_STREAM_ID_LENGTH (64u)
#define MAC_ADDRESS_LENGTH (6u)
#define GOOSE_FEATURE_COUNT (13u)
#define SV_FEATURE_COUNT (18u)
#define GOOSE_BATCH_FEATURE_COUNT (52u)
#define SV_BATCH_FEATURE_COUNT (72u)
#define FLOAT32_SIZE (4u)
#define BER_MAX_LENGTH_OCTETS (sizeof(size_t))
#define BER_UNSIGNED_INTEGER_MAX_OCTETS (5u)
#define BER_TAG_HIGH_BIT_MASK (0x80u)
#define BER_LENGTH_OCTET_MASK (0x7fu)
#define BITS_PER_BYTE (8u)
#define BER_TLV_HEADER_SIZE (2u)
#define ETHERNET_HEADER_SIZE (14u)
#define ETHERNET_TYPE_FIELD_OFFSET (12u)
#define VLAN_TAG_HEADER_SIZE (4u)
#define VLAN_TYPE_FIELD_OFFSET (2u)
#define MAXIMUM_VLAN_TAGS (2u)
#define IEC61850_APDU_MINIMUM_LENGTH (10u)
#define IEC61850_APDU_OFFSET (8u)
#define IEC61850_APDU_LENGTH_OFFSET (2u)
#define MAXIMUM_ENCODED_ASDU_COUNT (256u)
#define UINT32_SERIALIZATION_BUFFER (4u)
#define BATCH_FEATURES_PER_METRIC (4u)
#define INTEGER_MIDPOINT_DIVISOR (2u)
#define ASCII_PRINTABLE_MINIMUM (32u)
#define ASCII_PRINTABLE_MAXIMUM (127u)
#define BYTE_OFFSET_TWO (2u)
#define BYTE_OFFSET_THREE (3u)
#define EXPECTED_BATCH_FRAME_COUNT (4u)
#define EXPECTED_BATCH_STRIDE (2u)
#define EXPECTED_SV_CHANNEL_COUNT (6u)
#define EXPECTED_WAVE_HISTORY_SAMPLES (128u)
#define EXPECTED_TIMING_HISTORY_FRAMES (32u)
#define FLOAT_MIDPOINT_RATIO (0.5f)

#define ETHERNET_VLAN_8021Q_TYPE (0x8100u)
#define ETHERNET_VLAN_8021AD_TYPE (0x88a8u)
#define ETHERNET_VLAN_QINQ_TYPE (0x9100u)
#define GOOSE_APDU_TAG (0x61u)
#define SV_APDU_TAG (0x60u)
#define BER_SEQUENCE_TAG (0x30u)
#define SV_SEQUENCE_TAG (0xa2u)
#define GOOSE_TAG_GOCB_REF (0x80u)
#define GOOSE_TAG_TIME_ALLOWED_TO_LIVE (0x81u)
#define GOOSE_TAG_DATASET (0x82u)
#define GOOSE_TAG_GO_ID (0x83u)
#define GOOSE_TAG_TIMESTAMP (0x84u)
#define GOOSE_TAG_STATE_NUMBER (0x85u)
#define GOOSE_TAG_SEQUENCE_NUMBER (0x86u)
#define GOOSE_TAG_SIMULATION (0x87u)
#define GOOSE_TAG_CONFIGURATION_REVISION (0x88u)
#define GOOSE_TAG_NEEDS_COMMISSIONING (0x89u)
#define GOOSE_TAG_NUMBER_OF_ENTRIES (0x8au)
#define GOOSE_TAG_ALL_DATA (0xabu)
#define SV_TAG_COUNT (0x80u)
#define SV_TAG_IDENTIFIER (0x80u)
#define SV_TAG_SAMPLE_COUNT (0x82u)
#define SV_TAG_CONFIGURATION_REVISION (0x83u)
#define SV_TAG_SAMPLE_SYNCHRONIZATION (0x85u)
#define SV_TAG_SEQUENCE_DATA (0x87u)
#define GOOSE_BOOLEAN_DATA_TAG (0x83u)
#define SECONDS_PER_MICROSECOND (1.0e-6f)

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

typedef char
    analyzer_batch_size_must_be_four_t[(PICO_ML_BATCH_SIZE_FRAMES ==
                                        EXPECTED_BATCH_FRAME_COUNT)
                                           ? 1
                                                                         : -1];
typedef char analyzer_batch_stride_must_be_two_t
    [(PICO_ML_BATCH_STRIDE_FRAMES == EXPECTED_BATCH_STRIDE) ? 1 : -1];
typedef char analyzer_sv_channel_count_must_be_six_t
    [(PICO_ML_BATCH_SV_CHANNEL_COUNT == EXPECTED_SV_CHANNEL_COUNT) ? 1 : -1];
typedef char analyzer_wave_history_must_be_128_t
    [(PICO_ML_BATCH_WAVE_HISTORY_SAMPLES == EXPECTED_WAVE_HISTORY_SAMPLES) ? 1
                                                                          : -1];
typedef char analyzer_timing_history_must_be_32_t
    [(PICO_ML_BATCH_TIMING_HISTORY_FRAMES == EXPECTED_TIMING_HISTORY_FRAMES) ? 1
                                                                            : -1];

typedef struct
{
    uint16_t        type;
    const uint8_t * data;
    size_t          length;
} ethernet_payload_t;

typedef struct
{
    uint8_t         tag;
    const uint8_t * value;
    size_t          length;
    const uint8_t * next;
} analyzer_tlv_t;

typedef struct
{
    uint16_t        appid;
    const uint8_t * gocb_ref;
    size_t          gocb_ref_length;
    const uint8_t * dataset;
    size_t          dataset_length;
    const uint8_t * go_id;
    size_t          go_id_length;
    const uint8_t * timestamp;
    size_t          timestamp_length;
    const uint8_t * all_data;
    size_t          all_data_length;
    uint32_t        ttl_ms;
    uint32_t        st_num;
    uint32_t        sq_num;
    uint32_t        conf_rev;
    uint32_t        num_entries;
    bool            simulation;
    bool            nds_com;
} goose_fields_t;

typedef struct
{
    const uint8_t * sv_id;
    size_t          sv_id_length;
    uint32_t        smp_cnt;
    uint32_t        conf_rev;
    uint32_t        smp_synch;
    const uint8_t * seq_data;
    size_t          seq_data_length;
} sv_asdu_t;

typedef struct
{
    sv_asdu_t asdus[MAXIMUM_ASDUS];
    uint16_t  appid;
    uint32_t  no_asdu;
    size_t    asdu_count;
} sv_fields_t;

typedef struct
{
    uint8_t  destination_mac[MAC_ADDRESS_LENGTH];
    uint16_t appid;
    size_t   stream_id_length;
    uint8_t  stream_id[MAXIMUM_STREAM_ID_LENGTH];
} stream_identity_t;

typedef struct
{
    bool              used;
    uint32_t          key;
    stream_identity_t identity;
    float             previous_intervals[PICO_ML_BATCH_TIMING_HISTORY_FRAMES];
    size_t            interval_count;
    size_t            interval_next;
    uint64_t          timestamp_us;
    uint32_t          st_num;
    uint32_t          sq_num;
    bool              has_time;
    bool              has_st;
    bool              has_sq;
    bool              has_source;
    bool              has_boolean;
    uint8_t           source[MAC_ADDRESS_LENGTH];
    uint8_t           boolean_value;
    float             batch[PICO_ML_BATCH_SIZE_FRAMES][GOOSE_FEATURE_COUNT];
    size_t            batch_count;
    bool              has_prediction;
    uint8_t           previous_label;
} goose_state_t;

typedef struct
{
    bool              used;
    uint32_t          key;
    stream_identity_t identity;
    float             previous_intervals[PICO_ML_BATCH_TIMING_HISTORY_FRAMES];
    size_t            interval_count;
    size_t            interval_next;
    uint64_t          timestamp_us;
    bool              has_time;
    bool              has_source;
    uint8_t           source[MAC_ADDRESS_LENGTH];
    uint32_t          counters[MAXIMUM_ASDUS];
    bool              has_counter[MAXIMUM_ASDUS];
    float             wave[MAXIMUM_ASDUS][PICO_ML_BATCH_SV_CHANNEL_COUNT]
                          [PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
    uint16_t          wave_count[MAXIMUM_ASDUS][PICO_ML_BATCH_SV_CHANNEL_COUNT];
    uint16_t          wave_next[MAXIMUM_ASDUS][PICO_ML_BATCH_SV_CHANNEL_COUNT];
    float             wave_deltas[PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
    size_t            wave_delta_count;
    size_t            wave_delta_next;
    float             batch[PICO_ML_BATCH_SIZE_FRAMES][SV_FEATURE_COUNT];
    size_t            batch_count;
    bool              has_prediction;
    uint8_t           previous_label;
} sv_state_t;

typedef struct
{
    unsigned int back;
    unsigned int repeat;
    unsigned int gap;
    unsigned int jumps;
    unsigned int flat;
    unsigned int value_count;
    float        delta_max;
    size_t       change_count;
    size_t       previous_wave_count;
    float        robust;
    float        change_sum;
    float        change_max;
    float        ranges[PICO_ML_BATCH_SV_CHANNEL_COUNT];
    float        range_sum;
    float        range_max;
} sv_batch_metrics_t;

static goose_state_t g_goose_states[MAXIMUM_GOOSE_STREAMS];
static sv_state_t    g_sv_states[MAXIMUM_SV_STREAMS];
static uint64_t      g_latest_goose_us;
static uint64_t      g_latest_sv_us;
static bool          g_have_latest_goose;
static bool          g_have_latest_sv;
static uint32_t      g_unsupported_streams;
static uint32_t      g_unsupported_sv_asdu;
static uint32_t      g_malformed_frames;
static bool          g_unsupported_parse;
static float         g_median_scratch[PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
static float         g_timing_scratch[PICO_ML_BATCH_TIMING_HISTORY_FRAMES];
static float         g_sv_changes[MAXIMUM_ASDUS * PICO_ML_BATCH_SV_CHANNEL_COUNT];
static float  g_sv_channel_values[PICO_ML_BATCH_SV_CHANNEL_COUNT][MAXIMUM_ASDUS];
static float  g_sv_history_scratch[PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
static float  g_last_batch_features[SV_BATCH_FEATURE_COUNT];
static size_t g_last_batch_feature_count;
static analyzer_protocol_t g_last_batch_protocol = ANALYZER_PROTOCOL_GOOSE;

static float
maximum_float (float left, float right)
{
    return left > right ? left : right;
}

static float
minimum_float (float left, float right)
{
    return left < right ? left : right;
}

static uint16_t
read_be16 (const uint8_t * value)
{
    return (uint16_t) (((uint32_t) value[0] << BITS_PER_BYTE) |
                       (uint32_t) value[1]);
}

static bool
read_ber_uint (const uint8_t * value, size_t length, uint32_t * output)
{
    size_t   index = 0u;
    bool     has_sign_protection = false;
    uint32_t parsed = 0u;

    if (value == NULL || output == NULL || length == 0u ||
        length > BER_UNSIGNED_INTEGER_MAX_OCTETS)
    {
        return false;
    }
    has_sign_protection = length == BER_UNSIGNED_INTEGER_MAX_OCTETS;
    if (has_sign_protection)
    {
        if (value[0] != 0u)
        {
            return false;
        }
        ++value;
        --length;
    }
    else if ((value[0] & BER_TAG_HIGH_BIT_MASK) != 0u)
    {
        return false;
    }
    for (index = 0u; index < length; ++index)
    {
            parsed = (parsed << BITS_PER_BYTE) | value[index];
    }
    *output = parsed;
    return true;
}

static bool
read_ber_boolean (const uint8_t * value, size_t length, bool * output)
{
    if (value == NULL || output == NULL || length != 1u)
    {
        return false;
    }
    *output = value[0] != 0u;
    return true;
}

static bool
read_tlv (const uint8_t * cursor, const uint8_t * end, analyzer_tlv_t * output)
{
    size_t  available = 0u;
    size_t  length = 0u;
    uint8_t first_length = 0u;

    if (cursor == NULL || end == NULL || output == NULL || end < cursor)
    {
        return false;
    }
    available = (size_t) (end - cursor);
    if (available < BER_TLV_HEADER_SIZE)
    {
        return false;
    }
    output->tag  = *cursor++;
    first_length = *cursor++;
    if ((first_length & BER_TAG_HIGH_BIT_MASK) == 0u)
    {
        length = first_length;
    }
    else
    {
        const size_t octets = (size_t) (first_length & BER_LENGTH_OCTET_MASK);
        size_t       index = 0u;

        if (octets == 0u || octets > BER_MAX_LENGTH_OCTETS ||
            (size_t) (end - cursor) < octets)
        {
            return false;
        }
        for (index = 0u; index < octets; ++index)
        {
            if (length > (SIZE_MAX >> BITS_PER_BYTE))
            {
                return false;
            }
            length = (length << BITS_PER_BYTE) | cursor[index];
        }
        cursor += octets;
    }
    if (end < cursor || length > (size_t) (end - cursor))
    {
        return false;
    }
    output->value  = cursor;
    output->length = length;
    output->next   = cursor + length;
    return true;
}

static bool
find_ethernet_payload (const uint8_t * frame, size_t length,
                       ethernet_payload_t * output)
{
    uint16_t type = 0u;
    size_t   payload_offset = ETHERNET_HEADER_SIZE;
    size_t   tag_count = 0u;

    if (frame == NULL || output == NULL || length < ETHERNET_HEADER_SIZE)
    {
        return false;
    }
    type = read_be16(frame + ETHERNET_TYPE_FIELD_OFFSET);
    for (tag_count = 0u; tag_count < MAXIMUM_VLAN_TAGS &&
                          (type == ETHERNET_VLAN_8021Q_TYPE ||
                           type == ETHERNET_VLAN_8021AD_TYPE ||
                           type == ETHERNET_VLAN_QINQ_TYPE);
         ++tag_count)
    {
        if (payload_offset > length || length - payload_offset < VLAN_TAG_HEADER_SIZE)
        {
            return false;
        }
        type = read_be16(frame + payload_offset + VLAN_TYPE_FIELD_OFFSET);
        payload_offset += VLAN_TAG_HEADER_SIZE;
    }
    output->type   = type;
    output->data   = frame + payload_offset;
    output->length = length - payload_offset;
    return true;
}

static bool
parse_goose_field (const analyzer_tlv_t * field, goose_fields_t * fields,
                   bool * have_ref, bool * have_st_num, bool * have_sq_num)
{
    switch (field->tag)
    {
        case GOOSE_TAG_GOCB_REF:
            fields->gocb_ref        = field->value;
            fields->gocb_ref_length = field->length;
            *have_ref               = true;
            break;
        case GOOSE_TAG_TIME_ALLOWED_TO_LIVE:
            if (!read_ber_uint(field->value, field->length, &fields->ttl_ms))
            {
                return false;
            }
            break;
        case GOOSE_TAG_DATASET:
            fields->dataset        = field->value;
            fields->dataset_length = field->length;
            break;
        case GOOSE_TAG_GO_ID:
            fields->go_id        = field->value;
            fields->go_id_length = field->length;
            break;
        case GOOSE_TAG_TIMESTAMP:
            fields->timestamp        = field->value;
            fields->timestamp_length = field->length;
            break;
        case GOOSE_TAG_STATE_NUMBER:
            if (!read_ber_uint(field->value, field->length, &fields->st_num))
            {
                return false;
            }
            *have_st_num = true;
            break;
        case GOOSE_TAG_SEQUENCE_NUMBER:
            if (!read_ber_uint(field->value, field->length, &fields->sq_num))
            {
                return false;
            }
            *have_sq_num = true;
            break;
        case GOOSE_TAG_SIMULATION:
            if (!read_ber_boolean(field->value, field->length,
                                  &fields->simulation))
            {
                return false;
            }
            break;
        case GOOSE_TAG_CONFIGURATION_REVISION:
            if (!read_ber_uint(field->value, field->length, &fields->conf_rev))
            {
                return false;
            }
            break;
        case GOOSE_TAG_NEEDS_COMMISSIONING:
            if (!read_ber_boolean(field->value, field->length,
                                  &fields->nds_com))
            {
                return false;
            }
            break;
        case GOOSE_TAG_NUMBER_OF_ENTRIES:
            if (!read_ber_uint(field->value, field->length,
                               &fields->num_entries))
            {
                return false;
            }
            break;
        case GOOSE_TAG_ALL_DATA:
            fields->all_data        = field->value;
            fields->all_data_length = field->length;
            break;
        default:
            break;
    }
    return true;
}

static bool
parse_goose (const ethernet_payload_t * payload, goose_fields_t * output)
{
    uint16_t        apdu_length = 0u;
    const uint8_t * end = NULL;
    analyzer_tlv_t  pdu;
    goose_fields_t  fields      = {0};
    bool            have_ref    = false;
    bool            have_st_num = false;
    bool            have_sq_num = false;
    const uint8_t * cursor = NULL;
    const uint8_t * pdu_end = NULL;

    if (payload == NULL || output == NULL ||
        payload->length < IEC61850_APDU_MINIMUM_LENGTH)
    {
        return false;
    }
    apdu_length = read_be16(payload->data + IEC61850_APDU_LENGTH_OFFSET);
    if (apdu_length < IEC61850_APDU_MINIMUM_LENGTH ||
        apdu_length > payload->length)
    {
        return false;
    }
    end = payload->data + apdu_length;
    if (!read_tlv(payload->data + IEC61850_APDU_OFFSET, end, &pdu) ||
        pdu.tag != GOOSE_APDU_TAG)
    {
        return false;
    }
    fields.appid = read_be16(payload->data);
    cursor       = pdu.value;
    pdu_end      = pdu.value + pdu.length;
    while (cursor < pdu_end)
    {
        analyzer_tlv_t field;
        if (!read_tlv(cursor, pdu_end, &field))
        {
            return false;
        }
        if (!parse_goose_field(&field, &fields, &have_ref, &have_st_num,
                               &have_sq_num))
        {
            return false;
        }
        cursor = field.next;
    }
    if (!have_ref || !have_st_num || !have_sq_num)
    {
        return false;
    }
    *output = fields;
    return true;
}

static bool
parse_sv_asdu (const analyzer_tlv_t * raw, sv_asdu_t * asdu)
{
    bool            have_id = false;
    bool            have_count_field = false;
    const uint8_t * field_cursor = raw->value;
    const uint8_t * raw_end = raw->value + raw->length;

    if (raw->tag != BER_SEQUENCE_TAG)
    {
        return false;
    }
    while (field_cursor < raw_end)
    {
        analyzer_tlv_t field;
        if (!read_tlv(field_cursor, raw_end, &field))
        {
            return false;
        }
        if (field.tag == SV_TAG_IDENTIFIER)
        {
            asdu->sv_id        = field.value;
            asdu->sv_id_length = field.length;
            have_id            = true;
        }
        else if (field.tag == SV_TAG_SAMPLE_COUNT)
        {
            if (!read_ber_uint(field.value, field.length, &asdu->smp_cnt))
            {
                return false;
            }
            have_count_field = true;
        }
        else if (field.tag == SV_TAG_CONFIGURATION_REVISION)
        {
            if (!read_ber_uint(field.value, field.length, &asdu->conf_rev))
            {
                return false;
            }
        }
        else if (field.tag == SV_TAG_SAMPLE_SYNCHRONIZATION)
        {
            if (!read_ber_uint(field.value, field.length, &asdu->smp_synch))
            {
                return false;
            }
        }
        else if (field.tag == SV_TAG_SEQUENCE_DATA)
        {
            asdu->seq_data        = field.value;
            asdu->seq_data_length = field.length;
        }
        field_cursor = field.next;
    }
    return have_id && have_count_field && asdu->seq_data != NULL;
}

static bool
parse_sv (const ethernet_payload_t * payload, sv_fields_t * output)
{
    uint16_t        apdu_length = 0u;
    const uint8_t * end = NULL;
    analyzer_tlv_t  apdu;
    sv_fields_t     fields          = {0};
    bool            have_count      = false;
    const uint8_t * sequence        = NULL;
    size_t          sequence_length = 0u;
    const uint8_t * cursor = NULL;
    const uint8_t * apdu_end = NULL;

    g_unsupported_parse = false;
    if (payload == NULL || output == NULL ||
        payload->length < IEC61850_APDU_MINIMUM_LENGTH)
    {
        return false;
    }
    apdu_length = read_be16(payload->data + IEC61850_APDU_LENGTH_OFFSET);
    if (apdu_length < IEC61850_APDU_MINIMUM_LENGTH ||
        apdu_length > payload->length)
    {
        return false;
    }
    end = payload->data + apdu_length;
    if (!read_tlv(payload->data + IEC61850_APDU_OFFSET, end, &apdu) ||
        apdu.tag != SV_APDU_TAG)
    {
        return false;
    }
    fields.appid = read_be16(payload->data);
    cursor       = apdu.value;
    apdu_end     = apdu.value + apdu.length;
    while (cursor < apdu_end)
    {
        analyzer_tlv_t field;
        if (!read_tlv(cursor, apdu_end, &field))
        {
            return false;
        }
        if (field.tag == SV_TAG_COUNT)
        {
            if (!read_ber_uint(field.value, field.length, &fields.no_asdu))
            {
                return false;
            }
            have_count = true;
        }
        else if (field.tag == SV_SEQUENCE_TAG)
        {
            sequence        = field.value;
            sequence_length = field.length;
        }
        cursor = field.next;
    }
    if (!have_count || fields.no_asdu == 0u ||
        fields.no_asdu > MAXIMUM_ENCODED_ASDU_COUNT ||
        sequence == NULL)
    {
        return false;
    }
    if (fields.no_asdu > MAXIMUM_ASDUS)
    {
        ++g_unsupported_sv_asdu;
        g_unsupported_parse = true;
        return false;
    }
    cursor = sequence;
    while (cursor < sequence + sequence_length)
    {
        analyzer_tlv_t  raw;
        if (!read_tlv(cursor, sequence + sequence_length, &raw) ||
            raw.tag != BER_SEQUENCE_TAG || fields.asdu_count >= MAXIMUM_ASDUS)
        {
            return false;
        }
        if (!parse_sv_asdu(&raw, &fields.asdus[fields.asdu_count]))
        {
            return false;
        }
        ++fields.asdu_count;
        cursor = raw.next;
    }
    if (fields.asdu_count != fields.no_asdu)
    {
        return false;
    }
    *output = fields;
    return true;
}

static uint32_t
batch_hash (uint16_t appid, const uint8_t * stream_id, size_t stream_id_length,
            const uint8_t * destination)
{
    uint32_t hash = UINT32_C(2166136261);
    size_t   index = 0u;

    for (index = 0u; index < MAC_ADDRESS_LENGTH; ++index)
    {
        hash = (hash ^ destination[index]) * UINT32_C(16777619);
    }
    hash = (hash ^ (uint8_t) (appid >> BITS_PER_BYTE)) * UINT32_C(16777619);
    hash = (hash ^ (uint8_t) appid) * UINT32_C(16777619);
    for (index = 0u; index < stream_id_length; ++index)
    {
        hash = (hash ^ stream_id[index]) * UINT32_C(16777619);
    }
    return hash;
}

static bool
identity_matches (const stream_identity_t * identity, uint16_t appid,
                  const uint8_t * stream_id, size_t stream_id_length,
                  const uint8_t * destination)
{
    return identity->appid == appid &&
           identity->stream_id_length == stream_id_length &&
           memcmp(identity->destination_mac, destination, MAC_ADDRESS_LENGTH) ==
               0 &&
           (stream_id_length == 0u ||
            memcmp(identity->stream_id, stream_id, stream_id_length) == 0);
}

static goose_state_t *
goose_state_for (uint16_t appid, const uint8_t * stream_id,
                 size_t stream_id_length, const uint8_t * destination,
                 uint32_t key)
{
    goose_state_t * free_state = NULL;
    size_t          index = 0u;

    if (stream_id == NULL)
    {
        return NULL;
    }
    if (stream_id_length > MAXIMUM_STREAM_ID_LENGTH)
    {
        ++g_unsupported_streams;
        return NULL;
    }
    for (index = 0u; index < MAXIMUM_GOOSE_STREAMS; ++index)
    {
        goose_state_t * state = &g_goose_states[index];
        if (state->used && identity_matches(&state->identity, appid, stream_id,
                                            stream_id_length, destination))
        {
            return state;
        }
        if (!state->used && free_state == NULL)
        {
            free_state = state;
        }
    }
    if (free_state == NULL)
    {
        ++g_unsupported_streams;
        return NULL;
    }
    memset(free_state, 0, sizeof(*free_state));
    free_state->used                      = true;
    free_state->key                       = key;
    free_state->identity.appid            = appid;
    free_state->identity.stream_id_length = stream_id_length;
    memcpy(free_state->identity.destination_mac, destination,
           MAC_ADDRESS_LENGTH);
    if (stream_id_length != 0u)
    {
        memcpy(free_state->identity.stream_id, stream_id, stream_id_length);
    }
    return free_state;
}

static sv_state_t *
sv_state_for (uint16_t appid, const uint8_t * stream_id,
              size_t stream_id_length, const uint8_t * destination,
              uint32_t key)
{
    sv_state_t * free_state = NULL;
    size_t       index = 0u;

    if (stream_id == NULL)
    {
        return NULL;
    }
    if (stream_id_length > MAXIMUM_STREAM_ID_LENGTH)
    {
        ++g_unsupported_streams;
        return NULL;
    }
    for (index = 0u; index < MAXIMUM_SV_STREAMS; ++index)
    {
        sv_state_t * state = &g_sv_states[index];
        if (state->used && identity_matches(&state->identity, appid, stream_id,
                                            stream_id_length, destination))
        {
            return state;
        }
        if (!state->used && free_state == NULL)
        {
            free_state = state;
        }
    }
    if (free_state == NULL)
    {
        ++g_unsupported_streams;
        return NULL;
    }
    memset(free_state, 0, sizeof(*free_state));
    free_state->used                      = true;
    free_state->key                       = key;
    free_state->identity.appid            = appid;
    free_state->identity.stream_id_length = stream_id_length;
    memcpy(free_state->identity.destination_mac, destination,
           MAC_ADDRESS_LENGTH);
    if (stream_id_length != 0u)
    {
        memcpy(free_state->identity.stream_id, stream_id, stream_id_length);
    }
    return free_state;
}

static float
select_median_upper (size_t count, size_t target)
{
    size_t left  = 0u;
    size_t right = count - 1u;

    while (left < right)
    {
        const float pivot =
            g_median_scratch[left + ((right - left) / INTEGER_MIDPOINT_DIVISOR)];
        size_t      lower = left;
        size_t      upper = right;

        while (lower <= upper)
        {
            while (lower <= right && g_median_scratch[lower] < pivot)
            {
                ++lower;
            }
            while (g_median_scratch[upper] > pivot)
            {
                if (upper == 0u)
                {
                    break;
                }
                --upper;
            }
            if (lower <= upper)
            {
                const float temporary = g_median_scratch[lower];
                g_median_scratch[lower] = g_median_scratch[upper];
                g_median_scratch[upper] = temporary;
                ++lower;
                if (upper == 0u)
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
            break;
        }
    }
    return g_median_scratch[target];
}

static float
batch_median (const float * values, size_t count)
{
    size_t index = 0u;

    if (count > PICO_ML_BATCH_WAVE_HISTORY_SAMPLES)
    {
        count = PICO_ML_BATCH_WAVE_HISTORY_SAMPLES;
    }
    if (count == 0u || values == NULL)
    {
        return 0.0f;
    }
    memcpy(g_median_scratch, values, count * sizeof(float));
    if ((count & 1u) != 0u)
    {
        return select_median_upper(count, count / INTEGER_MIDPOINT_DIVISOR);
    }
    {
        const size_t middle = count / INTEGER_MIDPOINT_DIVISOR;
        const float  upper  = select_median_upper(count, middle);
        float        lower  = g_median_scratch[0];
        for (index = 1u; index < middle; ++index)
        {
            lower = maximum_float(lower, g_median_scratch[index]);
        }
        return (lower + upper) * FLOAT_MIDPOINT_RATIO;
    }
}

static float
ring_median (const float * values, size_t capacity, size_t count, size_t next)
{
    size_t index = 0u;

    if (count > capacity || capacity > PICO_ML_BATCH_TIMING_HISTORY_FRAMES)
    {
        return 0.0f;
    }
    for (index = 0u; index < count; ++index)
    {
        g_timing_scratch[index] =
            values[(next + capacity - count + index) % capacity];
    }
    return batch_median(g_timing_scratch, count);
}

static void
push_time (float * values, size_t capacity, size_t * count, size_t * next,
           float interval)
{
    if (values == NULL || count == NULL || next == NULL || capacity == 0u ||
        *next >= capacity)
    {
        return;
    }
    values[*next] = interval;
    *next         = (*next + 1u) % capacity;
    if (*count < capacity)
    {
        ++(*count);
    }
}

static void
predict_batch (float * batch, size_t feature_count, size_t * batch_count,
               const float * frame, analyzer_result_t * result,
               uint8_t * previous_label, bool * has_prediction, float threshold,
               float (*predict)(const float *), size_t output_count)
{
    float  output[SV_BATCH_FEATURE_COUNT];
    size_t feature = 0u;
    size_t frame_index = 0u;

    if (batch == NULL || batch_count == NULL || frame == NULL ||
        result == NULL || previous_label == NULL || has_prediction == NULL ||
        predict == NULL || feature_count == 0u ||
        feature_count > SV_FEATURE_COUNT ||
        *batch_count >= PICO_ML_BATCH_SIZE_FRAMES)
    {
        return;
    }
    memcpy(batch + (*batch_count * feature_count), frame,
           feature_count * sizeof(float));
    ++(*batch_count);
    if (*batch_count < PICO_ML_BATCH_SIZE_FRAMES)
    {
        result->warmup_remaining =
            (uint8_t) (PICO_ML_BATCH_SIZE_FRAMES - *batch_count);
        return;
    }
    if (output_count > SV_BATCH_FEATURE_COUNT ||
        output_count != feature_count * BATCH_FEATURES_PER_METRIC)
    {
        *batch_count = 0u;
        return;
    }
    for (feature = 0u; feature < feature_count; ++feature)
    {
        float        sum               = 0.0f;
        float        maximum           = batch[feature];
        float        squared_delta_sum = 0.0f;
        const size_t mean_index = feature * BATCH_FEATURES_PER_METRIC;

        for (frame_index = 0u; frame_index < PICO_ML_BATCH_SIZE_FRAMES;
             ++frame_index)
        {
            const float value = batch[frame_index * feature_count + feature];
            sum += value;
            maximum = maximum_float(maximum, value);
        }
        output[feature * BATCH_FEATURES_PER_METRIC] =
            sum / (float) PICO_ML_BATCH_SIZE_FRAMES;
        output[feature * BATCH_FEATURES_PER_METRIC + 1u] = maximum;
        output[feature * BATCH_FEATURES_PER_METRIC + BYTE_OFFSET_TWO] =
            batch[(PICO_ML_BATCH_SIZE_FRAMES - 1u) * feature_count + feature];
        for (frame_index = 0u; frame_index < PICO_ML_BATCH_SIZE_FRAMES;
             ++frame_index)
        {
            const float delta = batch[frame_index * feature_count + feature] -
                                output[mean_index];
            squared_delta_sum += delta * delta;
        }
        output[feature * BATCH_FEATURES_PER_METRIC + BYTE_OFFSET_THREE] =
            sqrtf(squared_delta_sum / (float) PICO_ML_BATCH_SIZE_FRAMES);
    }
    {
        const float   probability = predict(output);
        const uint8_t label       = probability >= threshold ? 1u : 0u;
        memcpy(g_last_batch_features, output, output_count * sizeof(float));
        g_last_batch_feature_count    = output_count;
        g_last_batch_protocol         = result->protocol;
        result->prediction_ready    = true;
        result->primary_probability = probability;
        result->primary_label       = label;
        result->label_changed = !*has_prediction || label != *previous_label;
        *has_prediction       = true;
        *previous_label       = label;
    }
    *batch_count -= PICO_ML_BATCH_STRIDE_FRAMES;
    for (frame_index = 0u; frame_index < *batch_count; ++frame_index)
    {
        memmove(batch + frame_index * feature_count,
                batch +
                    (frame_index + PICO_ML_BATCH_STRIDE_FRAMES) * feature_count,
                feature_count * sizeof(float));
    }
}

static void
printable (char * output, size_t capacity, const uint8_t * input,
           size_t input_length)
{
    size_t copy_length = 0u;
    size_t index = 0u;

    if (output == NULL || capacity == 0u)
    {
        return;
    }
    copy_length = input == NULL ? 0u : input_length;
    if (copy_length >= capacity)
    {
        copy_length = capacity - 1u;
    }
    for (index = 0u; index < copy_length; ++index)
    {
        output[index] = (input[index] >= ASCII_PRINTABLE_MINIMUM &&
                         input[index] < ASCII_PRINTABLE_MAXIMUM)
                            ? (char) input[index]
                            : '.';
    }
    output[copy_length] = '\0';
}

static void
wave_push (float * values, uint16_t * count, uint16_t * next, float value)
{
    if (values == NULL || count == NULL || next == NULL ||
        *next >= PICO_ML_BATCH_WAVE_HISTORY_SAMPLES)
    {
        return;
    }
    values[*next] = value;
    *next = (uint16_t) ((*next + 1u) % PICO_ML_BATCH_WAVE_HISTORY_SAMPLES);
    if (*count < PICO_ML_BATCH_WAVE_HISTORY_SAMPLES)
    {
        ++(*count);
    }
}

static uint32_t
read_be32_float_bits (const uint8_t * value)
{
    return ((uint32_t) value[0] << (BITS_PER_BYTE * BYTE_OFFSET_THREE)) |
           ((uint32_t) value[1] << (BITS_PER_BYTE * BYTE_OFFSET_TWO)) |
           ((uint32_t) value[BYTE_OFFSET_TWO] << BITS_PER_BYTE) |
           (uint32_t) value[BYTE_OFFSET_THREE];
}

static float
float_from_bits (uint32_t bits)
{
    float value = 0.0f;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static float
goose_predict (const float * features)
{
    return pico_ml_batch_predict_goose(features);
}

static float
sv_predict (const float * features)
{
    return pico_ml_batch_predict_sv(features);
}

static void
populate_goose_result (const goose_fields_t * fields, uint32_t key,
                       analyzer_result_t * result)
{
    memset(result, 0, sizeof(*result));
    result->protocol   = ANALYZER_PROTOCOL_GOOSE;
    result->appid      = fields->appid;
    result->stream_key = key;
    result->counter_1  = fields->st_num;
    result->counter_2  = fields->sq_num;
    printable(result->goose_gocb_ref, sizeof(result->goose_gocb_ref),
              fields->gocb_ref, fields->gocb_ref_length);
    printable(result->goose_dataset, sizeof(result->goose_dataset),
              fields->dataset, fields->dataset_length);
    printable(result->goose_go_id, sizeof(result->goose_go_id), fields->go_id,
              fields->go_id_length);
    result->goose_ttl_ms      = fields->ttl_ms;
    result->goose_conf_rev    = fields->conf_rev;
    result->goose_num_entries = fields->num_entries;
    result->goose_simulation  = fields->simulation;
    result->goose_nds_com     = fields->nds_com;
    if (fields->timestamp != NULL && fields->timestamp_length != 0u)
    {
        const size_t copy_length =
            fields->timestamp_length < sizeof(result->goose_timestamp)
                ? fields->timestamp_length
                : sizeof(result->goose_timestamp);
        memcpy(result->goose_timestamp, fields->timestamp, copy_length);
        result->goose_timestamp_length = (uint8_t) copy_length;
    }
    if (fields->all_data != NULL)
    {
        const size_t copy_length =
            fields->all_data_length < sizeof(result->goose_all_data_preview)
                ? fields->all_data_length
                : sizeof(result->goose_all_data_preview);
        result->goose_all_data_length =
            fields->all_data_length > UINT16_MAX
                ? UINT16_MAX
                : (uint16_t) fields->all_data_length;
        memcpy(result->goose_all_data_preview, fields->all_data, copy_length);
        result->goose_all_data_preview_length = (uint8_t) copy_length;
    }
}

static bool
read_goose_boolean (const goose_fields_t * fields, bool * value)
{
    analyzer_tlv_t data_field;

    if (fields->all_data == NULL || fields->all_data_length == 0u ||
        !read_tlv(fields->all_data,
                  fields->all_data + fields->all_data_length, &data_field) ||
        data_field.tag != GOOSE_BOOLEAN_DATA_TAG || data_field.length == 0u)
    {
        return false;
    }
    *value = data_field.value[data_field.length - 1u] != 0u;
    return true;
}

static void
calculate_goose_features (goose_state_t * state,
                          const goose_fields_t * fields,
                          const uint8_t * source, uint64_t timestamp_us,
                          float features[GOOSE_FEATURE_COUNT],
                          float * delta_seconds_out, bool * boolean_valid_out,
                          bool * boolean_value_out)
{
    const bool boolean_valid = read_goose_boolean(fields, boolean_value_out);
    const float delta_seconds =
        state->has_time
            ? (float) (timestamp_us - state->timestamp_us) *
                  SECONDS_PER_MICROSECOND
            : 0.0f;
    const float prior_interval =
        ring_median(state->previous_intervals,
                    PICO_ML_BATCH_TIMING_HISTORY_FRAMES, state->interval_count,
                    state->interval_next);
    const float ratio = prior_interval > 0.0f ? delta_seconds / prior_interval
                                               : 1.0f;
    const bool source_changed =
        state->has_source && memcmp(state->source, source, MAC_ADDRESS_LENGTH) != 0;
    const int64_t st_delta = state->has_st
                                 ? (int64_t) fields->st_num -
                                       (int64_t) state->st_num
                                 : 0;
    const int64_t sequence_delta = state->has_sq &&
                                           fields->st_num == state->st_num
                                       ? (int64_t) fields->sq_num -
                                             (int64_t) state->sq_num
                                       : 0;
    float age_seconds = PICO_ML_BATCH_TIMING_MISSING_AGE_SECONDS;

    if (g_have_latest_sv && timestamp_us >= g_latest_sv_us)
    {
        age_seconds =
            (float) (timestamp_us - g_latest_sv_us) * SECONDS_PER_MICROSECOND;
    }
    else if (g_have_latest_sv)
    {
        age_seconds = 0.0f;
    }
    features[GOOSE_FEATURE_INTERVAL_SECONDS] = delta_seconds;
    features[GOOSE_FEATURE_INTERVAL_RATIO] = ratio;
    features[GOOSE_FEATURE_ST_NUMBER_DELTA] = fabsf((float) st_delta);
    features[GOOSE_FEATURE_ST_NUMBER_ROLLBACK] = st_delta < 0 ? 1.0f : 0.0f;
    features[GOOSE_FEATURE_ST_NUMBER_JUMP] =
        st_delta > PICO_ML_BATCH_COUNTER_MAX_STNUM_STEP ? 1.0f : 0.0f;
    features[GOOSE_FEATURE_SQ_NUMBER_DELTA] = fabsf((float) sequence_delta);
    features[GOOSE_FEATURE_SQ_NUMBER_ROLLBACK] =
        sequence_delta < 0 ? 1.0f : 0.0f;
    features[GOOSE_FEATURE_SOURCE_CHANGED] = source_changed ? 1.0f : 0.0f;
    features[GOOSE_FEATURE_HISTORY_AVAILABLE] =
        state->has_time && state->has_st ? 1.0f : 0.0f;
    features[GOOSE_FEATURE_SV_AGE_SECONDS] = age_seconds;
    features[GOOSE_FEATURE_BOOLEAN_VALUE] =
        boolean_valid && *boolean_value_out ? 1.0f : 0.0f;
    features[GOOSE_FEATURE_BOOLEAN_MISSING] = boolean_valid ? 0.0f : 1.0f;
    features[GOOSE_FEATURE_BOOLEAN_CHANGED] =
        state->has_boolean && boolean_valid &&
                state->boolean_value != (uint8_t) *boolean_value_out
            ? 1.0f
            : 0.0f;
    *delta_seconds_out  = delta_seconds;
    *boolean_valid_out  = boolean_valid;
}

static void
update_goose_state (goose_state_t * state, const goose_fields_t * fields,
                    const uint8_t * source, uint64_t timestamp_us,
                    float delta_seconds, bool boolean_valid,
                    bool boolean_value)
{
    if (state->has_time && delta_seconds > 0.0f)
    {
        push_time(state->previous_intervals,
                  PICO_ML_BATCH_TIMING_HISTORY_FRAMES, &state->interval_count,
                  &state->interval_next, delta_seconds);
    }
    state->timestamp_us = timestamp_us;
    state->has_time     = true;
    state->st_num       = fields->st_num;
    state->sq_num       = fields->sq_num;
    state->has_st       = true;
    state->has_sq       = true;
    memcpy(state->source, source, MAC_ADDRESS_LENGTH);
    state->has_source = true;
    if (boolean_valid)
    {
        state->boolean_value = (uint8_t) boolean_value;
        state->has_boolean   = true;
    }
    g_latest_goose_us   = timestamp_us;
    g_have_latest_goose = true;
}

static bool
process_goose_batch (const uint8_t * source, const uint8_t * destination,
                     const goose_fields_t * fields, uint64_t timestamp_us,
                     analyzer_result_t * result)
{
    const uint32_t  key = batch_hash(fields->appid, fields->gocb_ref,
                                     fields->gocb_ref_length, destination);
    goose_state_t * state =
        goose_state_for(fields->appid, fields->gocb_ref,
                        fields->gocb_ref_length, destination, key);
    float   features[GOOSE_FEATURE_COUNT];
    float   delta_seconds = 0.0f;
    bool    boolean_valid = false;
    bool    boolean_value = false;
    size_t  feature_index = 0u;

    if (state == NULL)
    {
        if (!g_have_latest_goose || timestamp_us > g_latest_goose_us)
        {
            g_latest_goose_us = timestamp_us;
        }
        g_have_latest_goose = true;
        return false;
    }
    if (state->has_time && timestamp_us < state->timestamp_us)
    {
        ++g_malformed_frames;
        return false;
    }
    populate_goose_result(fields, key, result);
    calculate_goose_features(state, fields, source, timestamp_us, features,
                             &delta_seconds, &boolean_valid, &boolean_value);
    update_goose_state(state, fields, source, timestamp_us, delta_seconds,
                       boolean_valid, boolean_value);

    predict_batch(&state->batch[0][0], GOOSE_FEATURE_COUNT, &state->batch_count,
                  features, result, &state->previous_label,
                  &state->has_prediction, PICO_ML_BATCH_GOOSE_THRESHOLD,
                  goose_predict, GOOSE_BATCH_FEATURE_COUNT);
    result->feature_count = ANALYZER_FEATURE_CAPACITY;
    for (feature_index = 0u; feature_index < ANALYZER_FEATURE_CAPACITY;
         ++feature_index)
    {
        result->features[feature_index] = features[feature_index];
    }
    return true;
}

static bool
validate_sv_payload (const sv_fields_t * fields, size_t * required_length)
{
    size_t channel = 0u;
    size_t maximum_length = 0u;
    size_t asdu_index = 0u;

    if (fields == NULL || required_length == NULL || fields->asdu_count == 0u ||
        fields->asdu_count > MAXIMUM_ASDUS)
    {
        return false;
    }
    for (channel = 0u; channel < PICO_ML_BATCH_SV_CHANNEL_COUNT; ++channel)
    {
        const size_t channel_end =
            (size_t) g_pico_ml_batch_sv_channel_offsets[channel] + FLOAT32_SIZE;
        if (channel_end > maximum_length)
        {
            maximum_length = channel_end;
        }
    }
    for (asdu_index = 0u; asdu_index < fields->asdu_count; ++asdu_index)
    {
        const sv_asdu_t * asdu = &fields->asdus[asdu_index];
        if (asdu->seq_data == NULL || asdu->seq_data_length < maximum_length)
        {
            return false;
        }
        for (channel = 0u; channel < PICO_ML_BATCH_SV_CHANNEL_COUNT; ++channel)
        {
            const size_t offset = g_pico_ml_batch_sv_channel_offsets[channel];
            if (!isfinite(float_from_bits(
                    read_be32_float_bits(asdu->seq_data + offset))))
            {
                return false;
            }
        }
    }
    *required_length = maximum_length;
    return true;
}

static void
collect_sv_samples (sv_state_t * state, const sv_fields_t * fields,
                    sv_batch_metrics_t * metrics)
{
    size_t asdu_index = 0u;
    size_t channel = 0u;

    memset(g_sv_changes, 0, sizeof(g_sv_changes));
    memset(g_sv_channel_values, 0, sizeof(g_sv_channel_values));
    memset(g_sv_history_scratch, 0, sizeof(g_sv_history_scratch));
    for (asdu_index = 0u; asdu_index < fields->asdu_count; ++asdu_index)
    {
        const sv_asdu_t * asdu = &fields->asdus[asdu_index];
        if (state->has_counter[asdu_index])
        {
            int64_t counter_delta =
                (int64_t) (asdu->smp_cnt - state->counters[asdu_index]);
            if (counter_delta > INT32_MAX)
            {
                counter_delta -= INT64_C(4294967296);
            }
            const float absolute_delta = fabsf((float) counter_delta);
            metrics->delta_max = maximum_float(metrics->delta_max, absolute_delta);
            metrics->back += counter_delta < 0 ? 1u : 0u;
            metrics->repeat += counter_delta == 0 ? 1u : 0u;
            metrics->gap += absolute_delta >
                                    PICO_ML_BATCH_COUNTER_MAX_SMP_DELTA
                                ? 1u
                                : 0u;
        }
        state->counters[asdu_index]    = asdu->smp_cnt;
        state->has_counter[asdu_index] = true;
        for (channel = 0u; channel < PICO_ML_BATCH_SV_CHANNEL_COUNT; ++channel)
        {
            const size_t offset = g_pico_ml_batch_sv_channel_offsets[channel];
            const float current =
                float_from_bits(read_be32_float_bits(asdu->seq_data + offset));
            const uint16_t history_count =
                state->wave_count[asdu_index][channel];
            const uint16_t next = state->wave_next[asdu_index][channel];
            g_sv_channel_values[channel][asdu_index] = current;
            if (history_count != 0u)
            {
                size_t history_index = 0u;
                float baseline = 0.0f;
                float relative_change = 0.0f;
                for (history_index = 0u; history_index < history_count;
                     ++history_index)
                {
                    g_sv_history_scratch[history_index] =
                        state->wave[asdu_index][channel]
                                   [(next + PICO_ML_BATCH_WAVE_HISTORY_SAMPLES -
                                     history_count + history_index) %
                                    PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
                }
                baseline = batch_median(g_sv_history_scratch, history_count);
                relative_change =
                    fabsf(current - baseline) /
                    maximum_float(
                        maximum_float(fabsf(baseline),
                                      g_pico_ml_batch_sv_relative_scale[channel]),
                        PICO_ML_BATCH_WAVE_EPSILON);
                g_sv_changes[metrics->change_count++] = relative_change;
                metrics->jumps +=
                    relative_change >= PICO_ML_BATCH_WAVE_RELATIVE_JUMP_LIMIT
                        ? 1u
                        : 0u;
                metrics->flat +=
                    relative_change <= PICO_ML_BATCH_WAVE_PLATEAU_RELATIVE_LIMIT
                        ? 1u
                        : 0u;
                ++metrics->value_count;
            }
            wave_push(&state->wave[asdu_index][channel][0],
                      &state->wave_count[asdu_index][channel],
                      &state->wave_next[asdu_index][channel], current);
        }
    }
}

static void
summarize_sv_history (sv_state_t * state, sv_batch_metrics_t * metrics)
{
    size_t history_index = 0u;

    metrics->previous_wave_count = state->wave_delta_count;
    for (history_index = 0u; history_index < state->wave_delta_count;
         ++history_index)
    {
        g_sv_history_scratch[history_index] =
            state->wave_deltas[(state->wave_delta_next +
                                PICO_ML_BATCH_WAVE_HISTORY_SAMPLES -
                                state->wave_delta_count + history_index) %
                               PICO_ML_BATCH_WAVE_HISTORY_SAMPLES];
    }
    metrics->robust = batch_median(g_sv_history_scratch, state->wave_delta_count);
    for (history_index = 0u; history_index < metrics->change_count;
         ++history_index)
    {
        metrics->change_sum += g_sv_changes[history_index];
        metrics->change_max =
            maximum_float(metrics->change_max, g_sv_changes[history_index]);
        state->wave_deltas[state->wave_delta_next] = g_sv_changes[history_index];
        state->wave_delta_next =
            (state->wave_delta_next + 1u) % PICO_ML_BATCH_WAVE_HISTORY_SAMPLES;
        if (state->wave_delta_count < PICO_ML_BATCH_WAVE_HISTORY_SAMPLES)
        {
            ++state->wave_delta_count;
        }
    }
}

static void
calculate_sv_channel_ranges (size_t asdu_count, sv_batch_metrics_t * metrics)
{
    size_t channel = 0u;
    size_t asdu_index = 0u;

    for (channel = 0u; channel < PICO_ML_BATCH_SV_CHANNEL_COUNT; ++channel)
    {
        float channel_values[MAXIMUM_ASDUS];
        float center = 0.0f;
        float low = 0.0f;
        float high = 0.0f;
        for (asdu_index = 0u; asdu_index < asdu_count; ++asdu_index)
        {
            channel_values[asdu_index] = g_sv_channel_values[channel][asdu_index];
        }
        center = fabsf(batch_median(channel_values, asdu_count));
        low    = channel_values[0];
        high   = channel_values[0];
        for (asdu_index = 1u; asdu_index < asdu_count; ++asdu_index)
        {
            low  = minimum_float(low, channel_values[asdu_index]);
            high = maximum_float(high, channel_values[asdu_index]);
        }
        metrics->ranges[channel] =
            (high - low) /
            maximum_float(
                maximum_float(center, g_pico_ml_batch_sv_relative_scale[channel]),
                PICO_ML_BATCH_WAVE_EPSILON);
        metrics->range_sum += metrics->ranges[channel];
        metrics->range_max = maximum_float(metrics->range_max,
                                           metrics->ranges[channel]);
    }
}

static void
calculate_sv_features (const sv_state_t * state, const sv_fields_t * fields,
                       const uint8_t * source, uint64_t timestamp_us,
                       float delta_seconds, float ratio,
                       const sv_batch_metrics_t * metrics,
                       float features[SV_FEATURE_COUNT])
{
    float age_seconds = PICO_ML_BATCH_TIMING_MISSING_AGE_SECONDS;

    if (g_have_latest_goose && timestamp_us >= g_latest_goose_us)
    {
        age_seconds =
            (float) (timestamp_us - g_latest_goose_us) * SECONDS_PER_MICROSECOND;
    }
    else if (g_have_latest_goose)
    {
        age_seconds = 0.0f;
    }
    features[SV_FEATURE_INTERVAL_SECONDS] = delta_seconds;
    features[SV_FEATURE_INTERVAL_RATIO] = ratio;
    features[SV_FEATURE_GOOSE_AGE_SECONDS] = age_seconds;
    features[SV_FEATURE_ASDU_COUNT] = (float) fields->no_asdu;
    features[SV_FEATURE_COUNTER_BACK] = (float) metrics->back;
    features[SV_FEATURE_COUNTER_REPEAT] = (float) metrics->repeat;
    features[SV_FEATURE_COUNTER_GAP] = (float) metrics->gap;
    features[SV_FEATURE_COUNTER_DELTA_MAXIMUM] = metrics->delta_max;
    features[SV_FEATURE_WAVE_RELATIVE_CHANGE_MEAN] =
        metrics->change_count != 0u
            ? metrics->change_sum / (float) metrics->change_count
            : 0.0f;
    features[SV_FEATURE_WAVE_RELATIVE_CHANGE_MAXIMUM] = metrics->change_max;
    features[SV_FEATURE_WAVE_JUMP_FRACTION] =
        metrics->value_count != 0u
            ? (float) metrics->jumps / (float) metrics->value_count
            : 0.0f;
    features[SV_FEATURE_WAVE_PLATEAU_FRACTION] =
        metrics->value_count != 0u
            ? (float) metrics->flat / (float) metrics->value_count
            : 0.0f;
    features[SV_FEATURE_WAVE_JUMP_COUNT] = (float) metrics->jumps;
    features[SV_FEATURE_WAVE_HISTORY_COVERAGE] =
        minimum_float(1.0f, (float) metrics->previous_wave_count /
                                (float) PICO_ML_BATCH_WAVE_HISTORY_MIN_SAMPLES);
    features[SV_FEATURE_WAVE_ROBUST_RATIO] = minimum_float(
        PICO_ML_BATCH_WAVE_ROBUST_RATIO_CAP,
        metrics->change_max /
            maximum_float(metrics->robust, PICO_ML_BATCH_WAVE_EPSILON));
    features[SV_FEATURE_CHANNEL_RANGE_MEAN] =
        metrics->range_sum / (float) PICO_ML_BATCH_SV_CHANNEL_COUNT;
    features[SV_FEATURE_CHANNEL_RANGE_MAXIMUM] = metrics->range_max;
    features[SV_FEATURE_SOURCE_CHANGED] =
        state->has_source && memcmp(state->source, source, MAC_ADDRESS_LENGTH) != 0
            ? 1.0f
            : 0.0f;
}

static void
update_sv_state (sv_state_t * state, const uint8_t * source,
                 uint64_t timestamp_us, float delta_seconds)
{
    if (state->has_time && delta_seconds > 0.0f)
    {
        push_time(state->previous_intervals,
                  PICO_ML_BATCH_TIMING_HISTORY_FRAMES, &state->interval_count,
                  &state->interval_next, delta_seconds);
    }
    state->timestamp_us = timestamp_us;
    state->has_time     = true;
    memcpy(state->source, source, MAC_ADDRESS_LENGTH);
    state->has_source = true;
    g_latest_sv_us    = timestamp_us;
    g_have_latest_sv  = true;
}

static bool
process_sv_batch (const uint8_t * source, const uint8_t * destination,
                  const sv_fields_t * fields, uint64_t timestamp_us,
                  analyzer_result_t * result)
{
    const sv_asdu_t * first_asdu = NULL;
    uint32_t          key = 0u;
    sv_state_t *      state = NULL;
    size_t            required_length = 0u;
    size_t            channel = 0u;
    sv_batch_metrics_t metrics = {0};
    float             features[SV_FEATURE_COUNT];
    float             delta_seconds = 0.0f;
    float             prior_interval = 0.0f;
    float             ratio = 0.0f;

    if (source == NULL || destination == NULL || fields == NULL ||
        result == NULL || fields->asdu_count == 0u ||
        fields->asdu_count > MAXIMUM_ASDUS ||
        !validate_sv_payload(fields, &required_length))
    {
        ++g_malformed_frames;
        return false;
    }
    (void) required_length;
    first_asdu = &fields->asdus[0];
    key = batch_hash(fields->appid, first_asdu->sv_id, first_asdu->sv_id_length,
                     destination);
    state = sv_state_for(fields->appid, first_asdu->sv_id,
                         first_asdu->sv_id_length, destination, key);
    if (state == NULL)
    {
        if (!g_have_latest_sv || timestamp_us > g_latest_sv_us)
        {
            g_latest_sv_us = timestamp_us;
        }
        g_have_latest_sv = true;
        return false;
    }
    if (state->has_time && timestamp_us < state->timestamp_us)
    {
        ++g_malformed_frames;
        return false;
    }
    memset(result, 0, sizeof(*result));
    result->protocol   = ANALYZER_PROTOCOL_SAMPLED_VALUES;
    result->appid      = fields->appid;
    result->stream_key = key;
    result->counter_1  = first_asdu->smp_cnt;
    delta_seconds      = state->has_time
                             ? (float) (timestamp_us - state->timestamp_us) *
                                   SECONDS_PER_MICROSECOND
                             : 0.0f;
    prior_interval = ring_median(state->previous_intervals,
                                 PICO_ML_BATCH_TIMING_HISTORY_FRAMES,
                                 state->interval_count, state->interval_next);
    ratio = prior_interval > 0.0f ? delta_seconds / prior_interval : 1.0f;
    collect_sv_samples(state, fields, &metrics);
    summarize_sv_history(state, &metrics);
    calculate_sv_channel_ranges(fields->asdu_count, &metrics);
    calculate_sv_features(state, fields, source, timestamp_us, delta_seconds,
                          ratio, &metrics, features);
    update_sv_state(state, source, timestamp_us, delta_seconds);
    predict_batch(&state->batch[0][0], SV_FEATURE_COUNT, &state->batch_count,
                  features, result, &state->previous_label,
                  &state->has_prediction, PICO_ML_BATCH_SV_THRESHOLD,
                  sv_predict, SV_BATCH_FEATURE_COUNT);
    result->feature_count = ANALYZER_FEATURE_CAPACITY;
    for (channel = 0u; channel < ANALYZER_FEATURE_CAPACITY; ++channel)
    {
        result->features[channel] = features[channel];
    }
    return true;
}

void
analyzer_reset (void)
{
    memset(g_goose_states, 0, sizeof(g_goose_states));
    memset(g_sv_states, 0, sizeof(g_sv_states));
    g_latest_goose_us          = 0u;
    g_latest_sv_us             = 0u;
    g_have_latest_goose        = false;
    g_have_latest_sv           = false;
    g_last_batch_feature_count = 0u;
    g_unsupported_parse        = false;
}

void
analyzer_get_diagnostics (analyzer_diagnostics_t * diagnostics)
{
    if (diagnostics != NULL)
    {
        diagnostics->unsupported_streams = g_unsupported_streams;
        diagnostics->unsupported_sv_asdu = g_unsupported_sv_asdu;
        diagnostics->malformed_frames    = g_malformed_frames;
    }
}

bool
analyzer_copy_last_batch_features (float * output, size_t capacity,
                                   size_t *              count,
                                   analyzer_protocol_t * protocol)
{
    if (count != NULL)
    {
        *count = g_last_batch_feature_count;
    }
    if (protocol != NULL)
    {
        *protocol = g_last_batch_protocol;
    }
    if (output == NULL || g_last_batch_feature_count == 0u ||
        capacity < g_last_batch_feature_count)
    {
        return false;
    }
    memcpy(output, g_last_batch_features,
           g_last_batch_feature_count * sizeof(float));
    return true;
}

bool
analyzer_process_ethernet_frame (const uint8_t * frame, size_t length,
                                 uint64_t            timestamp_us,
                                 analyzer_result_t * result)
{
    ethernet_payload_t payload;
    const uint8_t *    source = NULL;
    const uint8_t *    destination = NULL;

    if (frame == NULL || result == NULL || length < ETHERNET_HEADER_SIZE)
    {
        ++g_malformed_frames;
        return false;
    }
    if (!find_ethernet_payload(frame, length, &payload))
    {
        ++g_malformed_frames;
        return false;
    }
    source      = frame + MAC_ADDRESS_LENGTH;
    destination = frame;
    if (payload.type == GOOSE_ETHERTYPE)
    {
        goose_fields_t fields;
        if (!parse_goose(&payload, &fields))
        {
            ++g_malformed_frames;
            return false;
        }
        return process_goose_batch(source, destination, &fields, timestamp_us,
                                   result);
    }
    if (payload.type == SV_ETHERTYPE)
    {
        sv_fields_t fields;
        if (!parse_sv(&payload, &fields))
        {
            if (!g_unsupported_parse)
            {
                ++g_malformed_frames;
            }
            g_unsupported_parse = false;
            return false;
        }
        return process_sv_batch(source, destination, &fields, timestamp_us,
                                result);
    }
    return false;
}
