/** @file storage_record.c
 * @brief P2INC001 files preserve four frames, values and all model inputs.
 * No C struct padding, native pointer or uninitialized tail is written.
 */
#include "storage_record.h"
#include <string.h>

typedef struct
{
    uint32_t  position;
    uint32_t  offset;
    uint8_t * p_output;
    size_t    capacity;
    size_t    copied;
} storage_encoder_t;

_Static_assert(4u == sizeof(float), "Model files require float32");

uint32_t
storage_record_size (const evidence_record_t * p_record)
{
    uint32_t total = 0u;
    if ((NULL == p_record) || (0u == p_record->incident_id)
        || (4u != p_record->result.batch_frame_count)
        || (!p_record->result.prediction_ready)
        || p_record->result.inference_skipped)
    {
        return 0u;
    }
    if (((ANALYZER_PROTOCOL_GOOSE == p_record->result.protocol)
         && (52u == p_record->feature_count))
        || ((ANALYZER_PROTOCOL_SAMPLED_VALUES == p_record->result.protocol)
            && (72u == p_record->feature_count)))
    {
        total = STORAGE_RECORD_HEADER + (uint32_t) p_record->feature_count * 4u;
        for (size_t index = 0u; 4u > index; index++)
        {
            const analyzer_packet_metadata_t * p =
                &p_record->result.batch_packets[index];
            if ((0u == p->frame_length)
                || (ANALYZER_MAXIMUM_FRAME_LENGTH < p->frame_length)
                || (ANALYZER_STREAM_ID_CAPACITY < p->stream_id_length)
                || (p_record->result.protocol != p->protocol))
            {
                return 0u;
            }
            total += STORAGE_PACKET_HEADER + p->frame_length;
        }
    }
    return total;
}

static void
storage_emit (storage_encoder_t * p, const void * p_source, size_t length)
{
    uint32_t end = p->position + (uint32_t) length;
    if ((end > p->offset) && (p->copied < p->capacity))
    {
        size_t start = (p->offset > p->position) ? p->offset - p->position : 0u;
        size_t amount = length - start;
        if (amount > p->capacity - p->copied)
        {
            amount = p->capacity - p->copied;
        }
        memcpy(&p->p_output[p->copied], (const uint8_t *) p_source + start,
               amount);
        p->copied += amount;
    }
    p->position = end;
}

static void
storage_number (storage_encoder_t * p, uint64_t value, size_t bytes)
{
    uint8_t encoded[8] = {0};
    for (size_t index = 0u; bytes > index; index++)
    {
        encoded[index] = (uint8_t) (value >> (8u * index));
    }
    storage_emit(p, encoded, bytes);
}

size_t
storage_record_read (const evidence_record_t * p_record, uint32_t offset,
                     uint8_t * p_output, size_t capacity)
{
    storage_encoder_t writer = {0u, offset, p_output, capacity, 0u};
    uint32_t          size   = storage_record_size(p_record);
    uint32_t          bits   = 0u;
    if ((0u == size) || (offset >= size) || (NULL == p_output))
    {
        return 0u;
    }
    storage_emit(&writer, "P2INC001", 8u);
    storage_number(&writer, 1u, 2u);
    storage_number(&writer, STORAGE_RECORD_HEADER, 2u);
    storage_number(&writer, size, 4u);
    storage_number(&writer, p_record->incident_id, 4u);
    storage_number(&writer, (uint32_t) p_record->result.protocol, 4u);
    storage_number(&writer, p_record->result.timestamp_us, 8u);
    storage_number(&writer, 4u, 2u);
    storage_number(&writer, p_record->feature_count, 2u);
    storage_number(&writer, p_record->result.primary_label, 4u);
    memcpy(&bits, &p_record->result.primary_probability, sizeof(bits));
    storage_number(&writer, bits, 4u);
    storage_number(&writer, p_record->result.rule_reasons, 4u);
    for (size_t index = 0u; p_record->feature_count > index; index++)
    {
        memcpy(&bits, &p_record->features[index], sizeof(bits));
        storage_number(&writer, bits, 4u);
    }
    for (size_t index = 0u; 4u > index; index++)
    {
        const analyzer_packet_metadata_t * p =
            &p_record->result.batch_packets[index];
        storage_number(&writer, p->frame_length, 2u);
        storage_number(&writer, p->appid, 2u);
        storage_number(&writer, p->capture_sequence, 4u);
        storage_number(&writer, p->timestamp_us, 8u);
        storage_number(&writer, p->counter_1, 4u);
        storage_number(&writer, p->counter_2, 4u);
        storage_number(&writer, p->stream_key, 4u);
        storage_emit(&writer, p->source_mac, 6u);
        storage_emit(&writer, p->destination_mac, 6u);
        storage_number(&writer, p->stream_id_length, 1u);
        storage_number(&writer, p_record->values[index].format, 1u);
        storage_number(&writer, 0u, 2u);
        for (size_t value = 0u; 6u > value; value++)
        {
            storage_number(&writer, p_record->values[index].bits[value], 4u);
        }
        storage_emit(&writer, p->stream_id, ANALYZER_STREAM_ID_CAPACITY);
        storage_emit(&writer, p_record->frames[index], p->frame_length);
    }
    return writer.copied;
}

/*** end of file ***/
