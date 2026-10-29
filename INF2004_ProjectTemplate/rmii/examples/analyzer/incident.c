#include "incident.h"

#include <math.h>
#include <string.h>

#define INCIDENT_GATE (0.65f)
#define INCIDENT_AGREEMENT_WINDOW_US (UINT64_C(1000000))
#define INCIDENT_MAXIMUM_BATCHES (INCIDENT_MAXIMUM_BATCHES_PER_CONTAINER)
#define INCIDENT_MODEL_COUNT (2u)
#define INCIDENT_SESSION_SEQUENCE_SHIFT (32u)

typedef struct
{
    bool                       used;
    uint8_t                    references;
    incident_packet_metadata_t metadata;
    uint8_t                    bytes[INCIDENT_MAXIMUM_FRAME_LENGTH];
} incident_packet_t;

typedef struct
{
    incident_container_info_t info;
    incident_batch_summary_t  batches[INCIDENT_MAXIMUM_BATCHES];
    uint8_t                   packet_refs[INCIDENT_MAXIMUM_PACKETS];
} incident_container_t;

typedef struct
{
    bool                     valid;
    uint64_t                 timestamp_us;
    float                    score;
    incident_batch_summary_t batch;
    uint16_t                 lengths[ANALYZER_BATCH_FRAME_COUNT];
    uint8_t frames[ANALYZER_BATCH_FRAME_COUNT][INCIDENT_MAXIMUM_FRAME_LENGTH];
} incident_vote_t;

static incident_container_t g_containers[INCIDENT_MAXIMUM_CONTAINERS];
static incident_packet_t    g_packets[INCIDENT_MAXIMUM_PACKETS];
static incident_vote_t      g_votes[INCIDENT_MODEL_COUNT];
static uint32_t             g_session_id;
static uint32_t             g_next_sequence;
static size_t               g_active_index;
static bool                 g_has_active;
static uint32_t             g_completed_containers;
static uint32_t             g_lost_containers;
static uint32_t             g_lost_batches;
static uint32_t             g_lost_packets;
static bool                 g_rejected_episode;

static void close_container (incident_closure_reason_t reason,
                             uint64_t                  timestamp_us);
static bool valid_score (float score);

static bool
same_batch (const incident_batch_summary_t * left,
            const incident_batch_summary_t * right)
{
    return left->protocol == right->protocol &&
           left->stream_key == right->stream_key &&
           left->appid == right->appid &&
           left->window_end_us == right->window_end_us &&
           left->packets[ANALYZER_BATCH_FRAME_COUNT - 1u].capture_sequence ==
               right->packets[ANALYZER_BATCH_FRAME_COUNT - 1u].capture_sequence;
}

static bool
repeated_suspicious_vote (size_t vote_index, const analyzer_result_t * result)
{
    const incident_vote_t * vote        = &g_votes[vote_index];
    const size_t            last_packet = ANALYZER_BATCH_FRAME_COUNT - 1u;

    return valid_score(result->primary_probability) &&
           result->primary_probability >= INCIDENT_GATE && vote->valid &&
           vote->score >= INCIDENT_GATE &&
           vote->batch.protocol == result->protocol &&
           vote->batch.stream_key == result->stream_key &&
           vote->batch.appid == result->appid &&
           vote->timestamp_us == result->timestamp_us &&
           vote->batch.packets[last_packet].capture_sequence ==
               result->batch_packets[last_packet].capture_sequence &&
           vote->batch.packets[last_packet].timestamp_us ==
               result->batch_packets[last_packet].timestamp_us;
}

static size_t
protocol_index (analyzer_protocol_t protocol)
{
    return protocol == ANALYZER_PROTOCOL_GOOSE ? 0u : 1u;
}

static bool
valid_score (float score)
{
    return isfinite(score) && score >= 0.0f && score <= 1.0f;
}

static bool
votes_recent (uint64_t now_us)
{
    size_t index = 0u;

    for (index = 0u; index < INCIDENT_MODEL_COUNT; ++index)
    {
        if (!g_votes[index].valid || now_us < g_votes[index].timestamp_us ||
            now_us - g_votes[index].timestamp_us > INCIDENT_AGREEMENT_WINDOW_US)
        {
            return false;
        }
    }
    return true;
}

static bool
votes_suspicious (uint64_t now_us)
{
    return votes_recent(now_us) && g_votes[0].score >= INCIDENT_GATE &&
           g_votes[1].score >= INCIDENT_GATE;
}

static bool
same_packet (const incident_packet_metadata_t * left,
             const incident_packet_metadata_t * right)
{
    return left->capture_sequence == right->capture_sequence &&
           left->timestamp_us == right->timestamp_us &&
           left->protocol == right->protocol &&
           left->stream_key == right->stream_key;
}

static size_t
find_container_slot (void)
{
    size_t index = 0u;

    for (index = 0u; index < INCIDENT_MAXIMUM_CONTAINERS; ++index)
    {
        if (!g_containers[index].info.used)
        {
            return index;
        }
    }
    return INCIDENT_MAXIMUM_CONTAINERS;
}

static size_t
find_packet (const incident_packet_metadata_t * metadata)
{
    size_t index = 0u;

    for (index = 0u; index < INCIDENT_MAXIMUM_PACKETS; ++index)
    {
        if (g_packets[index].used &&
            same_packet(&g_packets[index].metadata, metadata))
        {
            return index;
        }
    }
    return INCIDENT_MAXIMUM_PACKETS;
}

static size_t
free_packet_slot (void)
{
    size_t index = 0u;

    for (index = 0u; index < INCIDENT_MAXIMUM_PACKETS; ++index)
    {
        if (!g_packets[index].used)
        {
            return index;
        }
    }
    return INCIDENT_MAXIMUM_PACKETS;
}

static bool
retain_packet (size_t container_index, const incident_vote_t * vote,
               size_t frame_index)
{
    incident_container_t * container = &g_containers[container_index];
    const incident_packet_metadata_t * metadata =
        &vote->batch.packets[frame_index];
    size_t packet_index = find_packet(metadata);

    if (packet_index == INCIDENT_MAXIMUM_PACKETS)
    {
        packet_index = free_packet_slot();
        if (packet_index == INCIDENT_MAXIMUM_PACKETS)
        {
            ++container->info.lost_packets;
            ++g_lost_packets;
            container->info.truncated = true;
            return false;
        }
        if (metadata->frame_length == 0u ||
            metadata->frame_length > INCIDENT_MAXIMUM_FRAME_LENGTH ||
            vote->lengths[frame_index] != metadata->frame_length)
        {
            ++container->info.lost_packets;
            ++g_lost_packets;
            container->info.truncated = true;
            return false;
        }
        g_packets[packet_index].used       = true;
        g_packets[packet_index].references = 0u;
        g_packets[packet_index].metadata   = *metadata;
        memcpy(g_packets[packet_index].bytes, vote->frames[frame_index],
               metadata->frame_length);
        ++container->info.packet_count;
    }
    else
    {
        size_t existing = 0u;
        for (existing = 0u; existing < container->info.packet_count; ++existing)
        {
            const size_t reference = container->packet_refs[existing];
            if (reference == packet_index)
            {
                return true;
            }
        }
        ++container->info.packet_count;
    }
    container->packet_refs[container->info.packet_count - 1u] =
        (uint8_t) packet_index;
    ++g_packets[packet_index].references;
    return true;
}

static void
append_vote (size_t container_index, const incident_vote_t * vote)
{
    incident_container_t * container    = &g_containers[container_index];
    size_t                 batch_index  = 0u;
    size_t                 packet_index = 0u;

    for (batch_index = 0u; batch_index < container->info.batch_count;
         ++batch_index)
    {
        if (same_batch(&container->batches[batch_index], &vote->batch))
        {
            return;
        }
    }
    if (container->info.batch_count >= INCIDENT_MAXIMUM_BATCHES)
    {
        ++container->info.lost_batches;
        ++g_lost_batches;
        container->info.truncated = true;
        return;
    }
    batch_index                     = container->info.batch_count;
    container->batches[batch_index] = vote->batch;
    ++container->info.batch_count;
    if (vote->batch.window_end_us > container->info.end_us)
    {
        container->info.end_us = vote->batch.window_end_us;
    }
    for (packet_index = 0u; packet_index < vote->batch.packet_count;
         ++packet_index)
    {
        (void) retain_packet(container_index, vote, packet_index);
    }
}

static bool
open_container (uint64_t now_us)
{
    const size_t           slot      = find_container_slot();
    incident_container_t * container = NULL;

    if (slot == INCIDENT_MAXIMUM_CONTAINERS)
    {
        if (!g_rejected_episode)
        {
            ++g_lost_containers;
            g_rejected_episode = true;
        }
        return false;
    }
    if (g_next_sequence == UINT32_MAX)
    {
        if (!g_rejected_episode)
        {
            ++g_lost_containers;
            g_rejected_episode = true;
        }
        return false;
    }
    container = &g_containers[slot];
    memset(container, 0, sizeof(*container));
    container->info.used = true;
    container->info.id =
        ((uint64_t) g_session_id << INCIDENT_SESSION_SEQUENCE_SHIFT) |
        ++g_next_sequence;
    container->info.start_us    = now_us;
    container->info.end_us      = now_us;
    container->info.goose_score = g_votes[0].score;
    container->info.sv_score    = g_votes[1].score;
    g_active_index              = slot;
    g_has_active                = true;
    g_rejected_episode          = false;
    append_vote(slot, &g_votes[0]);
    append_vote(slot, &g_votes[1]);
    return true;
}

static void
evaluate_vote (size_t vote_index)
{
    incident_vote_t * vote = &g_votes[vote_index];

    if (g_has_active && vote->score < INCIDENT_GATE)
    {
        close_container(INCIDENT_CLOSURE_SAFE_PREDICTION, vote->timestamp_us);
    }
    else if (g_has_active && !votes_recent(vote->timestamp_us))
    {
        close_container(INCIDENT_CLOSURE_STALE_SCORE, vote->timestamp_us);
        memset(g_votes, 0, sizeof(g_votes));
        return;
    }
    if (g_has_active)
    {
        append_vote(g_active_index, vote);
    }
    else if (votes_suspicious(vote->timestamp_us) &&
             open_container(vote->timestamp_us))
    {
        g_containers[g_active_index].info.goose_score = g_votes[0].score;
        g_containers[g_active_index].info.sv_score    = g_votes[1].score;
    }
}

static void
close_container (incident_closure_reason_t reason, uint64_t timestamp_us)
{
    incident_container_t * container = NULL;

    if (!g_has_active)
    {
        return;
    }
    container                      = &g_containers[g_active_index];
    container->info.complete       = true;
    container->info.closure_reason = reason;
    if (timestamp_us > container->info.end_us)
    {
        container->info.end_us = timestamp_us;
    }
    g_has_active = false;
    ++g_completed_containers;
}

static bool
copy_vote (incident_vote_t * vote, const analyzer_result_t * result,
           const uint8_t * const * frames, const size_t * frame_lengths)
{
    size_t index = 0u;

    if (vote == NULL || result == NULL || frames == NULL ||
        frame_lengths == NULL)
    {
        return false;
    }
    memset(vote, 0, sizeof(*vote));
    vote->valid = true;
    vote->timestamp_us =
        result->batch_packets[ANALYZER_BATCH_FRAME_COUNT - 1u].timestamp_us;
    vote->score                 = result->primary_probability;
    vote->batch.protocol        = result->protocol;
    vote->batch.stream_key      = result->stream_key;
    vote->batch.appid           = result->appid;
    vote->batch.packet_count    = result->batch_frame_count;
    vote->batch.raw_score       = result->primary_probability;
    vote->batch.window_start_us = result->batch_packets[0].timestamp_us;
    vote->batch.window_end_us   = vote->timestamp_us;
    for (index = 0u; index < result->batch_frame_count; ++index)
    {
        const analyzer_packet_metadata_t * metadata =
            &result->batch_packets[index];
        vote->batch.packets[index] = *metadata;
        if (metadata->frame_length == 0u ||
            metadata->frame_length > INCIDENT_MAXIMUM_FRAME_LENGTH ||
            frame_lengths[index] != metadata->frame_length ||
            frames[index] == NULL)
        {
            vote->valid = false;
            return false;
        }
        vote->lengths[index] = metadata->frame_length;
        memcpy(vote->frames[index], frames[index], metadata->frame_length);
    }
    return true;
}

void
incident_initialize (uint32_t session_id)
{
    memset(g_containers, 0, sizeof(g_containers));
    memset(g_packets, 0, sizeof(g_packets));
    memset(g_votes, 0, sizeof(g_votes));
    g_session_id           = session_id;
    g_next_sequence        = 0u;
    g_active_index         = 0u;
    g_has_active           = false;
    g_completed_containers = 0u;
    g_lost_containers      = 0u;
    g_lost_batches         = 0u;
    g_lost_packets         = 0u;
    g_rejected_episode     = false;
}

void
incident_capture_gap (uint64_t timestamp_us)
{
    close_container(INCIDENT_CLOSURE_CAPTURE_GAP, timestamp_us);
    memset(g_votes, 0, sizeof(g_votes));
    g_rejected_episode = false;
}

void
incident_check_stale (uint64_t now_us)
{
    if (g_has_active && !votes_recent(now_us))
    {
        close_container(INCIDENT_CLOSURE_STALE_SCORE, now_us);
        memset(g_votes, 0, sizeof(g_votes));
        g_rejected_episode = false;
    }
}

void
incident_observe_prediction (const analyzer_result_t * result,
                             const uint8_t * const *   frames,
                             const size_t *            frame_lengths)
{
    size_t vote_index = 0u;
    if (result == NULL || frames == NULL || frame_lengths == NULL ||
        (result->protocol != ANALYZER_PROTOCOL_GOOSE &&
         result->protocol != ANALYZER_PROTOCOL_SAMPLED_VALUES) ||
        !result->prediction_ready ||
        result->batch_frame_count != ANALYZER_BATCH_FRAME_COUNT)
    {
        return;
    }
    if (!valid_score(result->primary_probability))
    {
        if (g_has_active)
        {
            close_container(INCIDENT_CLOSURE_INVALID_SCORE,
                            result->timestamp_us);
        }
        memset(g_votes, 0, sizeof(g_votes));
        return;
    }
    vote_index = protocol_index(result->protocol);
    if (repeated_suspicious_vote(vote_index, result))
    {
        return;
    }
    if (!copy_vote(&g_votes[vote_index], result, frames, frame_lengths))
    {
        if (g_has_active)
        {
            close_container(INCIDENT_CLOSURE_EVIDENCE_LOSS,
                            result->timestamp_us);
        }
        memset(g_votes, 0, sizeof(g_votes));
        return;
    }
    evaluate_vote(vote_index);
}

void
incident_observe_analyzer_prediction (const analyzer_result_t * result)
{
    size_t       index = 0u;
    const size_t vote_index =
        result != NULL ? protocol_index(result->protocol) : 0u;
    incident_vote_t * vote = &g_votes[vote_index];

    if (result == NULL ||
        (result->protocol != ANALYZER_PROTOCOL_GOOSE &&
         result->protocol != ANALYZER_PROTOCOL_SAMPLED_VALUES) ||
        !result->prediction_ready ||
        result->batch_frame_count != ANALYZER_BATCH_FRAME_COUNT)
    {
        return;
    }
    if (!valid_score(result->primary_probability))
    {
        if (g_has_active)
        {
            close_container(INCIDENT_CLOSURE_INVALID_SCORE,
                            result->timestamp_us);
        }
        memset(g_votes, 0, sizeof(g_votes));
        return;
    }
    if (repeated_suspicious_vote(vote_index, result))
    {
        return;
    }
    memset(vote, 0, sizeof(*vote));
    vote->valid                 = true;
    vote->timestamp_us          = result->timestamp_us;
    vote->score                 = result->primary_probability;
    vote->batch.protocol        = result->protocol;
    vote->batch.stream_key      = result->stream_key;
    vote->batch.appid           = result->appid;
    vote->batch.packet_count    = ANALYZER_BATCH_FRAME_COUNT;
    vote->batch.raw_score       = result->primary_probability;
    vote->batch.window_start_us = result->batch_packets[0].timestamp_us;
    vote->batch.window_end_us   = result->timestamp_us;
    for (index = 0u; index < ANALYZER_BATCH_FRAME_COUNT; ++index)
    {
        analyzer_packet_metadata_t * metadata = &vote->batch.packets[index];
        *metadata                             = result->batch_packets[index];
        if (!analyzer_copy_last_batch_frame(index, vote->frames[index],
                                            INCIDENT_MAXIMUM_FRAME_LENGTH,
                                            metadata))
        {
            vote->valid = false;
            if (g_has_active)
            {
                close_container(INCIDENT_CLOSURE_EVIDENCE_LOSS,
                                result->timestamp_us);
            }
            memset(g_votes, 0, sizeof(g_votes));
            return;
        }
        vote->lengths[index] = metadata->frame_length;
    }
    evaluate_vote(vote_index);
}

bool
incident_peek (size_t container_index, incident_container_info_t * info)
{
    if (container_index >= INCIDENT_MAXIMUM_CONTAINERS || info == NULL ||
        !g_containers[container_index].info.used)
    {
        return false;
    }
    *info = g_containers[container_index].info;
    return true;
}

bool
incident_read_batch (size_t container_index, size_t batch_index,
                     incident_batch_summary_t * batch)
{
    if (container_index >= INCIDENT_MAXIMUM_CONTAINERS || batch == NULL ||
        !g_containers[container_index].info.used ||
        batch_index >= g_containers[container_index].info.batch_count)
    {
        return false;
    }
    *batch = g_containers[container_index].batches[batch_index];
    return true;
}

bool
incident_read_packet (size_t container_index, size_t packet_index,
                      incident_packet_metadata_t * metadata, uint8_t * frame,
                      size_t capacity)
{
    incident_container_t * container = NULL;
    incident_packet_t *    packet    = NULL;

    if (container_index >= INCIDENT_MAXIMUM_CONTAINERS || metadata == NULL ||
        frame == NULL || !g_containers[container_index].info.used ||
        packet_index >= g_containers[container_index].info.packet_count)
    {
        return false;
    }
    container = &g_containers[container_index];
    packet    = &g_packets[container->packet_refs[packet_index]];
    if (!packet->used || capacity < packet->metadata.frame_length)
    {
        return false;
    }
    *metadata = packet->metadata;
    memcpy(frame, packet->bytes, packet->metadata.frame_length);
    return true;
}

bool
incident_acknowledge (size_t container_index, uint64_t matching_id)
{
    incident_container_t * container    = NULL;
    size_t                 packet_index = 0u;

    if (container_index >= INCIDENT_MAXIMUM_CONTAINERS ||
        !g_containers[container_index].info.used ||
        !g_containers[container_index].info.complete ||
        g_containers[container_index].info.id != matching_id)
    {
        return false;
    }
    container = &g_containers[container_index];
    for (packet_index = 0u; packet_index < container->info.packet_count;
         ++packet_index)
    {
        incident_packet_t * packet =
            &g_packets[container->packet_refs[packet_index]];
        if (packet->references > 0u)
        {
            --packet->references;
        }
        if (packet->references == 0u)
        {
            packet->used = false;
        }
    }
    memset(container, 0, sizeof(*container));
    return true;
}

void
incident_get_status (incident_status_t * status)
{
    if (status == NULL)
    {
        return;
    }
    status->session_id = g_session_id;
    status->next_sequence =
        g_next_sequence == UINT32_MAX ? UINT32_MAX : g_next_sequence + 1u;
    status->active_container_id_wide =
        g_has_active ? g_containers[g_active_index].info.id : 0u;
    status->completed_containers = g_completed_containers;
    status->lost_containers      = g_lost_containers;
    status->lost_batches         = g_lost_batches;
    status->lost_packets         = g_lost_packets;
}
