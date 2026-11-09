/** @file incident.c
 * @brief Provisional first-positive-per-stream policy; no cross-protocol gate.
 */
#include "incident.h"
#include <string.h>
#include "../health/evidence.h"

typedef struct
{
    bool                       used;
    analyzer_packet_metadata_t identity;
} incident_stream_t;

static incident_stream_t g_streams[INCIDENT_STREAMS];
static incident_stats_t  g_stats;

void
incident_init (void)
{
    memset(g_streams, 0, sizeof(g_streams));
    memset(&g_stats, 0, sizeof(g_stats));
    evidence_init();
}

/** @brief Compare full identities, not just a collision-prone stream hash. */
static bool
incident_same (const analyzer_packet_metadata_t * p_left,
               const analyzer_packet_metadata_t * p_right)
{
    return (p_left->protocol == p_right->protocol)
        && (p_left->appid == p_right->appid)
        && (p_left->stream_id_length == p_right->stream_id_length)
        && (0
            == memcmp(p_left->source_mac, p_right->source_mac,
                      ANALYZER_MAC_BYTES))
        && (0
            == memcmp(p_left->destination_mac, p_right->destination_mac,
                      ANALYZER_MAC_BYTES))
        && (0
            == memcmp(p_left->stream_id, p_right->stream_id,
                      p_left->stream_id_length));
}

bool
incident_observe (const analyzer_result_t * p_result, uint64_t decision_us,
                  incident_event_t * p_event)
{
    const analyzer_packet_metadata_t * p_identity = NULL;
    size_t                             index      = 0u;
    size_t                             free_slot  = INCIDENT_STREAMS;

    if ((NULL == p_result) || (NULL == p_event) || (!p_result->prediction_ready)
        || p_result->inference_skipped || (0u == p_result->primary_label)
        || (ANALYZER_BATCH_FRAME_COUNT != p_result->batch_frame_count)
        || ((ANALYZER_PROTOCOL_GOOSE != p_result->protocol)
            && (ANALYZER_PROTOCOL_SAMPLED_VALUES != p_result->protocol)))
    {
        return false;
    }
    p_identity = &p_result->batch_packets[ANALYZER_NEWEST_FRAME_INDEX];
    if ((ANALYZER_STREAM_ID_CAPACITY < p_identity->stream_id_length)
        || (p_identity->protocol != p_result->protocol))
    {
        return false;
    }
    g_stats.positive_windows++;
    for (index = 0u; INCIDENT_STREAMS > index; index++)
    {
        if (g_streams[index].used)
        {
            if (incident_same(&g_streams[index].identity, p_identity))
            {
                g_stats.repeated_windows++;
                return false;
            }
        }
        else if (INCIDENT_STREAMS == free_slot)
        {
            free_slot = index;
        }
    }
    if (INCIDENT_STREAMS == free_slot)
    {
        /* The global alarm has already latched on the first incident. Full
         * bookkeeping never blocks analysis or invents a benign decision.
         */
        g_stats.untracked_windows++;
        return false;
    }
    g_streams[free_slot].identity = *p_identity;
    g_streams[free_slot].used     = true;
    g_stats.incidents++;
    memset(p_event, 0, sizeof(*p_event));
    p_event->incident_id     = g_stats.incidents;
    p_event->protocol        = (uint32_t) p_result->protocol;
    p_event->window_start_us = p_result->batch_packets[0].timestamp_us;
    p_event->newest_end_us   = p_identity->timestamp_us;
    p_event->decision_us     = decision_us;
    p_event->evidence_saved  = evidence_save(p_event->incident_id, p_result);
    return true;
}

void
incident_stats (incident_stats_t * p_stats)
{
    if (NULL != p_stats)
    {
        *p_stats = g_stats;
    }
}

/*** end of file ***/
