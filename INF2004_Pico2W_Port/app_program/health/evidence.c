/** @file evidence.c
 * @brief Bounded full-window copies, independent of capture pool ownership.
 */
#include "evidence.h"
#include <string.h>

static evidence_record_t g_records[EVIDENCE_SLOTS];
static evidence_stats_t  g_stats;
static uint32_t          g_used;

void
evidence_init (void)
{
    memset(&g_stats, 0, sizeof(g_stats));
    memset(g_records, 0, sizeof(g_records));
    g_used = 0u;
}

bool
evidence_save (uint32_t incident_id, const analyzer_result_t * p_result)
{
    evidence_record_t * p_record = NULL;
    analyzer_protocol_t protocol = ANALYZER_PROTOCOL_GOOSE;
    size_t              index    = 0u;
    bool                b_ok     = true;
    size_t              slot     = 0u;

    if ((NULL == p_result) || (0u == incident_id)
        || (!p_result->prediction_ready) || p_result->inference_skipped
        || (ANALYZER_BATCH_FRAME_COUNT != p_result->batch_frame_count))
    {
        g_stats.copy_errors++;
        return false;
    }
    if (EVIDENCE_SLOTS <= g_stats.occupied)
    {
        g_stats.full++;
        return false;
    }
    while ((EVIDENCE_SLOTS > slot) && (0u != (g_used & (1u << slot))))
    {
        slot++;
    }
    p_record         = &g_records[slot];
    p_record->result = *p_result;
    for (index = 0u; ANALYZER_BATCH_FRAME_COUNT > index; index++)
    {
        b_ok = analyzer_copy_batch_frame(index, p_record->frames[index],
                                         sizeof(p_record->frames[index]),
                                         &p_record->result.batch_packets[index])
            && b_ok;
        b_ok =
            analyzer_copy_batch_values(index, &p_record->values[index]) && b_ok;
    }
    b_ok = analyzer_copy_batch_features(p_record->features, EVIDENCE_FEATURES,
                                        &p_record->feature_count, &protocol)
        && b_ok;
    b_ok = (protocol == p_result->protocol)
        && (p_record->feature_count
            == ((ANALYZER_PROTOCOL_GOOSE == protocol) ? 52u : 72u))
        && b_ok;
    if (b_ok)
    {
        /* Publish only a complete copy. No consumer sees a partial tray. */
        p_record->incident_id = incident_id;
        g_stats.saved++;
        g_stats.occupied++;
        g_used |= 1u << slot;
    }
    else
    {
        memset(p_record, 0, sizeof(*p_record));
        g_stats.copy_errors++;
    }
    return b_ok;
}

const evidence_record_t *
evidence_record (size_t index)
{
    return ((index < EVIDENCE_SLOTS) && (0u != (g_used & (1u << index))))
             ? &g_records[index]
             : NULL;
}

bool
evidence_release (size_t index, uint32_t incident_id)
{
    const evidence_record_t * p_record = evidence_record(index);
    if ((NULL == p_record) || (0u == incident_id)
        || (p_record->incident_id != incident_id))
    {
        g_stats.ack_rejected++;
        return false;
    }
    g_used &= ~(1u << index);
    g_stats.occupied--;
    g_stats.released++;
    return true;
}

void
evidence_stats (evidence_stats_t * p_stats)
{
    if (NULL != p_stats)
    {
        *p_stats = g_stats;
    }
}

/*** end of file ***/
