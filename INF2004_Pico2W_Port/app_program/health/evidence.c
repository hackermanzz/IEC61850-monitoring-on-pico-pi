/** @file evidence.c
 * @brief Bounded full-window copies, independent of capture pool ownership.
 */
#include "evidence.h"
#include <string.h>

static evidence_record_t g_records[EVIDENCE_SLOTS];
static evidence_stats_t  g_stats;

void
evidence_init (void)
{
    memset(&g_stats, 0, sizeof(g_stats));
    memset(g_records, 0, sizeof(g_records));
}

bool
evidence_save (uint32_t incident_id, const analyzer_result_t * p_result)
{
    evidence_record_t * p_record = NULL;
    analyzer_protocol_t protocol = ANALYZER_PROTOCOL_GOOSE;
    size_t              index    = 0u;
    bool                b_ok     = true;

    if ((NULL == p_result) || (0u == incident_id)
        || (!p_result->prediction_ready) || p_result->inference_skipped
        || (ANALYZER_BATCH_FRAME_COUNT != p_result->batch_frame_count))
    {
        g_stats.copy_errors++;
        return false;
    }
    if (EVIDENCE_SLOTS <= g_stats.saved)
    {
        g_stats.full++;
        return false;
    }
    p_record         = &g_records[g_stats.saved];
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
    return (index < g_stats.saved) ? &g_records[index] : NULL;
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
