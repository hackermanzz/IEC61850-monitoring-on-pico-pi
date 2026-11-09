/** @file evidence.h
 * @brief Two immutable evidence trays, written only by the analysis owner.
 */
#ifndef EVIDENCE_H
#define EVIDENCE_H

#include "../analysis/analyzer.h"

#define EVIDENCE_SLOTS    (2u)
#define EVIDENCE_FEATURES (72u)

typedef struct
{
    uint32_t                 incident_id;
    analyzer_result_t        result;
    analyzer_packet_values_t values[ANALYZER_BATCH_FRAME_COUNT];
    uint8_t frames[ANALYZER_BATCH_FRAME_COUNT][ANALYZER_MAXIMUM_FRAME_LENGTH];
    float   features[EVIDENCE_FEATURES];
    size_t  feature_count;
} evidence_record_t;

typedef struct
{
    uint32_t saved;
    uint32_t full;
    uint32_t copy_errors;
    uint32_t occupied;
    uint32_t released;
    uint32_t ack_rejected;
} evidence_stats_t;

/** @brief Boot only. No release/overwrite policy in this development image. */
void evidence_init(void);
/** @brief Copy now, before the next analyzer call invalidates its snapshot. */
bool evidence_save(uint32_t incident_id, const analyzer_result_t * p_result);
/** @brief Read only on the analysis owner; pointer remains valid until boot. */
const evidence_record_t * evidence_record(size_t index);
/** @brief S3 owner only: release after a successful matching durable ACK. */
bool evidence_release(size_t index, uint32_t incident_id);
void evidence_stats(evidence_stats_t * p_stats);

#endif /* EVIDENCE_H */

/*** end of file ***/
