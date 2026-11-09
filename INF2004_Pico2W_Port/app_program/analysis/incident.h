/** @file incident.h
 * @brief S3 alone creates incidents; either protocol may trigger the alarm.
 */
#ifndef INCIDENT_H
#define INCIDENT_H

#include "analyzer.h"

#define INCIDENT_STREAMS                                                       \
    (ANALYZER_MAXIMUM_GOOSE_STREAMS + ANALYZER_MAXIMUM_SV_STREAMS)

typedef struct
{
    uint32_t incident_id;
    uint32_t protocol;
    uint64_t window_start_us;
    uint64_t newest_end_us;
    uint64_t decision_us;
    bool     evidence_saved;
} incident_event_t;

typedef struct
{
    uint32_t incidents;
    uint32_t positive_windows;
    uint32_t repeated_windows;
    uint32_t untracked_windows;
} incident_stats_t;

/** @brief Boot only; alarms/episodes intentionally latch until reboot. */
void incident_init(void);
/** @brief Returns a copied event only for the first positive per stream/boot.
 * Unknown/skipped/rule-only results never become incidents. Capture resets
 * do not clear an already latched incident. Call before analyzer snapshot ends.
 */
bool incident_observe(const analyzer_result_t * p_result, uint64_t decision_us,
                      incident_event_t * p_event);
void incident_stats(incident_stats_t * p_stats);

#endif /* INCIDENT_H */

/*** end of file ***/
