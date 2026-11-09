/** @file alarm.h
 * @brief Copied event queue and independent fail-latched local alarm request.
 */
#ifndef ALARM_H
#define ALARM_H

#include "../analysis/incident.h"

typedef struct
{
    uint32_t requested_mask;
    uint32_t applied_mask;
    uint32_t queue_drops;
    uint32_t events;
    uint32_t max_window_to_service_us;
    uint32_t max_newest_to_service_us;
    uint32_t stack_used;
    uint64_t first_request_us;
    uint64_t first_apply_us;
} alarm_stats_t;

/** @brief Create and test the queue before any producer/service task starts. */
bool alarm_init(void);
bool alarm_start(void);
/** @brief Latch first, then try a non-waiting copy.
 * Full queue cannot mute the LED.
 */
void alarm_submit(const incident_event_t * p_event);
/** @brief One bounded cycle; alarm-task owner only (also host API model). */
void alarm_service_step(void);
void alarm_stats(alarm_stats_t * p_stats);

#endif /* ALARM_H */

/*** end of file ***/
