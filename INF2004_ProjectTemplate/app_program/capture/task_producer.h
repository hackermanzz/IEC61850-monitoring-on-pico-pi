/** @file task_producer.h
 *
 * @brief Capture producer task: turns finished RMII captures into checked
 * capture frames for the analysis module, and publishes capture health.
 */
#ifndef TASK_PRODUCER_H
#define TASK_PRODUCER_H

#include "../app.h"
#include "../monitor_status.h"

// Capture fault codes reported in monitor_capture_stats_t.fault.
//
#define CAPTURE_FAULT_NONE    (0u)
#define CAPTURE_FAULT_NO_PHY  (1u)
#define CAPTURE_FAULT_START   (2u)
#define CAPTURE_FAULT_NO_PINS (3u)

ER task_producer_init(void);
ID task_producer_start(void);
ER task_producer_read_stats(monitor_capture_stats_t * p_stats);

#endif /* TASK_PRODUCER_H */

/*** end of file ***/
