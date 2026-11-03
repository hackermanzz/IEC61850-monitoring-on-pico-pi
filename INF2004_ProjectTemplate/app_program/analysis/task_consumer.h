/** @file task_consumer.h
 *
 * @brief Analysis consumer task: takes capture frames from its mailbox,
 * analyses them, drives incidents and alarms, and publishes analysis health.
 */
#ifndef TASK_CONSUMER_H
#define TASK_CONSUMER_H

#include "../app.h"
#include "../capture/capture_frame.h"
#include "../monitor_status.h"

ER task_consumer_init(void);
ID task_consumer_start(void);
ER task_consumer_submit(capture_frame_t * p_frame);
ER task_consumer_read_stats(monitor_analysis_stats_t * p_stats);

#endif /* TASK_CONSUMER_H */

/*** end of file ***/
