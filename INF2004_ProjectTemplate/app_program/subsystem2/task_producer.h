/** @file task_producer.h
 *
 * @brief Capture producer task: turns finished RMII captures into checked
 * capture frames for the analysis subsystem, and publishes capture health.
 */
#ifndef TASK_PRODUCER_H
#define TASK_PRODUCER_H

#include "../app.h"

ID task_producer_start(void);

#endif /* TASK_PRODUCER_H */

/*** end of file ***/
