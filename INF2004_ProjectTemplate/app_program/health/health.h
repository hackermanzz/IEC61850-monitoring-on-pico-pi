/** @file health.h
 *
 * @brief Health and evidence: supervises task progress, feeds the watchdog
 * and keeps incident evidence.
 *
 * @par
 * TODO: Add the public interface of this module.
 */
#ifndef HEALTH_H
#define HEALTH_H

#include "../app.h"

ER health_init(void);
ER health_start(void);

#endif /* HEALTH_H */

/*** end of file ***/
