/** @file detection.h
 * @brief v0.7 runtime boundary; no radio, SD or capture IRQ kernel calls.
 */
#ifndef DETECTION_H
#define DETECTION_H

#include "supervision.h"
#include "../analysis/analyzer.h"

bool detection_init(void);
bool detection_start(void);
void detection_observe(const analyzer_result_t * p_result);
void detection_heartbeat(uint32_t owner);
/** @brief Console owner only; service tasks never use printf or SDK TLS. */
void detection_report(void);

#endif /* DETECTION_H */

/*** end of file ***/
