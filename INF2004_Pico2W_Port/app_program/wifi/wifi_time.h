/** @file wifi_time.h
 * @brief SNTP clock hooks, called only by the radio/lwIP owner.
 */
#ifndef WIFI_TIME_H
#define WIFI_TIME_H
#include <stdint.h>
void wifi_time_set_sntp(uint32_t seconds);
void wifi_time_get_sntp(uint32_t * p_seconds, uint32_t * p_microseconds);
#endif

/*** end of file ***/
