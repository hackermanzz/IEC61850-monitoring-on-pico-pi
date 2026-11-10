#ifndef PORT_NOTIFICATION_PORT_H
#define PORT_NOTIFICATION_PORT_H
#include <stdint.h>
#include <time.h>
#include "tls_arena.h"
uint32_t monitor_notification_ms(void);
time_t   monitor_tls_time(time_t * p_time);
#endif

/*** end of file ***/
