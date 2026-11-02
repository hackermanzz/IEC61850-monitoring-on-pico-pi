#ifndef MONITOR_NOTIFICATION_PORT_H
#define MONITOR_NOTIFICATION_PORT_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "../monitor_status.h"
uint32_t monitor_notification_ms(void);
/* TLS calls these checked kernel-heap adapters, never libc malloc. */
void *monitor_tls_calloc(size_t count, size_t bytes);
void monitor_tls_free(void *pointer);
void monitor_tls_memory_stats(size_t *current, size_t *peak, uint32_t *failures);
/* Set from the radio service owner after obtaining trusted UTC. */
void monitor_notification_set_utc(time_t unix_seconds);
time_t monitor_tls_time(time_t *out);
/* Radio service only. All DNS/TCP/TLS calls stay on that task. */
void monitor_notification_poll(void);
/* Kernel-only bridge: polls one copied notification without waiting. */
int monitor_notification_take(char *text, size_t capacity);
void monitor_notification_report(const monitor_network_stats_t *status);
#endif
