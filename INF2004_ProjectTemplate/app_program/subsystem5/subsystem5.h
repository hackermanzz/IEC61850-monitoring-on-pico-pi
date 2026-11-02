#ifndef SUBSYSTEM5_H
#define SUBSYSTEM5_H
#define S5_NOTICE_QUEUE_DEPTH 8u
#include "../app.h"
#include "../subsystem4/incident_store.h"
IMPORT ID mbf_notifications, tid_led, flg_alarm;
IMPORT ER subsystem5_alarm(void);
IMPORT void led_task(INT stacd, void *exinf);
#if !MONITOR_TELEGRAM
/* Called only by the low-priority S1 storage owner or S5 console task. */
IMPORT void subsystem5_console_poll(INT timeout);
#endif
IMPORT ER subsystem5_notify(const analyzer_result_t *result,
                               const monitor_incident_outcome_t *outcome);
#endif
