#ifndef SUBSYSTEM4_H
#define SUBSYSTEM4_H
#define S4_STATUS_QUEUE_DEPTH 8u
#include "../app.h"
#include "../monitor_status.h"
#define S4_SUMMARY_MAX ((INT)sizeof(monitor_status_message_t))
IMPORT ID mbf_summary;
IMPORT ID tid_monitor;
IMPORT ER subsystem4_publish(const monitor_status_message_t *message);
IMPORT void monitor_task(INT stacd, void *exinf);
#endif
