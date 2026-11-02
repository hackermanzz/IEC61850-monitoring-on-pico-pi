/* Compile with the RP2040 ABI; no missing implementation is stubbed or linked. */
#include <stdint.h>
#include <stddef.h>
#include "app_program/app.h"
#include "app_program/subsystem1/storage_queue.h"
#include "app_program/subsystem2/capture_frame.h"
#include "app_program/subsystem3/subsystem3.h"
#include "app_program/subsystem4/subsystem4.h"
#include "app_program/subsystem5/subsystem5.h"
#include "app_program/subsystem5/notification_port.h"

_Static_assert(MONITOR_FOUNDATION_ONLY == 1 && MONITOR_SUBSYSTEM_MASK == 0,
               "foundation must not claim enabled subsystems");
_Static_assert(sizeof(void *) == 4 && sizeof(float) == 4, "RP2040 ABI required");
_Static_assert(offsetof(capture_frame_t, header) == 0, "mailbox linkage must lead");
_Static_assert(sizeof(capture_frame_t) == 1536, "agreed frame block ABI changed");
_Static_assert(CAPTURE_FRAME_CAPACITY == ANALYZER_MAXIMUM_FRAME_LENGTH, "capture/analyzer limits differ");
_Static_assert(ANALYZER_BATCH_FRAME_COUNT == 4, "window contract changed");
_Static_assert(sizeof(monitor_incident_record_t) == 352, "copied export ABI changed");
_Static_assert(sizeof(((monitor_storage_ack_t *)0)->incident_id) == 8, "ACK must retain full ID");
_Static_assert(sizeof(((monitor_record_packet_t *)0)->timestamp_us) == 8, "uptime width changed");
_Static_assert(MONITOR_ALARM_PRIORITY < MONITOR_HEALTH_PRIORITY &&
               MONITOR_HEALTH_PRIORITY < MONITOR_ANALYSIS_PRIORITY, "preemption contract changed");
