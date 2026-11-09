/** @file detection.c
 * @brief One Core0 watchdog supervisor observes three independent task beats.
 */
#include "detection.h"
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include "hardware/sync.h"
#include "hardware/watchdog.h"
#include "pico/time.h"
#include "tk/tkernel.h"
#include "evidence.h"
#include "../alarm/alarm.h"
#include "../analysis/incident.h"

#define HEALTH_STACK_WORDS   (512u)
#define HEALTH_STACK_PATTERN (0xa5a5a5a5u)
#ifndef DETECTION_WATCHDOG_RESET
#define DETECTION_WATCHDOG_RESET (0)
#endif
#ifndef DETECTION_STALL_OWNER
#define DETECTION_STALL_OWNER (-1)
#endif
#ifndef DETECTION_STALL_AFTER_MS
#define DETECTION_STALL_AFTER_MS (10000u)
#endif
#ifndef DETECTION_ALARM_GPIO
#define DETECTION_ALARM_GPIO (-1)
#endif

_Alignas(8) static uint32_t g_stack[HEALTH_STACK_WORDS];
static atomic_uint   g_beats[SUPERVISION_OWNERS];
static atomic_uint   g_stalled;
static atomic_uint   g_checks;
static atomic_uint   g_injected;
static atomic_uint   g_stack_used;
static uint64_t      g_started_us;
static atomic_bool   gb_services_started;
static supervision_t g_supervisor;

static void detection_supervisor(INT code, void * p_exinf);

bool
detection_init (void)
{
    incident_init();
    return alarm_init();
}

bool
detection_start (void)
{
    T_CTSK task  = {0};
    ID     id    = 0;
    size_t index = 0u;
    for (index = 0u; HEALTH_STACK_WORDS > index; index++)
    {
        g_stack[index] = HEALTH_STACK_PATTERN;
    }
    task.tskatr  = TA_HLNG | TA_USERBUF | TA_ASSPRC;
    task.task    = (FP) detection_supervisor;
    task.itskpri = 6;
    task.stksz   = sizeof(g_stack);
    task.bufptr  = g_stack;
    task.assprc  = TP_PRC1;
    id           = tk_cre_tsk(&task);
    if (0 >= id)
    {
        return false;
    }
    g_started_us = time_us_64();
    atomic_store_explicit(&gb_services_started, true, memory_order_release);
    if (!alarm_start())
    {
        (void) tk_del_tsk(id);
        return false;
    }
    if (E_OK != tk_sta_tsk(id, 0))
    {
        (void) tk_del_tsk(id);
        return false;
    }
    return true;
}

void
detection_observe (const analyzer_result_t * p_result)
{
    incident_event_t event = {0};
    if (incident_observe(p_result, time_us_64(), &event))
    {
        alarm_submit(&event);
    }
}

void
detection_heartbeat (uint32_t owner)
{
    if (SUPERVISION_OWNERS > owner)
    {
        /* Deliberate task stall, with interrupts/kernel scheduling still on.
         * Built only when explicitly selected; never infer a cable unplug
         * or healthy idle period is a software-stall test.
         */
        if (((int32_t) owner == DETECTION_STALL_OWNER)
            && atomic_load_explicit(&gb_services_started, memory_order_acquire)
            && (time_us_64() - g_started_us
                >= (uint64_t) DETECTION_STALL_AFTER_MS * 1000u))
        {
            atomic_fetch_or(&g_injected, 1u << owner);
            for (;;)
            {
                (void) tk_dly_tsk(1000u);
            }
        }
        atomic_fetch_add_explicit(&g_beats[owner], 1u, memory_order_release);
    }
}

static void
detection_supervisor (INT code, void * p_exinf)
{
    uint32_t counts[SUPERVISION_OWNERS] = {0};
    uint32_t untouched                  = 0u;
    size_t   index                      = 0u;
    (void) code;
    (void) p_exinf;
    supervision_init(&g_supervisor, time_us_64());
#if DETECTION_WATCHDOG_RESET
    /* No other task/IRQ feeds this watchdog. If the supervisor itself stops
     * running, the hardware also resets. No reset occurs in monitor mode.
     */
    watchdog_enable(3000u, true);
#endif
    for (;;)
    {
        /* SEV wakes Core1's idle WFE without adding a packet-service sleep.
         * Its loop must make progress even with a disconnected/quiet cable.
         */
        __sev();
        for (index = 0u; SUPERVISION_OWNERS > index; index++)
        {
            counts[index] =
                atomic_load_explicit(&g_beats[index], memory_order_acquire);
        }
        if (supervision_check(&g_supervisor, counts, time_us_64()))
        {
#if DETECTION_WATCHDOG_RESET
            watchdog_update();
#endif
        }
        atomic_store(&g_stalled, g_supervisor.stalled_mask);
        atomic_fetch_add(&g_checks, 1u);
        untouched = 0u;
        while ((HEALTH_STACK_WORDS > untouched)
               && (HEALTH_STACK_PATTERN == g_stack[untouched]))
        {
            untouched++;
        }
        atomic_store(&g_stack_used,
                     (HEALTH_STACK_WORDS - untouched) * sizeof(uint32_t));
        (void) tk_dly_tsk(50u);
    }
}

void
detection_report (void)
{
    incident_stats_t incident = {0};
    evidence_stats_t evidence = {0};
    alarm_stats_t    alarm    = {0};
    incident_stats(&incident);
    evidence_stats(&evidence);
    alarm_stats(&alarm);
    printf("INC incidents=%" PRIu32 " positives=%" PRIu32 " repeated=%" PRIu32
           " untracked=%" PRIu32 "\n",
           incident.incidents, incident.positive_windows,
           incident.repeated_windows, incident.untracked_windows);
#if PORT_STORAGE
    printf("EVID occupied=%" PRIu32 "/2 saved_total=%" PRIu32
           " released=%" PRIu32 " ack_rejected=%" PRIu32 "\n",
           evidence.occupied, evidence.saved, evidence.released,
           evidence.ack_rejected);
#else
    printf("EVID saved=%" PRIu32 "/2 full=%" PRIu32 " copy_errors=%" PRIu32
           " bytes_per_slot=%u\n",
           evidence.saved, evidence.full, evidence.copy_errors,
           (unsigned) sizeof(evidence_record_t));
#endif
    printf("ALARM requested=%" PRIu32 " applied=%" PRIu32
           " gpio=%d events=%" PRIu32 " queue_drop=%" PRIu32
           " stack_used=%" PRIu32 "/2048\n",
           alarm.requested_mask, alarm.applied_mask, DETECTION_ALARM_GPIO,
           alarm.events, alarm.queue_drops, alarm.stack_used);
    printf("ALARM first_request_us=%" PRIu64 " first_apply_us=%" PRIu64
           " window_to_service_max_us=%" PRIu32
           " newest_to_service_max_us=%" PRIu32 "\n",
           alarm.first_request_us, alarm.first_apply_us,
           alarm.max_window_to_service_us, alarm.max_newest_to_service_us);
    printf("HEALTH checks=%u stalled_mask=%u injected_mask=%u reset=%u"
           " beats=%u/%u/%u stack_used=%u/2048\n",
           atomic_load(&g_checks), atomic_load(&g_stalled),
           atomic_load(&g_injected), DETECTION_WATCHDOG_RESET,
           atomic_load(&g_beats[0]), atomic_load(&g_beats[1]),
           atomic_load(&g_beats[2]), atomic_load(&g_stack_used));
}

/*** end of file ***/
