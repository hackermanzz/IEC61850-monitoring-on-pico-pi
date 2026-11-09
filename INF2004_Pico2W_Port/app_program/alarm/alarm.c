/** @file alarm.c
 * @brief Core0 priority5 alarm owner; never uses USB, libc state or radio.
 */
#include "alarm.h"
#include <stdatomic.h>
#include <string.h>
#include "hardware/gpio.h"
#include "pico/time.h"
#include "tk/tkernel.h"
#include "../health/detection.h"

#define ALARM_QUEUE_COUNT   (4u)
#define ALARM_STACK_WORDS   (512u)
#define ALARM_STACK_PATTERN (0xa5a5a5a5u)

#ifndef DETECTION_ALARM_GPIO
#define DETECTION_ALARM_GPIO (-1)
#endif
#if (DETECTION_ALARM_GPIO != -1) && (DETECTION_ALARM_GPIO != 19)
#error "Only explicit GP19 is supported; review other pins before enabling"
#endif

_Alignas(8) static uint8_t
    g_queue_bytes[ALARM_QUEUE_COUNT * (sizeof(INT) + sizeof(incident_event_t))];
_Alignas(8) static uint32_t g_stack[ALARM_STACK_WORDS];
static ID          g_queue;
static atomic_uint g_requested;
static atomic_uint g_applied;
static atomic_uint g_drops;
static atomic_uint g_events;
static atomic_uint g_max_window;
static atomic_uint g_max_newest;
static atomic_uint g_stack_used;
/* Immutable after release publication through the corresponding mask. */
static uint64_t g_first_request;
static uint64_t g_first_apply;

static void alarm_task(INT code, void * p_exinf);

/** @brief Startup FIFO/exhaustion test uses copies, without actuating a pin. */
bool
alarm_init (void)
{
    T_CMBF           queue    = {0};
    incident_event_t event    = {0};
    incident_event_t received = {0};
    uint32_t         index    = 0u;
    bool             b_ok     = true;

    queue.mbfatr = TA_USERBUF;
    queue.bufsz  = sizeof(g_queue_bytes);
    queue.maxmsz = sizeof(event);
    queue.bufptr = g_queue_bytes;
    g_queue      = tk_cre_mbf(&queue);
    if (0 >= g_queue)
    {
        return false;
    }
    for (index = 0u; ALARM_QUEUE_COUNT > index; index++)
    {
        event.incident_id = index + 1u;
        b_ok = (E_OK == tk_snd_mbf(g_queue, &event, sizeof(event), TMO_POL))
            && b_ok;
    }
    b_ok = (E_TMOUT == tk_snd_mbf(g_queue, &event, sizeof(event), TMO_POL))
        && b_ok;
    for (index = 0u; ALARM_QUEUE_COUNT > index; index++)
    {
        b_ok =
            ((INT) sizeof(received) == tk_rcv_mbf(g_queue, &received, TMO_POL))
            && b_ok;
        b_ok = (index + 1u == received.incident_id) && b_ok;
    }
    b_ok = (E_TMOUT == tk_rcv_mbf(g_queue, &received, TMO_POL)) && b_ok;
    if (!b_ok)
    {
        (void) tk_del_mbf(g_queue);
    }
    return b_ok;
}

bool
alarm_start (void)
{
    T_CTSK task  = {0};
    ID     id    = 0;
    size_t index = 0u;
    for (index = 0u; ALARM_STACK_WORDS > index; index++)
    {
        g_stack[index] = ALARM_STACK_PATTERN;
    }
    task.tskatr  = TA_HLNG | TA_USERBUF | TA_ASSPRC;
    task.task    = (FP) alarm_task;
    task.itskpri = 5;
    task.stksz   = sizeof(g_stack);
    task.bufptr  = g_stack;
    task.assprc  = TP_PRC1;
    id           = tk_cre_tsk(&task);
    if (0 >= id)
    {
        return false;
    }
#if DETECTION_ALARM_GPIO >= 0
    gpio_init(DETECTION_ALARM_GPIO);
    gpio_put(DETECTION_ALARM_GPIO, false);
    gpio_set_dir(DETECTION_ALARM_GPIO, GPIO_OUT);
#endif
    if (E_OK != tk_sta_tsk(id, 0))
    {
        (void) tk_del_tsk(id);
        return false;
    }
    return true;
}

void
alarm_submit (const incident_event_t * p_event)
{
    uint32_t mask = 0u;
    if ((NULL == p_event) || (1u < p_event->protocol))
    {
        return;
    }
    mask = 1u << p_event->protocol;
    if (0u == atomic_load(&g_requested))
    {
        g_first_request = time_us_64();
    }
    /* The producer is the sole analysis owner. Publish this immutable time
     * before the alarm task can see the first request. Queue fullness affects
     * event telemetry only, never the persistent critical alarm request.
     */
    atomic_fetch_or_explicit(&g_requested, mask, memory_order_release);
    if (E_OK != tk_snd_mbf(g_queue, p_event, sizeof(*p_event), TMO_POL))
    {
        atomic_fetch_add(&g_drops, 1u);
    }
}

/** @brief Monotonic elapsed time saturated to fit published counters. */
static uint32_t
alarm_elapsed (uint64_t now_us, uint64_t then_us)
{
    uint64_t delta = (now_us >= then_us) ? now_us - then_us : 0u;
    return (UINT32_MAX < delta) ? UINT32_MAX : (uint32_t) delta;
}

/** @brief Recheck after a preempting producer, before consuming its event. */
static void
alarm_apply (void)
{
    uint32_t mask = atomic_load_explicit(&g_requested, memory_order_acquire);
    if (mask != atomic_load(&g_applied))
    {
#if DETECTION_ALARM_GPIO >= 0
        gpio_put(DETECTION_ALARM_GPIO, true);
#endif
        if (0u == atomic_load(&g_applied))
        {
            g_first_apply = time_us_64();
        }
        atomic_store_explicit(&g_applied, mask, memory_order_release);
    }
}

void
alarm_service_step (void)
{
    incident_event_t event     = {0};
    uint32_t         elapsed   = 0u;
    uint32_t         untouched = 0u;
    uint64_t         now_us    = 0u;
    INT              received  = 0;
    detection_heartbeat(SUPERVISION_ALARM);
    alarm_apply();
    /* Apply before draining logs. A full/slow queue cannot delay latching.
     * At most four messages per cycle, then yield even under a flood.
     */
    for (uint32_t index = 0u; ALARM_QUEUE_COUNT > index; index++)
    {
        received = tk_rcv_mbf(g_queue, &event, TMO_POL);
        if ((INT) sizeof(event) == received)
        {
            alarm_apply();
            now_us  = time_us_64();
            elapsed = alarm_elapsed(now_us, event.window_start_us);
            if (elapsed > atomic_load(&g_max_window))
            {
                atomic_store(&g_max_window, elapsed);
            }
            elapsed = alarm_elapsed(now_us, event.newest_end_us);
            if (elapsed > atomic_load(&g_max_newest))
            {
                atomic_store(&g_max_newest, elapsed);
            }
            atomic_fetch_add(&g_events, 1u);
        }
    }
    untouched = 0u;
    while ((ALARM_STACK_WORDS > untouched)
           && (ALARM_STACK_PATTERN == g_stack[untouched]))
    {
        untouched++;
    }
    atomic_store(&g_stack_used,
                 (ALARM_STACK_WORDS - untouched) * sizeof(uint32_t));
}

static void
alarm_task (INT code, void * p_exinf)
{
    (void) code;
    (void) p_exinf;
    for (;;)
    {
        alarm_service_step();
        (void) tk_dly_tsk(10u);
    }
}

void
alarm_stats (alarm_stats_t * p_stats)
{
    memset(p_stats, 0, sizeof(*p_stats));
    p_stats->requested_mask =
        atomic_load_explicit(&g_requested, memory_order_acquire);
    p_stats->applied_mask =
        atomic_load_explicit(&g_applied, memory_order_acquire);
    p_stats->queue_drops              = atomic_load(&g_drops);
    p_stats->events                   = atomic_load(&g_events);
    p_stats->max_window_to_service_us = atomic_load(&g_max_window);
    p_stats->max_newest_to_service_us = atomic_load(&g_max_newest);
    p_stats->stack_used               = atomic_load(&g_stack_used);
    if (0u != p_stats->requested_mask)
    {
        p_stats->first_request_us = g_first_request;
    }
    if (0u != p_stats->applied_mask)
    {
        p_stats->first_apply_us = g_first_apply;
    }
}

/*** end of file ***/
