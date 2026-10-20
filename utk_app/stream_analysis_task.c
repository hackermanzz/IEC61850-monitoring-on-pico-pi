/*
 * stream_analysis_task.c  (owner: Buddy 3, Shaun)
 * Consumer side of the capture path for the µT-Kernel 3 SMP build.
 *
 *   mbx_frames --(block)--> analyzer --(event)--> mbf_pred (Incident Mgr)
 *                  |                      \--(evidence block) mpf_evidence
 *                  \--> tk_rel_mpf(block) back to the capture pool
 *
 * This task never waits on the Incident Manager: every send uses TMO_POL
 * and a full queue is counted, so a slow consumer cannot stall analysis.
 */
/* µT-Kernel's syslib.h would typedef size_t as a signed type, which
 * clashes with <stddef.h> used by the analyzer and SDK. Keep the C one. */
#define PROHIBIT_DEF_SIZE_T (1)
#include <stddef.h>

#include <tk/tkernel.h>
#include <tm/tmonitor.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "analyzer.h"
#include "app_config.h"
#include "app_messages.h"
#include "rmii_capture_hw.h" /* rmii_hw_time_us(): plain timer read */
#include "stream_analysis_task.h"

#define MALICIOUS_LABEL (1u)

volatile stream_analysis_stats_t g_stream_analysis_stats;

static ID       g_pool_id;
static ID       g_mailbox_id;
static ID       g_mbf_id;
static ID       g_evidence_id;
static uint32_t g_previous_seq;
static bool     g_have_previous;
static uint64_t g_overload_window_start_us;
static uint32_t g_overload_window_lost;
static bool     g_overload_reported;
/* Large, so static rather than on the task stack. */
static analyzer_result_t g_result;

static void
publish (void)
{
    __asm volatile("dmb" ::: "memory");
}

static void
send_event (const is18_event_t * event)
{
    if (tk_snd_mbf(g_mbf_id, (void *) event, (INT) sizeof(*event), TMO_POL) !=
        E_OK)
    {
        ++g_stream_analysis_stats.events_dropped;
        if (event->evidence != NULL)
        {
            (void) tk_rel_mpf(g_evidence_id, event->evidence);
        }
    }
}

/* FR8: count lost frames in a 1 s window; too many is itself suspicious
 * (flooding) and is reported instead of being silently absorbed. */
static void
check_overload (uint32_t lost, uint64_t now_us)
{
    is18_event_t event = {0};

    if (now_us - g_overload_window_start_us > IS18_OVERLOAD_WINDOW_US)
    {
        g_overload_window_start_us = now_us;
        g_overload_window_lost     = 0u;
        g_overload_reported        = false;
    }
    g_overload_window_lost += lost;
    if (g_overload_window_lost > IS18_OVERLOAD_FRAMES && !g_overload_reported)
    {
        g_overload_reported = true;
        ++g_stream_analysis_stats.overload_warnings;
        event.kind         = (uint8_t) IS18_EVENT_OVERLOAD;
        event.first_seq    = g_overload_window_lost;
        event.timestamp_us = now_us;
        send_event(&event);
    }
}

static void
note_sequence (const is18_frame_block_t * block)
{
    is18_event_t event = {0};
    uint32_t     lost  = 0u;

    if (g_have_previous && block->seq != g_previous_seq + 1u)
    {
        lost = block->seq - g_previous_seq - 1u;
        ++g_stream_analysis_stats.gaps;
        g_stream_analysis_stats.frames_lost += lost;
        /* Mark streams as suspect; each one checks its own counter on its
         * next frame instead of everything being reset. */
        analyzer_note_capture_gap();
        event.kind         = (uint8_t) IS18_EVENT_CAPTURE_GAP;
        event.first_seq    = g_previous_seq + 1u;
        event.last_seq     = block->seq - 1u;
        event.timestamp_us = block->timestamp_us;
        send_event(&event);
        check_overload(lost, block->timestamp_us);
    }
    g_previous_seq  = block->seq;
    g_have_previous = true;
}

static is18_evidence_t *
take_evidence (void)
{
    is18_evidence_t * evidence = NULL;
    size_t            index    = 0u;

    if (tk_get_mpf(g_evidence_id, (void **) &evidence, TMO_POL) != E_OK)
    {
        ++g_stream_analysis_stats.evidence_pool_empty;
        return NULL;
    }
    for (index = 0u; index < ANALYZER_BATCH_FRAME_COUNT; ++index)
    {
        (void) analyzer_copy_last_batch_metadata(index,
                                                 &evidence->packets[index]);
    }
    evidence->newest_length = 0u;
    if (analyzer_copy_last_batch_frame(ANALYZER_NEWEST_FRAME_INDEX,
                                       evidence->newest_frame,
                                       sizeof(evidence->newest_frame), NULL))
    {
        evidence->newest_length =
            evidence->packets[ANALYZER_NEWEST_FRAME_INDEX].frame_length;
    }
    ++g_stream_analysis_stats.evidence_attached;
    return evidence;
}

static void
report_result (const analyzer_result_t * result)
{
    is18_event_t event = {0};

    event.protocol     = (uint8_t) result->protocol;
    event.appid        = result->appid;
    event.stream_key   = result->stream_key;
    event.timestamp_us = result->timestamp_us;

    if (result->stream_reset)
    {
        ++g_stream_analysis_stats.stream_resets;
        event.kind = (uint8_t) IS18_EVENT_STREAM_RESET;
        send_event(&event);
    }
    if (!result->prediction_ready)
    {
        return;
    }
    ++g_stream_analysis_stats.predictions;
    event.kind        = (uint8_t) IS18_EVENT_PREDICTION;
    event.probability = result->primary_probability;
    event.label       = result->primary_label;
    event.first_seq   = result->batch_packets[0].capture_sequence;
    event.last_seq =
        result->batch_packets[ANALYZER_NEWEST_FRAME_INDEX].capture_sequence;
    /* Copy evidence now: the next analyzer call overwrites the snapshot. */
    event.evidence =
        result->primary_label == MALICIOUS_LABEL ? take_evidence() : NULL;
    send_event(&event);
}

static void
analyse_block (const is18_frame_block_t * block)
{
    uint64_t started = 0u;
    uint32_t elapsed = 0u;
    bool     parsed  = false;

    ++g_stream_analysis_stats.frames;
    note_sequence(block);

    started = rmii_hw_time_us();
    memset(&g_result, 0, sizeof(g_result));
    parsed = analyzer_process_ethernet_capture(block->data, block->length,
                                               block->timestamp_us, block->seq,
                                               &g_result);
    elapsed = (uint32_t) (rmii_hw_time_us() - started);

    g_stream_analysis_stats.analyze_last_us = elapsed;
    g_stream_analysis_stats.analyze_total_us += elapsed;
    if (elapsed > g_stream_analysis_stats.analyze_max_us)
    {
        g_stream_analysis_stats.analyze_max_us = elapsed;
    }
    if (elapsed > IS18_FRAME_BUDGET_US)
    {
        ++g_stream_analysis_stats.over_budget;
    }
    if (parsed)
    {
        ++g_stream_analysis_stats.parsed;
        report_result(&g_result);
    }
}

static void
analysis_task (INT stacd, void * exinf)
{
    T_MSG * message = NULL;
    ER      er      = E_OK;

    (void) stacd;
    (void) exinf;

    analyzer_reset();
#if TK_SUPPORT_SMP
    tm_printf((UB *) "analysis: running on processor %d\n", (INT) tk_get_prc());
#endif
    for (;;)
    {
        /* Timeout so the heartbeat moves even with no traffic. */
        er = tk_rcv_mbx(g_mailbox_id, &message, IS18_ANALYSIS_IDLE_MS);
        ++g_stream_analysis_stats.heartbeat;
        if (er == E_OK && message != NULL)
        {
            is18_frame_block_t * block = (is18_frame_block_t *) message;
            analyse_block(block);
            (void) tk_rel_mpf(g_pool_id, block); /* back to capture */
        }
        publish();
    }
}

ID
stream_analysis_task_create (ID frame_pool_id, ID frame_mailbox_id,
                             ID prediction_mbf_id, ID evidence_pool_id)
{
    T_CTSK ctsk = {0};

    g_pool_id     = frame_pool_id;
    g_mailbox_id  = frame_mailbox_id;
    g_mbf_id      = prediction_mbf_id;
    g_evidence_id = evidence_pool_id;
    ctsk.tskatr   = TA_HLNG | TA_RNG0 | TA_ASSPRC;
    ctsk.assprc   = TP_PRC1; /* core 0, with the control tasks */
    ctsk.task     = (FP) analysis_task;
    ctsk.itskpri  = IS18_PRI_ANALYSIS;
    ctsk.stksz    = IS18_STACK_ANALYSIS;
    return tk_cre_tsk(&ctsk);
}
