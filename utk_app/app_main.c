/*
 * app_main.c  (integration skeleton; kernel object table owner: Buddy 5)
 * Creates the kernel objects and starts the capture and analysis tasks so
 * the Week 10 partial demo can run: capture on core 1, analysis on core 0,
 * events printed by a temporary sink in place of the Incident Manager.
 *
 * Replace incident_sink_task with Sean's Incident Manager when it is ready;
 * it must keep the same rule: release every evidence block it receives.
 */
/* µT-Kernel's syslib.h would typedef size_t as a signed type, which
 * clashes with <stddef.h> used by the analyzer and SDK. Keep the C one. */
#define PROHIBIT_DEF_SIZE_T (1)
#include <stddef.h>

#include <tk/tkernel.h>
#include <tm/tmonitor.h>

#include <stdint.h>

#include "app_config.h"
#include "app_messages.h"
#include "rmii_capture_task.h"
#include "stream_analysis_task.h"

#define SINK_STACK_BYTES   (4096)
#define STATS_INTERVAL_MS  (10000)
#define MBF_HEADER_BYTES   (8u)

ID g_is18_mpf_frames;
ID g_is18_mbx_frames;
ID g_is18_mbf_pred;
ID g_is18_mpf_evidence;

/* Static backing stores: visible in the linker map for the RAM budget. */
static uint64_t g_frame_pool_store[(IS18_FRAME_POOL_BLOCKS *
                                    sizeof(is18_frame_block_t)) /
                                   sizeof(uint64_t)];
static uint64_t g_evidence_pool_store[(IS18_EVIDENCE_BLOCKS *
                                       sizeof(is18_evidence_t)) /
                                      sizeof(uint64_t)];
static uint64_t g_pred_mbf_store[(IS18_PRED_EVENTS *
                                  (sizeof(is18_event_t) + MBF_HEADER_BYTES)) /
                                 sizeof(uint64_t)];

static BOOL
created (const char * what, ID id)
{
    if (id <= E_OK)
    {
        tm_printf((UB *) "[is18] create %s failed, er=%d\n", what, (INT) id);
        return FALSE;
    }
    return TRUE;
}

/* Temporary stand-in for the Incident Manager (Buddy 4). */
static void
incident_sink_task (INT stacd, void * exinf)
{
    is18_event_t event   = {0};
    INT          size    = 0;
    uint32_t     printed = 0u;

    (void) stacd;
    (void) exinf;
    for (;;)
    {
        size = tk_rcv_mbf(g_is18_mbf_pred, &event, STATS_INTERVAL_MS);
        if (size == (INT) sizeof(event))
        {
            if (event.kind == (uint8_t) IS18_EVENT_PREDICTION &&
                event.label == 1u && printed < 20u)
            {
                ++printed;
                tm_printf((UB *) "suspicious window proto=%d stream=%x "
                                 "seq=%d..%d\n",
                          (INT) event.protocol, (UINT) event.stream_key,
                          (INT) event.first_seq, (INT) event.last_seq);
            }
            if (event.kind == (uint8_t) IS18_EVENT_OVERLOAD)
            {
                tm_printf((UB *) "WARNING capture overload: %d lost in 1 s\n",
                          (INT) event.first_seq);
            }
            if (event.evidence != NULL)
            {
                (void) tk_rel_mpf(g_is18_mpf_evidence, event.evidence);
            }
            continue;
        }
        /* Timeout: 10 s summary (FR9 style). */
        tm_printf((UB *) "stats rx=%d bad_crc=%d pool_empty=%d overrun=%d "
                         "decode_max_us=%d | frames=%d preds=%d gaps=%d "
                         "lost=%d resets=%d analyze_max_us=%d over_budget=%d "
                         "link=%d\n",
                  (INT) g_rmii_capture_stats.rx_frames,
                  (INT) g_rmii_capture_stats.bad_crc,
                  (INT) g_rmii_capture_stats.pool_empty,
                  (INT) g_rmii_capture_stats.rx_overrun,
                  (INT) g_rmii_capture_stats.decode_max_us,
                  (INT) g_stream_analysis_stats.frames,
                  (INT) g_stream_analysis_stats.predictions,
                  (INT) g_stream_analysis_stats.gaps,
                  (INT) g_stream_analysis_stats.frames_lost,
                  (INT) g_stream_analysis_stats.stream_resets,
                  (INT) g_stream_analysis_stats.analyze_max_us,
                  (INT) g_stream_analysis_stats.over_budget,
                  (INT) g_rmii_capture_stats.link_up);
    }
}

EXPORT INT
usermain (void)
{
    T_CMPF cmpf = {0};
    T_CMBX cmbx = {0};
    T_CMBF cmbf = {0};
    T_CTSK ctsk = {0};
    ID     id   = 0;

    cmpf.mpfatr = TA_TFIFO | TA_RNG0 | TA_USERBUF;
    cmpf.mpfcnt = (SZ) IS18_FRAME_POOL_BLOCKS;
    cmpf.blfsz  = (SZ) sizeof(is18_frame_block_t);
    cmpf.bufptr = g_frame_pool_store;
    g_is18_mpf_frames = tk_cre_mpf(&cmpf);
    if (!created("mpf_frames", g_is18_mpf_frames)) return 1;

    cmbx.mbxatr = TA_TFIFO | TA_MFIFO;
    g_is18_mbx_frames = tk_cre_mbx(&cmbx);
    if (!created("mbx_frames", g_is18_mbx_frames)) return 1;

    cmbf.mbfatr = TA_TFIFO | TA_USERBUF;
    cmbf.bufsz  = (SZ) sizeof(g_pred_mbf_store);
    cmbf.maxmsz = (INT) sizeof(is18_event_t);
    cmbf.bufptr = g_pred_mbf_store;
    g_is18_mbf_pred = tk_cre_mbf(&cmbf);
    if (!created("mbf_pred", g_is18_mbf_pred)) return 1;

    cmpf.mpfcnt = (SZ) IS18_EVIDENCE_BLOCKS;
    cmpf.blfsz  = (SZ) sizeof(is18_evidence_t);
    cmpf.bufptr = g_evidence_pool_store;
    g_is18_mpf_evidence = tk_cre_mpf(&cmpf);
    if (!created("mpf_evidence", g_is18_mpf_evidence)) return 1;

    id = rmii_capture_task_create(g_is18_mpf_frames, g_is18_mbx_frames);
    if (created("capture task", id)) (void) tk_sta_tsk(id, 0);

    id = stream_analysis_task_create(g_is18_mpf_frames, g_is18_mbx_frames,
                                     g_is18_mbf_pred, g_is18_mpf_evidence);
    if (created("analysis task", id)) (void) tk_sta_tsk(id, 0);

    ctsk.tskatr  = TA_HLNG | TA_RNG0 | TA_ASSPRC;
    ctsk.assprc  = TP_PRC1;
    ctsk.task    = (FP) incident_sink_task;
    ctsk.itskpri = IS18_PRI_INCIDENT;
    ctsk.stksz   = SINK_STACK_BYTES;
    id = tk_cre_tsk(&ctsk);
    if (created("incident sink", id)) (void) tk_sta_tsk(id, 0);

    /* The initial task must not return, or the kernel shuts down. */
    (void) tk_slp_tsk(TMO_FEVR);
    return 0;
}
