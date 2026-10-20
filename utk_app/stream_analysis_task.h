/*
 * stream_analysis_task.h  (owner: Buddy 3, Shaun)
 * Stream Analysis and RF inference as a µT-Kernel task pinned to
 * processor 1 (core 0), priority 6. Tribunal 1 decisions:
 *   - frames arrive as pool blocks through a mailbox (zero copy) and are
 *     released after analysis;
 *   - a capture gap marks streams as suspect instead of resetting all of
 *     them; only streams that really lost frames are reset (FR8);
 *   - more than IS18_OVERLOAD_FRAMES lost in 1 s raises a Capture Overload
 *     Warning;
 *   - each frame is timed against the 7,692 us budget (130 frames/s).
 * Only this task calls the analyzer, so the analyzer needs no lock.
 */
#ifndef STREAM_ANALYSIS_TASK_H
#define STREAM_ANALYSIS_TASK_H

#include <tk/tkernel.h>
#include <stdint.h>

typedef struct
{
    uint32_t heartbeat;           /* +1 per loop, also when idle */
    uint32_t frames;              /* blocks received from capture */
    uint32_t parsed;              /* GOOSE/SV frames the analyzer accepted */
    uint32_t predictions;
    uint32_t gaps;                /* sequence jumps seen */
    uint32_t frames_lost;         /* total frames missing in those jumps */
    uint32_t stream_resets;
    uint32_t overload_warnings;
    uint32_t events_dropped;      /* mbf_pred full */
    uint32_t evidence_attached;
    uint32_t evidence_pool_empty;
    uint32_t analyze_last_us;
    uint32_t analyze_max_us;
    uint32_t analyze_total_us;    /* divide by frames for the average */
    uint32_t over_budget;         /* frames slower than IS18_FRAME_BUDGET_US */
} stream_analysis_stats_t;

extern volatile stream_analysis_stats_t g_stream_analysis_stats;

/* Create (not start) the task. Needs the frame pool and mailbox from the
 * capture side, the prediction message buffer and the evidence pool. */
ID stream_analysis_task_create (ID frame_pool_id, ID frame_mailbox_id,
                                ID prediction_mbf_id, ID evidence_pool_id);

#endif /* STREAM_ANALYSIS_TASK_H */
