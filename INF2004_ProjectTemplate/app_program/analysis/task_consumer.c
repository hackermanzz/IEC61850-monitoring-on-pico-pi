/** @file task_consumer.c
 *
 * @brief Analysis consumer task: takes capture frames from its mailbox,
 * analyses them, drives incidents and alarms, and publishes analysis health.
 *
 * @par
 * This task is the only owner of the analyzer and of the incident store, so
 * neither needs a lock. Every frame is given back to the capture pool once
 * it has been analysed. Capture sequence gaps are reported to the analyzer,
 * which then checks each stream's own counters.
 *
 * @par
 * With MONITOR_SYNTHETIC the task only checks the capture module's
 * artificial frames, to test frame storage and ownership without Ethernet
 * hardware.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../alarm/alarm.h"
#include "../capture/capture.h"
#include "../health/health.h"
#include "../health/incident_store.h"
#include "../monitor_config.h"
#include "../monitor_stacks.h"
#include "../monitor_time.h"
#include "analyzer.h"
#include "iec_rules.h"
#include "task_consumer.h"

#if MONITOR_STORAGE
#include "../storage/storage_queue.h"
#endif

// Status reporting. The source number identifies the analysis module to the
// health monitor and to the stack report.
//
#define STATUS_SOURCE_ANALYSIS    (3u)
#define STATUS_PERIOD_US          (100000u)
#define RECEIVE_ERROR_FAULT_LIMIT (3u)
#define ANALYSIS_FAULT_NONE       (0u)
#define ANALYSIS_FAULT_RECEIVE    (1u)

// A larger jump means the sequence went backwards or restarted, which is a
// discontinuity but not a count of lost frames.
//
#define MAXIMUM_COUNTED_LOSS (UINT32_MAX / 2u)

// Every capture frame must fit in the analyzer's frame buffers.
//
_Static_assert(CAPTURE_FRAME_CAPACITY <= ANALYZER_MAXIMUM_FRAME_LENGTH,
               "capture frames are larger than the analyzer accepts");

static monitor_analysis_stats_t g_stats;
static monitor_analysis_stats_t g_published_stats;
static uint64_t                 g_last_report_us;
static uint32_t                 g_previous_sequence;
static bool                     gb_have_previous;
static uint32_t                 g_receive_error_count;

#if !MONITOR_SYNTHETIC
static analyzer_result_t g_result;
#endif

// Kernel object handles, created once by task_consumer_init().
//
static ID gh_frames;
static ID gh_stats_lock;

static void consumer_task(INT start_code, void * p_exinf);
static void handle_frame(capture_frame_t * p_frame);
static void check_sequence(uint32_t sequence_number);
static bool analyse_frame(capture_frame_t const * p_frame);
static void release_frame(capture_frame_t * p_frame);
static void note_receive_result(ER result);
static void publish_status(void);
#if !MONITOR_SYNTHETIC
static void handle_result(void);
static void handle_malicious(monitor_incident_outcome_t const * p_outcome);
#endif

/*!
 * @brief Create the frame mailbox and the statistics lock.
 *
 * @return E_OK, or the kernel error code.
 */
ER
task_consumer_init (void)
{
    T_CMBX mailbox = {0};
    T_CMTX lock    = {0};
    ER     result  = E_OK;

    mailbox.mbxatr = TA_TFIFO | TA_MFIFO;
    gh_frames      = tk_cre_mbx(&mailbox);

    if (gh_frames < E_OK)
    {
        result = gh_frames;
    }
    else
    {
        lock.mtxatr   = TA_INHERIT;
        gh_stats_lock = tk_cre_mtx(&lock);

        if (gh_stats_lock < E_OK)
        {
            result = gh_stats_lock;
        }
    }

    return (result);
}

/*!
 * @brief Create and start the analysis consumer task.
 *
 * @return The task ID, or a negative kernel error code.
 */
ID
task_consumer_start (void)
{
    return (app_start_task_ex(consumer_task, MONITOR_ANALYSIS_PRIORITY, TP_PRC1,
                              MONITOR_ANALYSIS_STACK));
}

/*!
 * @brief Send a capture frame to the consumer task.
 *
 * @par
 * On success the consumer task owns the frame and gives it back with
 * capture_frame_release(). On failure the caller still owns it.
 *
 * @param[in] p_frame The frame.
 *
 * @return E_OK, or the kernel error code.
 */
ER
task_consumer_submit (capture_frame_t * p_frame)
{
    ER result = E_PAR;

    if (NULL != p_frame)
    {
        result = tk_snd_mbx(gh_frames, &p_frame->header);
    }

    return (result);
}

/*!
 * @brief Copy the statistics the task last published.
 *
 * @param[out] p_stats Receives the statistics.
 *
 * @return E_OK, or the kernel error code.
 */
ER
task_consumer_read_stats (monitor_analysis_stats_t * p_stats)
{
    ER result = E_PAR;

    if (NULL != p_stats)
    {
        result = tk_loc_mtx(gh_stats_lock, TMO_FEVR);

        if (E_OK == result)
        {
            *p_stats = g_published_stats;
            result   = tk_unl_mtx(gh_stats_lock);
        }
    }

    return (result);
}

/*!
 * @brief The analysis consumer task.
 *
 * @param[in] start_code The kernel start code (unused).
 * @param[in] p_exinf    The kernel extended information (unused).
 */
static void
consumer_task (INT start_code, void * p_exinf)
{
    // The casts mark parameters the kernel task signature requires but this
    // task does not use.
    (void) start_code;
    (void) p_exinf;

    analyzer_reset();

    // The cast is safe: only the low 32 bits are needed as a session number.
    monitor_incident_init((uint32_t) monitor_time_us());

    for (;;)
    {
        capture_frame_t * p_frame = NULL;

        // The cast is safe: every message in this mailbox is a
        // capture_frame_t, whose first member is its T_MSG header.
        ER const result =
            tk_rcv_mbx(gh_frames, (T_MSG **) &p_frame, MONITOR_IDLE_MS);

        note_receive_result(result);

        if (E_OK == result)
        {
            handle_frame(p_frame);
        }

        monitor_incident_expire(monitor_time_us());
#if MONITOR_STORAGE
        monitor_storage_service_acks();
#endif
#if !MONITOR_SYNTHETIC
        iec_rules_poll(monitor_time_us());
#endif

        if ((monitor_time_us() - g_last_report_us) >= STATUS_PERIOD_US)
        {
            publish_status();
        }
    }
}

/*!
 * @brief Analyse one received frame and give it back to the pool.
 *
 * @param[in] p_frame The frame; owned by this task until it is released.
 */
static void
handle_frame (capture_frame_t * p_frame)
{
    uint64_t const start_us = monitor_time_us();
    uint32_t       elapsed  = 0u;

    g_stats.received++;
    check_sequence(p_frame->sequence_number);

    if (analyse_frame(p_frame))
    {
        g_stats.accepted++;
#if !MONITOR_SYNTHETIC
        handle_result();
#endif
    }
    else
    {
        g_stats.rejected++;
    }

    release_frame(p_frame);

    // The cast is safe: analysing one frame takes far less than 71 minutes.
    elapsed = (uint32_t) (monitor_time_us() - start_us);

    if (elapsed > g_stats.analysis_max_us)
    {
        g_stats.analysis_max_us = elapsed;
    }
}

/*!
 * @brief Count frames lost before analysis and tell the analyzer.
 *
 * @param[in] sequence_number The frame's capture sequence number.
 */
static void
check_sequence (uint32_t sequence_number)
{
    if (gb_have_previous && (sequence_number != (g_previous_sequence + 1u)))
    {
        uint32_t const lost = sequence_number - g_previous_sequence - 1u;

        g_stats.sequence_gaps++;

        if (lost < MAXIMUM_COUNTED_LOSS)
        {
            g_stats.missing_frames += lost;
        }

        analyzer_note_capture_gap();
    }

    g_previous_sequence = sequence_number;
    gb_have_previous    = true;
}

/*!
 * @brief Analyse the bytes of one frame.
 *
 * @param[in] p_frame The frame.
 *
 * @return True if the frame was accepted.
 */
static bool
analyse_frame (capture_frame_t const * p_frame)
{
    bool b_parsed = false;

    if (p_frame->valid_byte_count <= CAPTURE_FRAME_CAPACITY)
    {
#if MONITOR_SYNTHETIC
        // NOTE: Must match the artificial frame of the capture module.
        static uint8_t const expected[] = {0xDEu, 0xADu, 0xBEu, 0xEFu};

        b_parsed =
            (sizeof(expected) == p_frame->valid_byte_count)
            && (0 == memcmp(p_frame->frame_data, expected, sizeof(expected)));
#else
        b_parsed = analyzer_process_capture(
            p_frame->frame_data, p_frame->valid_byte_count,
            p_frame->timestamp_us, p_frame->sequence_number, &g_result);
#endif
    }

    return (b_parsed);
}

/*!
 * @brief Give a frame back to the capture pool, counting failures.
 *
 * @param[in] p_frame The frame.
 */
static void
release_frame (capture_frame_t * p_frame)
{
    ER const result = capture_frame_release(p_frame);

    if (E_OK != result)
    {
        g_stats.cleanup_failed++;
        CHECK(result, "frame cleanup");
    }
}

/*!
 * @brief Track mailbox receive errors.
 *
 * @par
 * Waiting for traffic is healthy; several receive errors in a row are a
 * fault.
 *
 * @param[in] result The result of tk_rcv_mbx().
 */
static void
note_receive_result (ER result)
{
    if ((E_OK == result) || (E_TMOUT == result))
    {
        g_receive_error_count = 0u;
        g_stats.fault         = ANALYSIS_FAULT_NONE;
    }
    else
    {
        g_stats.receive_errors++;
        g_receive_error_count++;

        if (g_receive_error_count >= RECEIVE_ERROR_FAULT_LIMIT)
        {
            g_stats.fault = ANALYSIS_FAULT_RECEIVE;
        }

        CHECK(result, "frame receive");
    }
}

/*!
 * @brief Publish the analysis statistics to the test reader and the health
 *        monitor.
 */
static void
publish_status (void)
{
    monitor_status_message_t message = {0};

    g_stats.heartbeat++;
    monitor_incident_stats(&g_stats.incidents);
    iec_rules_stats(&g_stats.rules);

    // Never block the analysis task: if a reader holds the lock, the copy is
    // simply updated at the next report.
    if (E_OK == tk_loc_mtx(gh_stats_lock, TMO_POL))
    {
        g_published_stats = g_stats;
        CHECK(tk_unl_mtx(gh_stats_lock), "stats unlock");
    }

    message.source        = STATUS_SOURCE_ANALYSIS;
    message.generated_us  = monitor_time_us();
    message.data.analysis = g_stats;

    if (E_OK != health_publish(&message))
    {
        g_stats.summary_dropped++;
    }

    g_last_report_us = monitor_time_us();
    MONITOR_STACK_REPORT(STATUS_SOURCE_ANALYSIS);
}

#if !MONITOR_SYNTHETIC

/*!
 * @brief Act on the analyzer result of an accepted frame.
 */
static void
handle_result (void)
{
    if (g_result.stream_reset)
    {
        g_stats.stream_resets++;
        monitor_incident_reset_stream(g_result.protocol, g_result.stream_key,
                                      g_result.appid, g_result.timestamp_us);
    }

    if (g_result.prediction_ready)
    {
        monitor_incident_outcome_t const outcome =
            monitor_incident_observe(&g_result, analyzer_copy_batch_frame);

        g_stats.predictions++;

        if (outcome.malicious)
        {
            handle_malicious(&outcome);
        }
    }
}

/*!
 * @brief Raise the alarm for a malicious window, and report a new episode.
 *
 * @param[in] p_outcome The incident store's decision.
 */
static void
handle_malicious (monitor_incident_outcome_t const * p_outcome)
{
    CHECK(alarm_raise(), "alarm signal");

    if (p_outcome->new_episode)
    {
        if (E_OK != alarm_notify(&g_result, p_outcome))
        {
            g_stats.notification_dropped++;
        }

#if MONITOR_STORAGE
        if (E_OK != monitor_storage_submit(&g_result, p_outcome))
        {
            g_stats.storage_dropped++;
        }
#endif
    }
}

#endif /* !MONITOR_SYNTHETIC */

/*** end of file ***/
