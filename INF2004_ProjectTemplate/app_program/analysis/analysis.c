/** @file analysis.c
 *
 * @brief Analysis and rules: start-up, the frame hand-over from the capture
 * module, and the on-target tests.
 */

#include "../monitor_config.h"
#include "../monitor_status.h"
#include "analysis.h"
#include "task_consumer.h"

#if APP_TEST
#include "../test_report.h"

// Time for the synthetic capture task to deliver a few frames.
//
#define SYNTHETIC_WAIT_MS (2000)
#endif

/*!
 * @brief Create the frame mailbox and the statistics lock.
 *
 * @return E_OK, or the kernel error code.
 */
ER
analysis_init (void)
{
    return (task_consumer_init());
}

/*!
 * @brief Start the analysis consumer task.
 *
 * @return E_OK, or the kernel error code.
 */
ER
analysis_start (void)
{
    ID const task_id = task_consumer_start();

    return ((task_id < E_OK) ? task_id : E_OK);
}

/*!
 * @brief Hand a capture frame over to the analysis task.
 *
 * @par
 * On success the analysis task owns the frame and gives it back with
 * capture_frame_release(). On failure the caller still owns it.
 *
 * @param[in] p_frame The frame.
 *
 * @return E_OK, or the kernel error code.
 */
ER
analysis_submit_frame (capture_frame_t * p_frame)
{
    return (task_consumer_submit(p_frame));
}

#if APP_TEST

/*!
 * @brief Check the published counters, and with MONITOR_SYNTHETIC that
 *        frames reach the analysis task.
 */
void
analysis_test (void)
{
    monitor_analysis_stats_t before = {0};
    ER                       result = E_OK;

    TEST_INIT();

    result = task_consumer_read_stats(&before);
    TEST_CHECK("ANALYSIS-U01",
               (E_OK == result)
                   && (before.received == (before.accepted + before.rejected)),
               "published receive counters are consistent");

#if MONITOR_SYNTHETIC
    {
        monitor_analysis_stats_t after = {0};

        // The delay only paces the test, so its result is not needed.
        (void) tk_dly_tsk(SYNTHETIC_WAIT_MS);
        result = task_consumer_read_stats(&after);
        TEST_CHECK("INT-01",
                   (E_OK == result) && (after.accepted > before.accepted),
                   "synthetic frames reach the consumer");
    }
#endif

    TEST_SUMMARY("analysis");
}

#endif /* APP_TEST */

/*** end of file ***/
