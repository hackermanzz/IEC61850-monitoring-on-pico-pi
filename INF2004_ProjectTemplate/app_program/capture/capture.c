/** @file capture.c
 *
 * @brief Ethernet capture: creates the bounded capture frame pool and starts
 * the capture producer task.
 *
 * @par
 * A counting semaphore guards a fixed-size memory pool, so the semaphore
 * count always equals the number of free frames.
 *
 * @par
 * In test builds (APP_TEST) capture_test() runs the on-board tests listed in
 * testing/capture/TEST_LOG.md.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../monitor_config.h"
#include "capture.h"
#include "task_producer.h"

#if APP_TEST
#include "../monitor_status.h"
#include "../test_report.h"
#include "test_rmii_frame.h"
#endif

#define POOL_BLOCK_COUNT (MONITOR_FRAME_BLOCKS)
#define ONE_SLOT         (1)

#if APP_TEST
// On-board test timing, and the LAN8720 identifier in PHY registers 2 and 3
// (the low four bits of register 3 are the silicon revision).
//
#define TEST_SETTLE_MS     (3000)
#define TEST_WINDOW_MS     (5000)
#define LAN8720_ID1        (0x0007u)
#define LAN8720_ID2        (0xC0F0u)
#define PHY_ID2_MODEL_MASK (0xFFF0u)
#endif

// Kernel object handles, created once by capture_init().
//
static ID gh_frame_slots = 0;
static ID gh_frame_pool  = 0;

#if APP_TEST
// Frames held by the pool test.
//
static capture_frame_t * gp_test_frames[POOL_BLOCK_COUNT + 1u];

static size_t test_drain_pool(bool * pb_ran_dry);
static bool   test_frames_distinct(size_t count);
static bool   test_release_frames(size_t count);
#endif

/*!
 * @brief Create the frame semaphore, the fixed-size frame pool and the
 *        statistics lock.
 *
 * @return E_OK, or the kernel error code.
 */
ER
capture_init (void)
{
    T_CSEM slots  = {0};
    T_CMPF pool   = {0};
    ER     result = E_OK;

    slots.sematr   = TA_TFIFO;
    slots.isemcnt  = POOL_BLOCK_COUNT;
    slots.maxsem   = POOL_BLOCK_COUNT;
    gh_frame_slots = tk_cre_sem(&slots);

    if (gh_frame_slots < E_OK)
    {
        result = gh_frame_slots;
    }
    else
    {
        pool.mpfatr   = TA_TFIFO | TA_RNG3;
        pool.mpfcnt   = POOL_BLOCK_COUNT;
        pool.blfsz    = sizeof(capture_frame_t);
        gh_frame_pool = tk_cre_mpf(&pool);

        if (gh_frame_pool < E_OK)
        {
            result = gh_frame_pool;
        }
        else
        {
            result = task_producer_init();
        }
    }

    return (result);
}

/*!
 * @brief Start the capture producer task.
 *
 * @return E_OK, or the kernel error code.
 */
ER
capture_start (void)
{
    ID const task_id = task_producer_start();

    return ((task_id < E_OK) ? task_id : E_OK);
}

/*!
 * @brief Take a free frame from the pool without waiting.
 *
 * @param[out] pb_cleanup_failed Set to true if a slot could not be given
 *                               back after the pool failed; may be NULL.
 *
 * @return The frame, or NULL if none is free.
 */
capture_frame_t *
capture_frame_acquire (bool * pb_cleanup_failed)
{
    capture_frame_t * p_frame = NULL;

    if (E_OK == tk_wai_sem(gh_frame_slots, ONE_SLOT, TMO_POL))
    {
        void * p_block = NULL;

        if (E_OK == tk_get_mpf(gh_frame_pool, &p_block, TMO_POL))
        {
            // The cast is safe: every pool block holds one capture_frame_t.
            p_frame = (capture_frame_t *) p_block;
        }
        else
        {
            // No block was taken, so give the slot back.
            ER const undo_result = tk_sig_sem(gh_frame_slots, ONE_SLOT);

            if ((E_OK != undo_result) && (NULL != pb_cleanup_failed))
            {
                *pb_cleanup_failed = true;
            }
        }
    }

    return (p_frame);
}

/*!
 * @brief Give a frame back to the pool.
 *
 * @param[in] p_frame The frame from capture_frame_acquire().
 *
 * @return E_OK, or the kernel error code.
 */
ER
capture_frame_release (capture_frame_t * p_frame)
{
    ER result = E_PAR;

    if (NULL != p_frame)
    {
        result = tk_rel_mpf(gh_frame_pool, p_frame);

        if (E_OK == result)
        {
            result = tk_sig_sem(gh_frame_slots, ONE_SLOT);
        }
    }

    return (result);
}

/*!
 * @brief Report how many frames are free, for the health monitor.
 *
 * @param[out] p_free_slots  Receives the semaphore count.
 * @param[out] p_free_blocks Receives the free pool block count.
 *
 * @return E_OK, or the kernel error code.
 */
ER
capture_pool_status (uint32_t * p_free_slots, uint32_t * p_free_blocks)
{
    T_RSEM slots  = {0};
    T_RMPF pool   = {0};
    ER     result = E_PAR;

    if ((NULL != p_free_slots) && (NULL != p_free_blocks))
    {
        result = tk_ref_sem(gh_frame_slots, &slots);

        if (E_OK == result)
        {
            result = tk_ref_mpf(gh_frame_pool, &pool);
        }

        if (E_OK == result)
        {
            // The casts are safe: kernel counts are never negative.
            *p_free_slots  = (uint32_t) slots.semcnt;
            *p_free_blocks = (uint32_t) pool.frbcnt;
        }
    }

    return (result);
}

#if APP_TEST

/*!
 * @brief Run the capture tests and print one [TEST] line per check.
 *
 * @par
 * The frame decode cases (RF-xx) and pool cases (CAP-U0x) need no network.
 * The hardware cases (CAP-H0x) need the LAN8720 board, a cable and a
 * GOOSE or SV publisher sending during the five-second window. With
 * MONITOR_SYNTHETIC, CAP-S01 replaces them.
 */
void
capture_test (void)
{
    monitor_capture_stats_t before        = {0};
    monitor_capture_stats_t after         = {0};
    char const *            p_id          = NULL;
    char const *            p_description = NULL;
    size_t                  index         = 0u;
    size_t                  count         = 0u;
    bool                    b_ran_dry     = false;
    bool                    b_read        = false;

    TEST_INIT();

    for (index = 0u; index < test_rmii_frame_count(); ++index)
    {
        bool const b_passed = test_rmii_frame_run(index, &p_id, &p_description);

        TEST_CHECK(p_id, b_passed, p_description);
    }

    TEST_CHECK("CAP-U01", (E_PAR == capture_frame_release(NULL)),
               "releasing NULL is refused");
    count = test_drain_pool(&b_ran_dry);
    TEST_CHECK("CAP-U02", b_ran_dry && (count <= POOL_BLOCK_COUNT),
               "the pool runs dry after at most MONITOR_FRAME_BLOCKS frames");
    TEST_CHECK("CAP-U03", test_frames_distinct(count),
               "pool frames never overlap");
    TEST_CHECK("CAP-U04", test_release_frames(count),
               "every acquired frame is released");

    // The delays only pace the test, so their results are not needed.
    (void) tk_dly_tsk(TEST_SETTLE_MS);
    b_read = (E_OK == task_producer_read_stats(&before));
    (void) tk_dly_tsk(TEST_WINDOW_MS);
    b_read = b_read && (E_OK == task_producer_read_stats(&after));
    TEST_CHECK("CAP-U05", b_read && (after.heartbeat > before.heartbeat),
               "the capture task keeps publishing its status");

#if MONITOR_SYNTHETIC
    TEST_CHECK("CAP-S01", (after.rx_frames > before.rx_frames),
               "synthetic frames are produced");
#else
    TEST_CHECK("CAP-H01", (1u == after.phy_found), "the PHY answers on MDIO");
    TEST_CHECK("CAP-H02",
               (LAN8720_ID1 == after.phy.id1)
                   && (LAN8720_ID2 == (after.phy.id2 & PHY_ID2_MODEL_MASK)),
               "the PHY identifies as a LAN8720");
    TEST_CHECK("CAP-H03", (1u == after.link_up), "the Ethernet link is up");
    TEST_CHECK("CAP-H04", (CAPTURE_FAULT_NONE == after.fault),
               "the receiver started without a fault");
    TEST_CHECK("CAP-H05", (after.rx_frames > before.rx_frames),
               "frames with a valid FCS are received");
    TEST_CHECK("CAP-H06", (after.bad_crc == before.bad_crc),
               "no capture fails its FCS check");
    TEST_CHECK("CAP-H07",
               ((after.last_seq - before.last_seq)
                == ((after.rx_frames - before.rx_frames)
                    - (after.non_iec_dropped - before.non_iec_dropped))),
               "every GOOSE or SV frame gets the next sequence number");
    TEST_CHECK("CAP-H08",
               (after.rx_overrun == before.rx_overrun)
                   && (after.dma_full == before.dma_full),
               "no receive buffer overruns");
#endif

    TEST_SUMMARY("capture");
}

/*!
 * @brief Take frames from the pool until it is empty.
 *
 * @param[out] pb_ran_dry Set to true if the pool ran dry within
 *                        POOL_BLOCK_COUNT + 1 attempts.
 *
 * @return The number of frames taken, stored in gp_test_frames.
 */
static size_t
test_drain_pool (bool * pb_ran_dry)
{
    size_t count     = 0u;
    bool   b_is_done = false;

    while (!b_is_done && (count <= POOL_BLOCK_COUNT))
    {
        gp_test_frames[count] = capture_frame_acquire(NULL);

        if (NULL == gp_test_frames[count])
        {
            b_is_done = true;
        }
        else
        {
            count++;
        }
    }

    *pb_ran_dry = b_is_done;

    return (count);
}

/*!
 * @brief Check that no two taken frames overlap.
 *
 * @param[in] count The number of frames in gp_test_frames.
 *
 * @return True if every pair is at least one frame apart.
 */
static bool
test_frames_distinct (size_t count)
{
    bool   b_distinct = true;
    size_t first      = 0u;
    size_t second     = 0u;

    for (first = 0u; first < count; ++first)
    {
        for (second = first + 1u; second < count; ++second)
        {
            // The casts are safe: they compare addresses as integers.
            uintptr_t const lower  = (uintptr_t) gp_test_frames[first];
            uintptr_t const higher = (uintptr_t) gp_test_frames[second];
            uintptr_t const gap =
                (lower > higher) ? (lower - higher) : (higher - lower);

            b_distinct = b_distinct && (gap >= sizeof(capture_frame_t));
        }
    }

    return (b_distinct);
}

/*!
 * @brief Give every taken frame back to the pool.
 *
 * @param[in] count The number of frames in gp_test_frames.
 *
 * @return True if every release succeeded.
 */
static bool
test_release_frames (size_t count)
{
    bool   b_released = true;
    size_t index      = 0u;

    for (index = 0u; index < count; ++index)
    {
        b_released = (E_OK == capture_frame_release(gp_test_frames[index]))
                  && b_released;
        gp_test_frames[index] = NULL;
    }

    return (b_released);
}

#endif /* APP_TEST */

/*** end of file ***/
