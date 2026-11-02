/** @file subsystem2.c
 *
 * @brief Subsystem 2, Ethernet capture: creates the bounded capture frame
 * pool and starts the capture producer task.
 *
 * @par
 * A counting semaphore guards a fixed-size memory pool, so the semaphore
 * count always equals the number of free frames.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../monitor_config.h"
#include "subsystem2.h"
#include "task_producer.h"

#define POOL_BLOCK_COUNT (MONITOR_FRAME_BLOCKS)
#define ONE_SLOT         (1)

// Kernel object handles, created once by subsystem2_init().
//
static ID gh_frame_slots = 0;
static ID gh_frame_pool  = 0;

/*!
 * @brief Create the frame semaphore and the fixed-size frame pool.
 *
 * @return E_OK, or the kernel error code.
 */
ER
subsystem2_init (void)
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
    }

    return (result);
}

/*!
 * @brief Start the capture producer task.
 *
 * @return E_OK, or the kernel error code.
 */
ER
subsystem2_start (void)
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
subsystem2_frame_acquire (bool * pb_cleanup_failed)
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
 * @param[in] p_frame The frame from subsystem2_frame_acquire().
 *
 * @return E_OK, or the kernel error code.
 */
ER
subsystem2_frame_release (capture_frame_t * p_frame)
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
subsystem2_pool_status (uint32_t * p_free_slots, uint32_t * p_free_blocks)
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

/*** end of file ***/
