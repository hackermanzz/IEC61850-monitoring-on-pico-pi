/** @file capture_pipe.c
 * @brief Transfer pointers without copying 1.5 KiB frames through kernel
 * queues.
 *
 * Pool: eight preallocated frame blocks. Queue: four pointer messages.
 * Non-waiting producer calls retain ownership on failure. The consumer must
 * return each successful receive exactly once, after its final read.
 */
#include "capture_pipe.h"

#if PORT_CAPTURE
#include <stdatomic.h>  /* Ownership transitions visible to both cores. */
#include <stddef.h>     /* NULL and exact object sizes. */
#include "tk/tkernel.h" /* Course fixed memory pool and message buffer APIs. */

typedef enum
{
    FRAME_FREE,
    FRAME_PRODUCER,
    FRAME_QUEUED,
    FRAME_CONSUMER
} frame_owner_t;

/* Size is a multiple of eight: the kernel rounds pool blocks to alignment. */
_Static_assert(0u == sizeof(capture_frame_t) % 8u, "Frame pool alignment");
_Alignas(8) static capture_frame_t g_frames[CAPTURE_POOL_COUNT];
_Alignas(8) static uint8_t
    g_messages[CAPTURE_QUEUE_COUNT * (sizeof(INT) + sizeof(capture_frame_t *))];
static atomic_uint g_owners[CAPTURE_POOL_COUNT];
static atomic_uint g_pool_drops;
static atomic_uint g_queue_drops;
static atomic_uint g_errors;
static atomic_uint g_generation;
static ID          g_pool;
static ID          g_queue;

static bool capture_pipe_transition(capture_frame_t * p_frame, uint32_t from,
                                    uint32_t to);
static bool capture_pipe_return(capture_frame_t * p_frame, uint32_t owner);

/** @brief Reject foreign/misaligned pointers before accessing owner metadata.
 */
static bool
capture_pipe_transition (capture_frame_t * p_frame, uint32_t from, uint32_t to)
{
    uintptr_t address = (uintptr_t) p_frame;
    uintptr_t base    = (uintptr_t) g_frames;
    bool      b_ok    = false;

    if ((base <= address) && (sizeof(g_frames) > address - base)
        && (0u == (address - base) % sizeof(capture_frame_t)))
    {
        b_ok = atomic_compare_exchange_strong(
            &g_owners[(address - base) / sizeof(capture_frame_t)], &from, to);
    }
    if (!b_ok)
    {
        atomic_fetch_add(&g_errors, 1u);
    }
    return b_ok;
}

bool
capture_pipe_init (void)
{
    T_CMPF pool  = {0};
    T_CMBF queue = {0};

    pool.mpfatr = TA_USERBUF;
    pool.mpfcnt = CAPTURE_POOL_COUNT;
    pool.blfsz  = sizeof(capture_frame_t);
    pool.bufptr = g_frames;
    g_pool      = tk_cre_mpf(&pool);
    if (0 >= g_pool)
    {
        return false;
    }
    queue.mbfatr = TA_USERBUF;
    queue.bufsz  = sizeof(g_messages);
    queue.maxmsz = sizeof(capture_frame_t *);
    queue.bufptr = g_messages;
    g_queue      = tk_cre_mbf(&queue);
    if (0 >= g_queue)
    {
        (void) tk_del_mpf(g_pool);
        return false;
    }
    return true;
}

void
capture_pipe_loss (void)
{
    atomic_fetch_add(&g_generation, 1u);
}

capture_frame_t *
capture_pipe_reserve (void)
{
    void * p_block = NULL;

    if (E_OK != tk_get_mpf(g_pool, &p_block, TMO_POL))
    {
        atomic_fetch_add(&g_pool_drops, 1u);
        capture_pipe_loss();
        return NULL;
    }
    if (!capture_pipe_transition(p_block, FRAME_FREE, FRAME_PRODUCER))
    {
        /* A corrupt owner table is not permission to reuse somebody's block. */
        return NULL;
    }
    return p_block;
}

bool
capture_pipe_offer (capture_frame_t * p_frame)
{
    if (!capture_pipe_transition(p_frame, FRAME_PRODUCER, FRAME_QUEUED))
    {
        return false;
    }
    p_frame->loss_generation = atomic_load(&g_generation);
    /* State must be QUEUED before send: the remote receiver can run before
     * this call returns. On success, never touch the frame again here.
     */
    if (E_OK != tk_snd_mbf(g_queue, &p_frame, sizeof(p_frame), TMO_POL))
    {
        (void) capture_pipe_transition(p_frame, FRAME_QUEUED, FRAME_PRODUCER);
        atomic_fetch_add(&g_queue_drops, 1u);
        capture_pipe_loss();
        return false;
    }
    return true;
}

static bool
capture_pipe_return (capture_frame_t * p_frame, uint32_t owner)
{
    if (!capture_pipe_transition(p_frame, owner, FRAME_FREE))
    {
        return false;
    }
    if (E_OK != tk_rel_mpf(g_pool, p_frame))
    {
        (void) capture_pipe_transition(p_frame, FRAME_FREE, owner);
        atomic_fetch_add(&g_errors, 1u);
        return false;
    }
    return true;
}

bool
capture_pipe_cancel (capture_frame_t * p_frame)
{
    return capture_pipe_return(p_frame, FRAME_PRODUCER);
}

capture_frame_t *
capture_pipe_receive (uint32_t wait_ms)
{
    capture_frame_t * p_frame  = NULL;
    INT               received = tk_rcv_mbf(g_queue, &p_frame, (TMO) wait_ms);

    if (E_TMOUT == received)
    {
        return NULL;
    }
    if ((sizeof(p_frame) != (size_t) received)
        || (!capture_pipe_transition(p_frame, FRAME_QUEUED, FRAME_CONSUMER)))
    {
        atomic_fetch_add(&g_errors, 1u);
        return NULL;
    }
    return p_frame;
}

bool
capture_pipe_release (capture_frame_t * p_frame)
{
    return capture_pipe_return(p_frame, FRAME_CONSUMER);
}

void
capture_pipe_stats (capture_pipe_stats_t * p_stats)
{
    p_stats->pool_drops       = atomic_load(&g_pool_drops);
    p_stats->queue_drops      = atomic_load(&g_queue_drops);
    p_stats->ownership_errors = atomic_load(&g_errors);
    p_stats->loss_generation  = atomic_load(&g_generation);
}

/** @brief Exercise real pool/queue exhaustion without hardware or traffic. */
bool
capture_pipe_self_check (void)
{
    capture_frame_t * p_held[CAPTURE_POOL_COUNT] = {NULL};
    capture_frame_t * p_frame                    = NULL;
    T_RMPF            state                      = {0};
    uint32_t          index                      = 0u;
    bool              b_ok                       = true;

    for (index = 0u; CAPTURE_POOL_COUNT > index; index++)
    {
        p_held[index] = capture_pipe_reserve();
        b_ok          = b_ok && (NULL != p_held[index]);
    }
    p_frame = capture_pipe_reserve();
    b_ok    = b_ok && (NULL == p_frame);
    for (index = 0u; CAPTURE_POOL_COUNT > index; index++)
    {
        b_ok = capture_pipe_cancel(p_held[index]) && b_ok;
    }
    for (index = 0u; CAPTURE_QUEUE_COUNT + 1u > index; index++)
    {
        p_held[index] = capture_pipe_reserve();
        if (NULL == p_held[index])
        {
            return false;
        }
        if (CAPTURE_QUEUE_COUNT > index)
        {
            b_ok = capture_pipe_offer(p_held[index]) && b_ok;
        }
        else
        {
            b_ok = (!capture_pipe_offer(p_held[index])) && b_ok;
            b_ok = capture_pipe_cancel(p_held[index]) && b_ok;
        }
    }
    for (index = 0u; CAPTURE_QUEUE_COUNT > index; index++)
    {
        p_frame = capture_pipe_receive(0u);
        b_ok    = (p_frame == p_held[index]) && b_ok;
        b_ok    = capture_pipe_release(p_frame) && b_ok;
    }
    b_ok = (!capture_pipe_release(p_frame)) && b_ok;
    b_ok = (E_OK == tk_ref_mpf(g_pool, &state)) && b_ok;
    b_ok = (CAPTURE_POOL_COUNT == state.frbcnt) && b_ok;
    b_ok = (1u == atomic_load(&g_pool_drops)) && b_ok;
    b_ok = (1u == atomic_load(&g_queue_drops)) && b_ok;
    b_ok = (1u == atomic_load(&g_errors)) && b_ok;
    /* Expected exhaustion/duplicate-release checks are not live losses. */
    atomic_store(&g_pool_drops, 0u);
    atomic_store(&g_queue_drops, 0u);
    atomic_store(&g_errors, 0u);
    atomic_store(&g_generation, 0u);
    return b_ok;
}
#endif /* PORT_CAPTURE */

/*** end of file ***/
