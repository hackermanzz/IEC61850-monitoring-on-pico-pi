/** @file notification_queue.c
 * @brief Publish copied messages only after writes; release slots after reads.
 */
#include "notification_queue.h"
#include <string.h>
_Static_assert(0u
                   == (NOTIFICATION_QUEUE_COUNT
                       & (NOTIFICATION_QUEUE_COUNT - 1u)),
               "Power-of-two capacity preserves unsigned-counter wrap");
_Static_assert(2 == ATOMIC_INT_LOCK_FREE, "Queue counters must be lock-free");
bool
notification_queue_put (notification_queue_t *         p_queue,
                        const notification_message_t * p_message)
{
    unsigned int written =
        atomic_load_explicit(&p_queue->written, memory_order_relaxed);
    unsigned int read =
        atomic_load_explicit(&p_queue->read, memory_order_acquire);
    if (NOTIFICATION_QUEUE_COUNT <= written - read)
    {
        atomic_fetch_add_explicit(&p_queue->dropped, 1u, memory_order_relaxed);
        return false;
    }
    memcpy(&p_queue->messages[written % NOTIFICATION_QUEUE_COUNT], p_message,
           sizeof(*p_message));
    atomic_store_explicit(&p_queue->written, written + 1u,
                          memory_order_release);
    return true;
}
bool
notification_queue_take (notification_queue_t *   p_queue,
                         notification_message_t * p_message)
{
    unsigned int read =
        atomic_load_explicit(&p_queue->read, memory_order_relaxed);
    unsigned int written =
        atomic_load_explicit(&p_queue->written, memory_order_acquire);
    if (written == read)
    {
        return false;
    }
    memcpy(p_message, &p_queue->messages[read % NOTIFICATION_QUEUE_COUNT],
           sizeof(*p_message));
    atomic_store_explicit(&p_queue->read, read + 1u, memory_order_release);
    return true;
}

/*** end of file ***/
