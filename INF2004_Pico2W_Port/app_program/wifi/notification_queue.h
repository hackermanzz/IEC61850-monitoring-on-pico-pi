/** @file notification_queue.h
 * @brief Eight copied alerts (five possible boot incidents); one producer and
 * one consumer.
 */
#ifndef NOTIFICATION_QUEUE_H
#define NOTIFICATION_QUEUE_H
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#define NOTIFICATION_QUEUE_COUNT (8u)
#define NOTIFICATION_TEXT_BYTES  (256u)
typedef struct
{
    uint64_t created_us;
    char     text[NOTIFICATION_TEXT_BYTES];
} notification_message_t;
typedef struct
{
    notification_message_t messages[NOTIFICATION_QUEUE_COUNT];
    atomic_uint            written;
    atomic_uint            read;
    atomic_uint            dropped;
} notification_queue_t;
bool notification_queue_put(notification_queue_t *         p_queue,
                            const notification_message_t * p_message);
bool notification_queue_take(notification_queue_t *   p_queue,
                             notification_message_t * p_message);
#endif

/*** end of file ***/
