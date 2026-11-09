/** @file console_queue.c
 * @brief Publish whole lines; never discard a suffix and splice two reports.
 */
#include "console_queue.h"
#include <string.h>

_Static_assert(2 == ATOMIC_INT_LOCK_FREE, "Lock-free console cursors required");

void
console_queue_init (console_queue_t * p_queue)
{
    memset(p_queue, 0, sizeof(*p_queue));
    atomic_init(&p_queue->write_cursor, 0u);
    atomic_init(&p_queue->read_cursor, 0u);
    atomic_init(&p_queue->dropped_lines, 0u);
}

static void
console_queue_publish (console_queue_t * p_queue)
{
    uint32_t write =
        atomic_load_explicit(&p_queue->write_cursor, memory_order_relaxed);
    uint32_t read =
        atomic_load_explicit(&p_queue->read_cursor, memory_order_acquire);
    uint32_t length = p_queue->line_used + 2u;

    if (p_queue->discarding
        || (CONSOLE_QUEUE_BYTES - (write - read) < length + 2u))
    {
        atomic_fetch_add(&p_queue->dropped_lines, 1u);
    }
    else
    {
        p_queue->line[p_queue->line_used]           = '\r';
        p_queue->line[p_queue->line_used + 1u]      = '\n';
        p_queue->bytes[write % CONSOLE_QUEUE_BYTES] = (uint8_t) length;
        p_queue->bytes[(write + 1u) % CONSOLE_QUEUE_BYTES] =
            (uint8_t) (length >> 8u);
        for (uint32_t index = 0u; length > index; index++)
        {
            p_queue->bytes[(write + 2u + index) % CONSOLE_QUEUE_BYTES] =
                p_queue->line[index];
        }
        atomic_store_explicit(&p_queue->write_cursor, write + length + 2u,
                              memory_order_release);
    }
    p_queue->line_used  = 0u;
    p_queue->discarding = false;
}

void
console_queue_write (console_queue_t * p_queue, const char * p_text,
                     size_t length)
{
    for (size_t index = 0u; length > index; index++)
    {
        if ('\n' == p_text[index])
        {
            console_queue_publish(p_queue);
        }
        else if ('\r' != p_text[index])
        {
            if (CONSOLE_LINE_BYTES - 2u > p_queue->line_used)
            {
                p_queue->line[p_queue->line_used++] = (uint8_t) p_text[index];
            }
            else
            {
                p_queue->discarding = true;
            }
        }
    }
}

size_t
console_queue_peek (const console_queue_t * p_queue, char * p_output,
                    size_t capacity)
{
    uint32_t read =
        atomic_load_explicit(&p_queue->read_cursor, memory_order_relaxed);
    uint32_t write =
        atomic_load_explicit(&p_queue->write_cursor, memory_order_acquire);
    uint32_t length = 0u;

    if (2u <= write - read)
    {
        length = p_queue->bytes[read % CONSOLE_QUEUE_BYTES]
               | ((uint32_t) p_queue->bytes[(read + 1u) % CONSOLE_QUEUE_BYTES]
                  << 8u);
        if ((CONSOLE_LINE_BYTES < length) || (length + 2u > write - read)
            || (capacity < length))
        {
            return 0u;
        }
        for (uint32_t index = 0u; length > index; index++)
        {
            p_output[index] =
                (char)
                    p_queue->bytes[(read + 2u + index) % CONSOLE_QUEUE_BYTES];
        }
    }
    return length;
}

void
console_queue_consume (console_queue_t * p_queue, size_t length)
{
    uint32_t read =
        atomic_load_explicit(&p_queue->read_cursor, memory_order_relaxed);
    atomic_store_explicit(&p_queue->read_cursor, read + (uint32_t) length + 2u,
                          memory_order_release);
}

uint32_t
console_queue_pending (const console_queue_t * p_queue)
{
    uint32_t read =
        atomic_load_explicit(&p_queue->read_cursor, memory_order_acquire);
    uint32_t write =
        atomic_load_explicit(&p_queue->write_cursor, memory_order_acquire);
    return write - read;
}

uint32_t
console_queue_dropped (const console_queue_t * p_queue)
{
    return atomic_load(&p_queue->dropped_lines);
}

/*** end of file ***/
