/** @file console_queue.h
 * @brief Bounded single-producer/single-consumer complete-line queue.
 */
#ifndef CONSOLE_QUEUE_H
#define CONSOLE_QUEUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#define CONSOLE_QUEUE_BYTES (2048u)
#define CONSOLE_LINE_BYTES  (256u)

typedef struct
{
    uint8_t     bytes[CONSOLE_QUEUE_BYTES];
    uint8_t     line[CONSOLE_LINE_BYTES];
    uint32_t    line_used;
    bool        discarding;
    atomic_uint write_cursor;
    atomic_uint read_cursor;
    atomic_uint dropped_lines;
} console_queue_t;

void console_queue_init(console_queue_t * p_queue);
/** @brief Producer only. Overlong/full lines drop whole, through newline. */
void console_queue_write(console_queue_t * p_queue, const char * p_text,
                         size_t length);
/** @brief Consumer only. Peek retains ownership until consume. */
size_t   console_queue_peek(const console_queue_t * p_queue, char * p_output,
                            size_t capacity);
void     console_queue_consume(console_queue_t * p_queue, size_t length);
uint32_t console_queue_pending(const console_queue_t * p_queue);
uint32_t console_queue_dropped(const console_queue_t * p_queue);

#endif /* CONSOLE_QUEUE_H */

/*** end of file ***/
