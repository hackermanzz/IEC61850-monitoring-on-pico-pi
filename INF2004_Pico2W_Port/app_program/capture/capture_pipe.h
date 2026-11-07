/** @file capture_pipe.h
 * @brief Bounded frame ownership over real kernel fixed pool/message buffer.
 */
#ifndef CAPTURE_PIPE_H
#define CAPTURE_PIPE_H

#include <stdbool.h>        /* Explicit ownership API success. */
#include "capture_decode.h" /* Shared frame type. */

#define CAPTURE_POOL_COUNT  8u
#define CAPTURE_QUEUE_COUNT 4u

typedef struct
{
    uint32_t pool_drops;
    uint32_t queue_drops;
    uint32_t ownership_errors;
    uint32_t loss_generation;
} capture_pipe_stats_t;

#if PORT_CAPTURE
bool              capture_pipe_init(void);
bool              capture_pipe_self_check(void);
capture_frame_t * capture_pipe_reserve(void);
bool              capture_pipe_offer(capture_frame_t * p_frame);
bool              capture_pipe_cancel(capture_frame_t * p_frame);
capture_frame_t * capture_pipe_receive(uint32_t wait_ms);
bool              capture_pipe_release(capture_frame_t * p_frame);
void              capture_pipe_loss(void);
void              capture_pipe_stats(capture_pipe_stats_t * p_stats);
#endif

#endif /* CAPTURE_PIPE_H */

/*** end of file ***/
