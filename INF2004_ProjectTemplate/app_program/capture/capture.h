/** @file capture.h
 *
 * @brief Ethernet capture: start-up, and the bounded pool of capture frames
 * shared with the analysis module.
 *
 * @par
 * The producer task takes a frame with capture_frame_acquire() and sends
 * it to the analysis consumer. The consumer gives it back with
 * capture_frame_release() once the frame has been analysed.
 */
#ifndef CAPTURE_H
#define CAPTURE_H

#include <stdbool.h>
#include <stdint.h>

#include "../app.h"
#include "capture_frame.h"

ER                capture_init(void);
ER                capture_start(void);
capture_frame_t * capture_frame_acquire(bool * pb_cleanup_failed);
ER                capture_frame_release(capture_frame_t * p_frame);
ER capture_pool_status(uint32_t * p_free_slots, uint32_t * p_free_blocks);

#endif /* CAPTURE_H */

/*** end of file ***/
