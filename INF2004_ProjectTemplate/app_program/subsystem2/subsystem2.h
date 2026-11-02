/** @file subsystem2.h
 *
 * @brief Subsystem 2, Ethernet capture: start-up, and the bounded pool of
 * capture frames shared with the analysis subsystem.
 *
 * @par
 * The producer task takes a frame with subsystem2_frame_acquire() and sends
 * it to the analysis consumer. The consumer gives it back with
 * subsystem2_frame_release() once the frame has been analysed.
 */
#ifndef SUBSYSTEM2_H
#define SUBSYSTEM2_H

#include <stdbool.h>
#include <stdint.h>

#include "../app.h"
#include "capture_frame.h"

ER                subsystem2_init(void);
ER                subsystem2_start(void);
capture_frame_t * subsystem2_frame_acquire(bool * pb_cleanup_failed);
ER                subsystem2_frame_release(capture_frame_t * p_frame);
ER subsystem2_pool_status(uint32_t * p_free_slots, uint32_t * p_free_blocks);

#endif /* SUBSYSTEM2_H */

/*** end of file ***/
