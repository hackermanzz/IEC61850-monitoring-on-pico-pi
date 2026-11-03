/** @file analysis.h
 *
 * @brief Analysis and rules: parses GOOSE and SV frames and runs the rule
 * checks and models.
 *
 * @par
 * The capture task hands each frame over with analysis_submit_frame(). The
 * analysis task gives it back with capture_frame_release() once the frame
 * has been analysed.
 *
 * @par
 * TODO: Add the rest of the public interface of this module.
 */
#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "../app.h"
#include "../capture/capture_frame.h"

ER analysis_init(void);
ER analysis_start(void);
ER analysis_submit_frame(capture_frame_t * p_frame);

#endif /* ANALYSIS_H */

/*** end of file ***/
