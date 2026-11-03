/** @file analysis.c
 *
 * @brief Analysis and rules: parses GOOSE and SV frames and runs the rule
 * checks and models.
 *
 * @par
 * NOTE: Frames arrive from the capture module through
 * analysis_submit_frame() (see ../capture/capture_frame.h). Give each frame
 * back with capture_frame_release() once it has been analysed.
 */

#include "analysis.h"

/*!
 * @brief Create the kernel objects this module needs.
 *
 * @return E_OK, or the kernel error code.
 */
ER
analysis_init (void)
{
    ER result = E_OK;

    // TODO: Create the queues, pools and other kernel objects.

    return (result);
}

/*!
 * @brief Start the tasks of this module.
 *
 * @return E_OK, or the kernel error code.
 */
ER
analysis_start (void)
{
    ER result = E_OK;

    // TODO: Start the tasks.

    return (result);
}

/*!
 * @brief Hand a capture frame over to the analysis task.
 *
 * @par
 * On success the analysis task owns the frame and gives it back with
 * capture_frame_release(). On failure the caller still owns it.
 *
 * @param[in] p_frame The frame.
 *
 * @return E_OK, or the kernel error code.
 */
ER
analysis_submit_frame (capture_frame_t * p_frame)
{
    // TODO: Queue the frame for the analysis task. Until then every frame is
    // refused, so the capture task gives it straight back to the pool.
    (void) p_frame;

    return (E_NOSPT);
}

/*** end of file ***/
