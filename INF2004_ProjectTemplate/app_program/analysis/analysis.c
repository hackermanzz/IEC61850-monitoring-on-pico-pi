/** @file analysis.c
 *
 * @brief Analysis and rules: parses GOOSE and SV frames and runs the rule
 * checks and models.
 *
 * @par
 * NOTE: Frames arrive from the capture module by mailbox (see
 * ../capture/capture_frame.h). Give each frame back with
 * capture_frame_release() once it has been analysed.
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

/*** end of file ***/
