/** @file health.c
 *
 * @brief Health and evidence: supervises task progress, feeds the watchdog
 * and keeps incident evidence.
 *
 * @par
 * NOTE: The capture task reports its status with health_publish(). The
 * capture frame pool levels come from capture_pool_status() (see
 * ../capture/capture.h).
 */

#include "health.h"

/*!
 * @brief Create the kernel objects this module needs.
 *
 * @return E_OK, or the kernel error code.
 */
ER
health_init (void)
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
health_start (void)
{
    ER result = E_OK;

    // TODO: Start the tasks.

    return (result);
}

/*** end of file ***/
