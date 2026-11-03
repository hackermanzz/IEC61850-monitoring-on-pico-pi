/** @file alarm.c
 *
 * @brief Alarm and Telegram: drives the alarm output and sends Telegram
 * notifications.
 */

#include "alarm.h"

/*!
 * @brief Create the kernel objects this module needs.
 *
 * @return E_OK, or the kernel error code.
 */
ER
alarm_init (void)
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
alarm_start (void)
{
    ER result = E_OK;

    // TODO: Start the tasks.

    return (result);
}

/*** end of file ***/
