/** @file storage.c
 *
 * @brief SD card storage: writes incident records to the SD card.
 */

#include "storage.h"

/*!
 * @brief Create the kernel objects this module needs.
 *
 * @return E_OK, or the kernel error code.
 */
ER
storage_init (void)
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
storage_start (void)
{
    ER result = E_OK;

    // TODO: Start the tasks.

    return (result);
}

/*** end of file ***/
