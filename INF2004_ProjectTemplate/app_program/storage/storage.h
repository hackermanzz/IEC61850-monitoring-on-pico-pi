/** @file storage.h
 *
 * @brief SD card storage: writes incident records to the SD card.
 *
 * @par
 * TODO: Add the public interface of this module.
 */
#ifndef STORAGE_H
#define STORAGE_H

#include "../app.h"

ER storage_init(void);
ER storage_start(void);

#endif /* STORAGE_H */

/*** end of file ***/
