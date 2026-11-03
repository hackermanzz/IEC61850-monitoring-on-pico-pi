/** @file alarm.h
 *
 * @brief Alarm and Telegram: drives the alarm output and sends Telegram
 * notifications.
 *
 * @par
 * TODO: Add the public interface of this module.
 */
#ifndef ALARM_H
#define ALARM_H

#include "../app.h"

ER alarm_init(void);
ER alarm_start(void);

#endif /* ALARM_H */

/*** end of file ***/
