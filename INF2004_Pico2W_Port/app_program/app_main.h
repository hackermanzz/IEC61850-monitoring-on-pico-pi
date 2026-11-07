/** @file app_main.h
 * @brief Shared diagnostic functions for SDK and kernel profiles.
 */
#ifndef APP_MAIN_H
#define APP_MAIN_H

#include <stdint.h> /* Microsecond timestamp width. */

/** @brief Return the SDK hardware timer's monotonic microsecond count. */
uint64_t port_time_us(void);

/** @brief Scan all Clause 22 addresses once and print raw PHY identities. */
void app_main_scan_phy(void);

#endif /* APP_MAIN_H */

/*** end of file ***/
