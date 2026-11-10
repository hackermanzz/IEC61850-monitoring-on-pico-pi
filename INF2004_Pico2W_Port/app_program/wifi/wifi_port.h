/** @file wifi_port.h
 * @brief Copied S3 alerts to one Core0 radio/lwIP/TLS owner.
 */
#ifndef WIFI_PORT_H
#define WIFI_PORT_H
#include <stdbool.h>
#include "../analysis/incident.h"
bool wifi_port_start(void);
/* Consumer only: bounded copied text, never waits for a network operation. */
void wifi_port_submit(const incident_event_t *  p_event,
                      const analyzer_result_t * p_result);
/* Consumer only: accepts trusted UTC from USB; no secrets on the console. */
void wifi_port_console(void);
void wifi_port_report(void);
#endif

/*** end of file ***/
