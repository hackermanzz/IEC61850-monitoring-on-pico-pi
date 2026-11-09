/** @file console.h
 * @brief Queue formatting output without waiting for the USB host.
 */
#ifndef CONSOLE_H
#define CONSOLE_H

#include <stdbool.h>
#include <stddef.h>
#include "console_queue.h"

typedef struct
{
    char   line[CONSOLE_LINE_BYTES];
    size_t length;
    size_t offset;
} console_stream_t;

bool console_start(void);
/** @brief USB owner only: one bounded, resumable non-waiting output step. */
void console_service_step(console_stream_t * p_stream);
/** @brief Called only by the analysis/printf owner. */
void console_report(void);

#endif /* CONSOLE_H */

/*** end of file ***/
