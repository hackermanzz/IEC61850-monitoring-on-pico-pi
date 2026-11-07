/** @file config.h
 * @brief v0.3 uses static user buffers and a single scheduler core.
 */
#ifndef PORT_CONFIG_H
#define PORT_CONFIG_H

/* Keep the recovered course API selection; override only this board profile. */
#include "../third_party/mtkernel/config/config.h"

#undef USE_IMALLOC
#define USE_IMALLOC 0
#undef USE_SHUTDOWN
#define USE_SHUTDOWN 0
#undef USE_TMONITOR
#define USE_TMONITOR 0
#undef USE_SYSTEM_MESSAGE
#define USE_SYSTEM_MESSAGE 0
#undef CNF_TMP_STACK_SIZE
#define CNF_TMP_STACK_SIZE 1024

#define CNF_SMP 0

#endif /* PORT_CONFIG_H */

/*** end of file ***/
