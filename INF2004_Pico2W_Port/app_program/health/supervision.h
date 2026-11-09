/** @file supervision.h
 * @brief Pure progress policy shared by target supervisor and host tests.
 */
#ifndef SUPERVISION_H
#define SUPERVISION_H

#include <stdbool.h>
#include <stdint.h>

#define SUPERVISION_OWNERS     (3u)
#define SUPERVISION_TIMEOUT_US (1000000u)
#define SUPERVISION_CONSUMER   (0u)
#define SUPERVISION_WORKER     (1u)
#define SUPERVISION_ALARM      (2u)

typedef struct
{
    uint32_t previous[SUPERVISION_OWNERS];
    uint64_t changed_us[SUPERVISION_OWNERS];
    uint32_t stalled_mask;
} supervision_t;

void supervision_init(supervision_t * p_state, uint64_t now_us);
/** @brief A packet count is not a heartbeat: healthy idle still progresses.
 * Once a stall is observed it latches; automatic recovery cannot hide it.
 */
bool supervision_check(supervision_t * p_state,
                       const uint32_t  counts[SUPERVISION_OWNERS],
                       uint64_t        now_us);

#endif /* SUPERVISION_H */

/*** end of file ***/
