/** @file supervision.c
 * @brief Detect lack of task progress rather than lack of Ethernet packets.
 */
#include "supervision.h"
#include <string.h>

void
supervision_init (supervision_t * p_state, uint64_t now_us)
{
    size_t index = 0u;
    memset(p_state, 0, sizeof(*p_state));
    for (index = 0u; SUPERVISION_OWNERS > index; index++)
    {
        p_state->changed_us[index] = now_us;
    }
}

bool
supervision_check (supervision_t * p_state,
                   const uint32_t counts[SUPERVISION_OWNERS], uint64_t now_us)
{
    size_t index = 0u;
    for (index = 0u; SUPERVISION_OWNERS > index; index++)
    {
        if (counts[index] != p_state->previous[index])
        {
            p_state->previous[index]   = counts[index];
            p_state->changed_us[index] = now_us;
        }
        else if ((now_us < p_state->changed_us[index])
                 || (SUPERVISION_TIMEOUT_US
                     <= now_us - p_state->changed_us[index]))
        {
            p_state->stalled_mask |= 1u << index;
        }
    }
    return 0u == p_state->stalled_mask;
}

/*** end of file ***/
