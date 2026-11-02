#include "monitor_time.h"

/* RP2040 timer raw high/low registers; repeat if the low word rolled over. */
uint64_t monitor_time_us(void)
{
    volatile const uint32_t *high = (const uint32_t *)0x40054024u;
    volatile const uint32_t *low = (const uint32_t *)0x40054028u;
    uint32_t first, last, value;
    do {
        first = *high;
        value = *low;
        last = *high;
    } while (first != last);
    return ((uint64_t)last << 32) | value;
}
