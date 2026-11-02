#ifndef MONITOR_MEMORY_H
#define MONITOR_MEMORY_H
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t heap_now;
    uint32_t heap_peak;
    uint32_t heap_failures;
    uint32_t live_blocks;
    uint32_t fixed_reserved;
    uint32_t reserved_peak_lower;
} monitor_memory_stats_t;

/* Core-0 owner only (foundation startup, later the S4 supervisor). Includes reserved stacks through kernel heap use,
 * static RAM, exception/scratch reservations and allocator setup. Free-fragment
 * bookkeeping and stack headroom still need board qualification. No allocation,
 * list walk or network call is performed. False for an unsupported RAM layout. */
bool monitor_memory_stats(monitor_memory_stats_t *stats);
#endif
