#include "app.h"
#include "monitor_memory.h"
#include <sys/sysdef.h>

extern char __bss_end;
_Static_assert(sizeof(UW) == 4 && sizeof(void *) == 4,
               "RAM accounting requires the RP2040's 32-bit layout");

bool monitor_memory_stats(monitor_memory_stats_t *stats)
{
    if (stats == NULL) return false;
    const uintptr_t end = (uintptr_t)&__bss_end;
    if (CNF_SYSTEMAREA_TOP || CNF_SYSTEMAREA_END ||
        end < INTERNAL_RAM_START || end > INTERNAL_RAM_END) return false;
    T_KHEAP heap;
    Kheap_stats(&heap);
    /* memory.c IMACB is five target words, aligned to eight bytes, followed
     * by the initial/final area headers. Matches tools/memory_budget.py. */
    const uintptr_t allocator_end = (end + 5u * sizeof(UW) + 7u) & ~(uintptr_t)7u;
    uint32_t fixed = (uint32_t)(allocator_end - INTERNAL_RAM_START) +
                     CNF_EXC_STACK_SIZE + 4u * sizeof(void *);
#if TK_SUPPORT_SMP
    fixed += 8192u; /* Core 1 scratch-bank exception/boot stack reservation. */
#endif
    stats->heap_now = heap.allocated_bytes;
    stats->heap_peak = heap.peak_allocated_bytes;
    stats->heap_failures = heap.allocation_failures;
    stats->live_blocks = heap.live_blocks;
    stats->fixed_reserved = fixed;
    stats->reserved_peak_lower = fixed + heap.peak_allocated_bytes;
    return true;
}
