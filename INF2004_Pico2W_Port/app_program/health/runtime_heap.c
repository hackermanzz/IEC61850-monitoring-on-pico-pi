/** @file runtime_heap.c
 * @brief Core0-only libc allocation cannot consume the remaining RP2350 RAM.
 */
#include "runtime_heap.h"
#include <errno.h>
#include <stdint.h>
#include "pico.h"

/* HEAP_LIMIT is fixed to __end__+2048 in the detection linker options. The
 * SDK weak _sbrk uses __StackLimit instead, so that implementation alone would
 * NOT enforce our budget. No Core1 libc allocation is permitted.
 */
extern char     __detection_heap_start;
extern char     __HeapLimit;
static uint32_t g_heap_used;

void *
_sbrk (int increment)
{
    uintptr_t base       = (uintptr_t) &__detection_heap_start;
    uintptr_t capacity   = (uintptr_t) &__HeapLimit - base;
    int64_t   next       = (int64_t) g_heap_used + increment;
    void *    p_previous = (void *) (base + g_heap_used);

    if (0u != get_core_num())
    {
        /* errno/TLS itself belongs to Core0; do not touch it remotely. */
        return (void *) -1;
    }
    if ((0 > next) || ((uint64_t) next > capacity))
    {
        errno = ENOMEM;
        return (void *) -1;
    }
    g_heap_used = (uint32_t) next;
    return p_previous;
}

/*** end of file ***/
