/** @file tls_arena.c
 * @brief First-fit TLS arena with splitting, wiping and adjacent coalescing.
 * All callers belong to the single radio task. No cross-task allocator access.
 */
#include "tls_arena.h"
#include <stdbool.h>
#include <string.h>

typedef union tls_block tls_block_t;
union tls_block
{
    max_align_t alignment;
    struct
    {
        size_t        capacity;
        tls_block_t * p_next;
        bool          free;
    } block;
};

_Alignas(max_align_t) static unsigned char g_arena[TLS_ARENA_BYTES];
static tls_block_t * gp_first;
static size_t        g_current;
static size_t        g_peak;
static uint32_t      g_failures;

void *
monitor_tls_calloc (size_t count, size_t bytes)
{
    const size_t  alignment = _Alignof(max_align_t);
    size_t        length    = 0u;
    tls_block_t * p_block   = NULL;
    if ((0u == count) || (0u == bytes) || (SIZE_MAX / count < bytes))
    {
        g_failures++;
        return NULL;
    }
    length = count * bytes;
    if (SIZE_MAX - (alignment - 1u) < length)
    {
        g_failures++;
        return NULL;
    }
    length = (length + alignment - 1u) / alignment * alignment;
    if (NULL == gp_first)
    {
        gp_first                 = (tls_block_t *) g_arena;
        gp_first->block.capacity = sizeof(g_arena) - sizeof(tls_block_t);
        gp_first->block.p_next   = NULL;
        gp_first->block.free     = true;
    }
    for (p_block = gp_first; NULL != p_block; p_block = p_block->block.p_next)
    {
        if (p_block->block.free && (length <= p_block->block.capacity))
        {
            if (p_block->block.capacity - length
                >= sizeof(tls_block_t) + alignment)
            {
                tls_block_t * p_rest =
                    (tls_block_t *) ((unsigned char *) (p_block + 1) + length);
                p_rest->block.capacity =
                    p_block->block.capacity - length - sizeof(tls_block_t);
                p_rest->block.p_next    = p_block->block.p_next;
                p_rest->block.free      = true;
                p_block->block.p_next   = p_rest;
                p_block->block.capacity = length;
            }
            p_block->block.free = false;
            g_current += p_block->block.capacity + sizeof(tls_block_t);
            if (g_peak < g_current)
            {
                g_peak = g_current;
            }
            memset(p_block + 1, 0, p_block->block.capacity);
            return p_block + 1;
        }
    }
    g_failures++;
    return NULL;
}

void
monitor_tls_free (void * p_memory)
{
    tls_block_t * p_block = NULL;
    if (NULL == p_memory)
    {
        return;
    }
    /* Locate a real allocation rather than interpreting an arbitrary pointer
     * as a header. A duplicate/invalid free cannot corrupt the arena list.
     */
    for (p_block = gp_first; NULL != p_block; p_block = p_block->block.p_next)
    {
        if (((void *) (p_block + 1) == p_memory) && !p_block->block.free)
        {
            volatile unsigned char * p_wipe = p_memory;
            for (size_t index = 0u; p_block->block.capacity > index; index++)
            {
                p_wipe[index] = 0u;
            }
            g_current -= p_block->block.capacity + sizeof(tls_block_t);
            p_block->block.free = true;
            break;
        }
    }
    for (p_block = gp_first; NULL != p_block; p_block = p_block->block.p_next)
    {
        while (p_block->block.free && (NULL != p_block->block.p_next)
               && p_block->block.p_next->block.free)
        {
            tls_block_t * p_next = p_block->block.p_next;
            p_block->block.capacity +=
                sizeof(tls_block_t) + p_next->block.capacity;
            p_block->block.p_next = p_next->block.p_next;
        }
    }
}

void
monitor_tls_memory_stats (size_t * p_current, size_t * p_peak,
                          uint32_t * p_failures)
{
    *p_current  = g_current;
    *p_peak     = g_peak;
    *p_failures = g_failures;
}

/*** end of file ***/
