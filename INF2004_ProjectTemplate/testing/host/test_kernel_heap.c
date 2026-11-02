/* Execute the production allocator and public Kmalloc/Kcalloc/Krealloc API.
 * Audit actual area boundaries independently after randomized operations. */
#include "kernel.h"
#include "memory.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static union { max_align_t alignment; unsigned char bytes[8192]; } arena;
void *knl_lowmem_top, *knl_lowmem_limit;
static UINT interrupts_disabled;
UINT heap_irq_disable(void)
{
    UINT previous = interrupts_disabled;
    interrupts_disabled = 1;
    return previous;
}
void heap_irq_restore(UINT previous)
{
    assert(interrupts_disabled);
    interrupts_disabled = previous;
}
static void reset(void)
{
    assert(!interrupts_disabled);
    memset(&arena, 0xa5, sizeof(arena));
    knl_lowmem_top = arena.bytes;
    knl_lowmem_limit = arena.bytes + sizeof(arena.bytes);
    assert(knl_init_Imalloc() == E_OK);
}
static T_KHEAP audit(void)
{
    size_t used = 0, blocks = 0, segments = 0;
    for (QUEUE *area = knl_imacb->areaque.next;
         area->next != &knl_imacb->areaque; area = area->next) {
        assert(++segments < 1024);
        assert((unsigned char *)area >= arena.bytes &&
               (unsigned char *)area->next < arena.bytes + sizeof(arena.bytes));
        assert((uintptr_t)area->next > (uintptr_t)area);
        if (chkAreaFlag(area, AREA_USE)) {
            used += (size_t)((unsigned char *)area->next - (unsigned char *)area);
            blocks++;
        }
    }
    T_KHEAP info;
    Kheap_stats(&info);
    assert(!interrupts_disabled);
    assert(info.allocated_bytes == used && info.live_blocks == blocks);
    assert(info.peak_allocated_bytes >= info.allocated_bytes);
    return info;
}
static size_t span(void *pointer)
{
    QUEUE *area = (QUEUE *)pointer - 1;
    return (size_t)((unsigned char *)area->next - (unsigned char *)area);
}
int main(void)
{
    reset();
    assert(audit().allocated_bytes == 0);
    T_KSTACK stack;
    assert(Kstack_stats(&stack) == E_NOSPT); /* Release mode must not invent a watermark. */
    Kheap_stats(NULL);
    Kfree(NULL);
    unsigned char *a = Kcalloc(3, 17);
    assert(a);
    for (size_t i = 0; i < 51; i++) assert(a[i] == 0);
    memset(a, 0x5a, 51);
    size_t old_span = span(a);
    unsigned char *b = Krealloc(a, 1024);
    assert(b);
    for (size_t i = 0; i < 51; i++) assert(b[i] == 0x5a);
    assert(audit().peak_allocated_bytes == old_span + span(b));
    assert(Krealloc(b, INT32_MAX) == NULL);
    for (size_t i = 0; i < 51; i++) assert(b[i] == 0x5a);
    assert(audit().live_blocks == 1);
    assert(Krealloc(b, 0) == NULL);
    assert(audit().allocated_bytes == 0);

    reset();
    assert(Kcalloc(UINT32_C(1073741825), 4) == NULL); /* signed product would wrap to 4 */
    assert(Kcalloc(2, INT32_MAX) == NULL);
    assert(Kcalloc(SIZE_MAX, 2) == NULL);
    assert(Kcalloc(0, 32) == NULL);
    assert(Kmalloc(INT32_MAX) == NULL);
    assert(Kmalloc(0) == NULL);
    assert(audit().allocated_bytes == 0 && audit().allocation_failures == 6);

    reset();
    size_t largest = (size_t)knl_imacb->memsz & ~(sizeof(QUEUE) - 1u);
    a = Kmalloc(largest);
    assert(a && audit().allocated_bytes == (UW)knl_imacb->memsz + sizeof(QUEUE));
    assert(Kmalloc(1) == NULL && audit().allocation_failures == 1);
    Kfree(a);
    assert(audit().allocated_bytes == 0);
    /* Free must coalesce back to one whole arena after an unsplittable tail. */
    a = Kmalloc(largest);
    assert(a);
    Kfree(a);

    reset();
    struct { unsigned char *data; size_t size; unsigned char pattern; } live[64] = {0};
    uint32_t random = UINT32_C(0x1badb002);
    for (unsigned iteration = 0; iteration < 20000; iteration++) {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        unsigned index = random % 64;
        if (live[index].data) {
            for (size_t i = 0; i < live[index].size; i++)
                assert(live[index].data[i] == live[index].pattern);
            Kfree(live[index].data);
            live[index].data = NULL;
        } else {
            size_t size = (random >> 8) % 1024 + 1;
            live[index].data = Kmalloc(size);
            if (live[index].data) {
                live[index].size = size;
                live[index].pattern = (unsigned char)iteration;
                memset(live[index].data, live[index].pattern, size);
            }
        }
        audit();
    }
    for (size_t i = 0; i < 64; i++) Kfree(live[i].data);
    T_KHEAP info = audit();
    assert(info.allocated_bytes == 0 && info.live_blocks == 0 && info.allocation_failures > 0);
    puts("kernel heap: production allocation/rounding/coalescing, calloc overflow, realloc/OOM,");
    puts("             20000 randomized operations, peak/header accounting and IRQ restore PASS");
}
