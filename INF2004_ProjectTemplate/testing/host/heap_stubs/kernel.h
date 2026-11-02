#ifndef HEAP_TEST_KERNEL_H
#define HEAP_TEST_KERNEL_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
/* Keep requested-size arithmetic 32-bit as on RP2040. Addresses and queue
 * links use native host width so the real allocator can execute under ASan.
 * This tests allocation logic, not exact target header sizes or SMP exclusion. */
typedef int32_t SZ;
typedef intptr_t W;
typedef uintptr_t UW;
typedef unsigned UINT;
typedef int ER, BOOL, INT, ID, PRI;
typedef unsigned char UB;
typedef void (*FP)();
typedef char VB;
#define TRUE 1
#define FALSE 0
#define E_OK 0
#define E_NOSPT (-9)
#define E_PAR (-17)
#define E_CTX (-25)
#define EXPORT
#define IMPORT extern
#define LOCAL static
#define Inline static inline
#define Noinit(declaration) declaration
#define USE_IMALLOC 1
#define TK_SUPPORT_MEMLIB 1
#include <sys/queue.h>
typedef struct {
    UW allocated_bytes, peak_allocated_bytes, allocation_failures, live_blocks;
} T_KHEAP;
typedef struct {
    ID task_id;
    UW total_bytes, paint_prefix, written_lower;
    BOOL bottom_touched;
} T_KSTACK;
typedef struct {
    ID tskid;
    UW tskatr;
    SZ sstksz;
    void *isstack;
} TCB;
extern TCB *stack_test_tasks[2];
extern unsigned stack_test_core;
#define knl_ctxtsk (stack_test_tasks[stack_test_core])
#define TA_USERBUF 0x20u
#define isDI(mask) ((mask) != 0)
UW knl_get_ipsr(void);
extern void *knl_lowmem_top, *knl_lowmem_limit;
UINT heap_irq_disable(void);
void heap_irq_restore(UINT previous);
#define DI(previous) ((previous) = heap_irq_disable())
#define EI(previous) heap_irq_restore(previous)
#define knl_memset memset
#define knl_memcpy memcpy
void *knl_Imalloc(SZ);
void *knl_Icalloc(SZ, SZ);
void *knl_Irealloc(void *, SZ);
void knl_Ifree(void *);
ER knl_init_Imalloc(void);
void *Kmalloc(size_t);
void *Kcalloc(size_t, size_t);
void *Krealloc(void *, size_t);
void Kfree(void *);
void Kheap_stats(T_KHEAP *);
ER Kstack_stats(T_KSTACK *);
#endif
