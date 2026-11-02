/* Production stack paint/query code, with only CPU/TCB context substituted. */
#include "kernel.h"
#include <sys/stack_diag.h>
#include <assert.h>
#include <stdio.h>

void *knl_lowmem_top, *knl_lowmem_limit;
TCB *stack_test_tasks[2];
unsigned stack_test_core;
static UINT masked;
static UW ipsr;
static UB *interrupt_write;
UW knl_get_ipsr(void) { return ipsr; }
UINT heap_irq_disable(void) { UINT old = masked; masked = 1; return old; }
void heap_irq_restore(UINT old)
{
    assert(masked);
    masked = old;
    if (!masked && interrupt_write) { *interrupt_write = 0; interrupt_write = NULL; }
}
int main(void)
{
    UB first[130], second[66];
    memset(first, 0x7c, sizeof(first));
    memset(second, 0x7c, sizeof(second));
    tk_stack_paint(first + 1, 128);
    tk_stack_paint(second + 1, 64);
    assert(first[0] == 0x7c && first[129] == 0x7c && second[0] == 0x7c && second[65] == 0x7c);
    assert(tk_stack_paint_prefix(NULL, 100) == 0 && tk_stack_paint_prefix(first, -1) == 0);
    TCB a = {.tskid = 1, .sstksz = 128, .isstack = first + 129};
    TCB b = {.tskid = 2, .sstksz = 64, .isstack = second + 65};
    stack_test_tasks[0] = &a;
    stack_test_tasks[1] = &b;
    T_KSTACK info;
    assert(Kstack_stats(&info) == E_OK && info.task_id == 1 && info.total_bytes == 128);
    assert(info.paint_prefix == 128 && info.written_lower == 0 && !info.bottom_touched && !masked);
    first[64] = 0;
    second[2] = 0;
    assert(Kstack_stats(&info) == E_OK && info.paint_prefix == 63 && info.written_lower == 65);
    assert(!info.bottom_touched);
    stack_test_core = 1;
    assert(Kstack_stats(&info) == E_OK && info.task_id == 2 && info.total_bytes == 64);
    assert(info.paint_prefix == 1 && info.written_lower == 63 && info.bottom_touched);
    stack_test_core = 0;
    assert(Kstack_stats(&info) == E_OK && info.task_id == 1 && info.paint_prefix == 63);
    assert(Kstack_stats(NULL) == E_PAR);
    ipsr = 16;
    assert(Kstack_stats(&info) == E_CTX && !masked);
    ipsr = 0;
    masked = 1;
    assert(Kstack_stats(&info) == E_CTX && masked);
    masked = 0;
    stack_test_tasks[0] = NULL;
    assert(Kstack_stats(&info) == E_CTX && !masked);
    stack_test_tasks[0] = &a;
    a.tskatr = TA_USERBUF;
    a.isstack = (void *)(uintptr_t)1; /* Must not dereference an unpainted user stack. */
    assert(Kstack_stats(&info) == E_NOSPT && !masked);
    a.tskatr = 0;
    a.isstack = first + 129;
    a.sstksz = 0;
    assert(Kstack_stats(&info) == E_CTX);
    a.sstksz = 128;
    /* An interrupt writes the bottom byte immediately after IRQ restore.
     * Seeing it proves the scan happens after the short masked metadata copy. */
    tk_stack_paint(first + 1, 128);
    interrupt_write = first + 1;
    assert(Kstack_stats(&info) == E_OK && info.paint_prefix == 0 && info.written_lower == 128);
    assert(info.bottom_touched && !masked && interrupt_write == NULL);
    puts("stack diagnostics: production paint/query, guards, both self contexts, ISR/masked rejection,");
    puts("                   unpainted user buffers and interrupts restored before scanning PASS");
}
