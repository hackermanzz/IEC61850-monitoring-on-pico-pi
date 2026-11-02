/* Monitor stack diagnostics. Include after the T-Kernel basic types. */
#ifndef MONITOR_SYS_STACK_DIAG_H
#define MONITOR_SYS_STACK_DIAG_H
#define TK_STACK_PAINT 0xa5u

Inline void tk_stack_paint(UB *base, SZ bytes)
{
    if (!base) return;
    for (SZ i = 0; i < bytes; i++) base[i] = TK_STACK_PAINT;
}
Inline SZ tk_stack_paint_prefix(const volatile UB *base, SZ bytes)
{
    SZ prefix = 0;
    if (!base) return 0;
    while (prefix < bytes && base[prefix] == TK_STACK_PAINT) prefix++;
    return prefix;
}
#endif
