#include "app.h"
#include "monitor_memory.h"

/* Keep the configured object tables large enough for the actual startup
 * inventory, including tasks started by the USB/radio service backends. */
enum { monitor_service_tasks = 0
#if TM_CONSOLE_USB_CDC
    + 1
#endif
#if TM_WIFI_CYW43
    + 1
#endif
};
_Static_assert(CNF_MAX_TSKID >= 1 + monitor_service_tasks,
               "insufficient foundation/service task IDs");
_Static_assert(CNF_MAX_MBFID >= 4 && CNF_MAX_MPFID >= 1,
               "insufficient table headroom for agreed future interfaces");

EXPORT ID app_start_task_ex(FP entry, PRI priority, UW processor, SZ stack_size)
{
    T_CTSK definition = {0};
    definition.task = entry;
    definition.itskpri = priority;
    definition.stksz = stack_size;
    definition.tskatr = TA_HLNG | TA_RNG3;
#if TK_SUPPORT_SMP
    if (processor != 0) {
        definition.tskatr |= TA_ASSPRC;
        definition.assprc = processor;
    }
#else
    (void)processor;
#endif
    ID id = tk_cre_tsk(&definition);
    if (id < E_OK) return id;
    ER er = tk_sta_tsk(id, 0);
    if (er != E_OK) {
        CHECK(tk_del_tsk(id), "delete unstarted task");
        return er;
    }
    return id;
}

EXPORT ID app_start_task(FP entry, PRI priority, UW processor, const char *name)
{
    (void)name;
    return app_start_task_ex(entry, priority, processor, TASK_STACK_SIZE);
}

/* No subsystem init/start entry points are called in this checkpoint.
 * Their headers define the agreed API; later integration commits add owners. */
EXPORT INT usermain(void)
{
    tm_printf((UB *)"\nIEC61850 foundation: S1 SD=disabled S2 capture=disabled S3 analysis=disabled S4 health=disabled S5 alerts=disabled\n");
    tm_printf((UB *)"foundation: SMP=%u external_io=disabled watchdog=disabled subsystem_mask=%u\n",
              (UINT)TK_SUPPORT_SMP, (UINT)MONITOR_SUBSYSTEM_MASK);
#if USE_TASK_STACK_DIAG
    T_KSTACK stack;
    ER er = Kstack_stats(&stack);
    if (er == E_OK)
        tm_printf((UB *)"foundation_stack: task=%u total=%u written_lower=%u bottom_touched=%u\n",
            (UINT)stack.task_id, (UINT)stack.total_bytes, (UINT)stack.written_lower,
            (UINT)stack.bottom_touched);
    else CHECK(er, "foundation stack query");
#endif
    for (;;) {
        monitor_memory_stats_t memory;
        if (monitor_memory_stats(&memory))
            tm_printf((UB *)"foundation_ram: heap_now=%u heap_peak=%u alloc_fail=%u reserved_peak_lower=%u ceiling=%u\n",
                memory.heap_now, memory.heap_peak, memory.heap_failures,
                memory.reserved_peak_lower, (UINT)MONITOR_RAM_CEILING);
        else tm_printf((UB *)"foundation_ram: unsupported memory layout\n");
        (void)tk_dly_tsk(1000);
    }
}
