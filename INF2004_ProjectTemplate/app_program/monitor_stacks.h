#ifndef MONITOR_STACKS_H
#define MONITOR_STACKS_H
/* One calling task owns each tag: 1 storage, 2 capture, 3 analysis, 4 health,
 * 5 alarm, 6 USB, 7 radio, 8 initial, 9 console. Never call from an interrupt/lock. */
#if USE_TASK_STACK_DIAG
void monitor_stack_report(unsigned owner);
const char *monitor_stack_owner_name(unsigned owner);
#define MONITOR_STACK_REPORT(owner) monitor_stack_report(owner)
#else
#define MONITOR_STACK_REPORT(owner) ((void)0)
#endif
#endif
