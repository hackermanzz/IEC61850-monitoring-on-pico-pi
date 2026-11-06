#include "subsystem5.h"
#include "../monitor_stacks.h"
EXPORT void led_task(INT stacd, void *exinf)
{
    UINT flags;
    (void)stacd;
    (void)exinf;
    if (MONITOR_PINS_CONFIGURED) {
        CHECK(gpio_set_pin(MONITOR_ALARM_PIN, GPIO_MODE_OUT), "alarm gpio");
        CHECK(gpio_set_val(MONITOR_ALARM_PIN, 0), "alarm low");
    }
    for (;;) {
        MONITOR_STACK_REPORT(5);
        ER er = tk_wai_flg(flg_alarm, 1, TWF_ORW | TWF_CLR, &flags, TMO_FEVR);
        if (er == E_OK) {
            if (MONITOR_PINS_CONFIGURED)
                CHECK(gpio_set_val(MONITOR_ALARM_PIN, 1), "alarm high");
            /* Latched until reboot; diagnostics cannot suspend this task. */
        } else CHECK(er, "alarm wait");
    }
}
