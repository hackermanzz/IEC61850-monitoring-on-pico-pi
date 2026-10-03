/*
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico/mutex.h"
#include "pico/stdlib.h"

#include "lwip/init.h"

auto_init_mutex(g_lwip_mutex);

/* lwip has provision for using a mutex, when applicable */
sys_prot_t
sys_arch_protect (void)
{
    mutex_enter_blocking(&g_lwip_mutex);

    return 0;
}

void
sys_arch_unprotect (sys_prot_t pval)
{
    (void) pval;

    mutex_exit(&g_lwip_mutex);
}

/* lwIP needs a millisecond time source supplied by the Pico SDK clock. */
uint32_t
sys_now (void)
{
    return to_ms_since_boot(get_absolute_time());
}
