/** @file app_main.c
 * @brief Pico 2 W entry for diagnostics, kernel acceptance and capture
 * profiles.
 */
#include "app_main.h"

#include <inttypes.h>         /* Portable fixed-width printf formats. */
#include <stdio.h>            /* USB diagnostic output. */
#include "hardware/clocks.h"  /* Actual system clock, rather than a guess. */
#include "pico/stdlib.h"      /* Console initialization and SDK delays. */
#include "pico/stdio_usb.h"   /* Keep startup text until CDC is opened. */
#include "capture/mdio_phy.h" /* Read-only management, not packet capture. */

#if PORT_KERNEL
#include "kernel_port.h"
#endif

#define APP_REPORT_PERIOD_MS 1000u
#define APP_CONSOLE_WAIT_MS  15000u
#define APP_CONSOLE_POLL_MS  100u

uint64_t
port_time_us (void)
{
    return time_us_64();
}

void
app_main_scan_phy (void)
{
    uint32_t      address     = 0u;
    uint32_t      found_count = 0u;
    mdio_phy_id_t identity    = {0u, 0u, 0u, false};

    mdio_phy_init();
    for (address = 0u; MDIO_PHY_ADDRESS_COUNT > address; address++)
    {
        /* The loop bounds guarantee that this narrowing cast is exact. */
        if (mdio_phy_identify((uint8_t) address, &identity))
        {
            found_count++;
            printf("PHY addr=%" PRIu32 " id1=%04" PRIx16 " id2=%04" PRIx16
                   " LAN8720=%u\n",
                   address, identity.id1, identity.id2,
                   identity.b_is_lan8720 ? 1u : 0u);
        }
    }
    printf("PHY scan: %" PRIu32 " acknowledged identities.\n", found_count);
}

int
main (void)
{
    uint32_t elapsed = 0u;

    stdio_init_all();
    /* Bound the wait so unattended boot can still progress without a host. */
    while ((!stdio_usb_connected()) && (APP_CONSOLE_WAIT_MS > elapsed))
    {
        sleep_ms(APP_CONSOLE_POLL_MS);
        elapsed += APP_CONSOLE_POLL_MS;
    }

#if PORT_KERNEL
#if PORT_CAPTURE
    printf("Starting RP2350 SMP kernel; capture bring-up follows.\n");
#elif PORT_SMP
    printf("Starting RP2350 SMP kernel; board tests follow.\n");
#else
    printf("Starting RP2350 single-core kernel; board tests follow.\n");
#endif
    /* The SDK owns reset/boot metadata; the kernel owns task scheduling. */
    kernel_port_start();
#else
    /* Give a connected USB host time to enumerate before the first scan. */
    sleep_ms(APP_REPORT_PERIOD_MS);
    printf("Pico 2 W SDK diagnostic v0.2 (no kernel).\n");
    app_main_scan_phy();
    for (;;)
    {
        printf("clk_sys=%" PRIu32 "Hz, time=%" PRIu64 " us\n",
               clock_get_hz(clk_sys), port_time_us());
        sleep_ms(APP_REPORT_PERIOD_MS);
    }
#endif

    return 0;
}

/*** end of file ***/
