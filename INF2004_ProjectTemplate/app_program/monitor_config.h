#ifndef MONITOR_CONFIG_H
#define MONITOR_CONFIG_H

/* This checkpoint publishes contracts; application implementations are disabled. */
#define MONITOR_FOUNDATION_ONLY 1
#ifndef MONITOR_TELEGRAM
#define MONITOR_TELEGRAM 0
#endif
#define MONITOR_SUBSYSTEM_MASK 0u

/* PLACEHOLDERS: choose these pins, then explicitly enable external I/O.
 * The example numbers below are compile-time stand-ins, not wiring claims. */
#ifndef MONITOR_PINS_CONFIGURED
#define MONITOR_PINS_CONFIGURED 0
#endif
#ifndef MONITOR_CRS_DV_PIN
#define MONITOR_CRS_DV_PIN 4u
#endif
#define IS18_RMII_RXD0_PIN 5u
#define IS18_RMII_CRS_DV_PIN MONITOR_CRS_DV_PIN
#define IS18_RMII_MDIO_PIN 2u
#define IS18_RMII_MDC_PIN 3u
#define MONITOR_ALARM_PIN 19u

/* Validate the chosen map only when external I/O is deliberately enabled. */
#define MONITOR_PIN_ALLOWED(pin) ((pin) >= 0 && (pin) <= 28 && \
    !((pin) >= 10 && (pin) <= 15) && !((pin) >= 23 && (pin) <= 25))
#if MONITOR_PINS_CONFIGURED
#if !MONITOR_PIN_ALLOWED(IS18_RMII_RXD0_PIN) || \
    !MONITOR_PIN_ALLOWED(IS18_RMII_RXD0_PIN + 1) || \
    !MONITOR_PIN_ALLOWED(IS18_RMII_CRS_DV_PIN) || \
    !MONITOR_PIN_ALLOWED(IS18_RMII_MDIO_PIN) || \
    !MONITOR_PIN_ALLOWED(IS18_RMII_MDC_PIN) || \
    !MONITOR_PIN_ALLOWED(MONITOR_ALARM_PIN)
#error "Pin map uses a reserved or invalid GPIO (SD GP10-15, radio GP23-25/29)"
#else
#define MONITOR_PIN_SUM ((1u << IS18_RMII_RXD0_PIN) + \
    (1u << (IS18_RMII_RXD0_PIN + 1)) + (1u << IS18_RMII_CRS_DV_PIN) + \
    (1u << IS18_RMII_MDIO_PIN) + (1u << IS18_RMII_MDC_PIN) + \
    (1u << MONITOR_ALARM_PIN))
#define MONITOR_PIN_BITS ((1u << IS18_RMII_RXD0_PIN) | \
    (1u << (IS18_RMII_RXD0_PIN + 1)) | (1u << IS18_RMII_CRS_DV_PIN) | \
    (1u << IS18_RMII_MDIO_PIN) | (1u << IS18_RMII_MDC_PIN) | \
    (1u << MONITOR_ALARM_PIN))
#if MONITOR_PIN_SUM != MONITOR_PIN_BITS
#error "Two monitor signals are assigned to the same GPIO"
#endif
#if TM_CONSOLE_UART && (MONITOR_PIN_BITS & 3u)
#error "GP0/GP1 conflict with the selected UART/crash console"
#endif
#endif
#endif
#define MONITOR_FRAME_BLOCKS 8u
#define MONITOR_RAM_CEILING 216064u
#define MONITOR_CAPTURE_STACK 4096
#define MONITOR_ALARM_STACK 2048
#define MONITOR_LOG_STACK 2048
#ifndef MONITOR_STORAGE
#define MONITOR_STORAGE 0
#endif
#define MONITOR_STORAGE_STACK 3072
#define MONITOR_NOTICE_STACK (MONITOR_STORAGE ? MONITOR_STORAGE_STACK : MONITOR_LOG_STACK)
#define MONITOR_ANALYSIS_STACK 6144
#define MONITOR_HEALTH_STACK 4096
#define MONITOR_CAPTURE_PRIORITY 8
#define MONITOR_ANALYSIS_PRIORITY 10
#define MONITOR_ALARM_PRIORITY 6
#define MONITOR_HEALTH_PRIORITY 7
#define MONITOR_IDLE_MS 100
#define MONITOR_CAPTURE_RETRY_US UINT64_C(2000000)
#define MONITOR_STALE_US UINT64_C(1000000)
#ifndef MONITOR_WATCHDOG
#define MONITOR_WATCHDOG 0
#endif
#ifndef MONITOR_SYNTHETIC
#define MONITOR_SYNTHETIC 0
#endif
#if MONITOR_PINS_CONFIGURED || MONITOR_STORAGE || MONITOR_WATCHDOG || MONITOR_TELEGRAM
#error "Foundation checkpoint: external I/O, storage, watchdog and Telegram are not integrated"
#endif
#endif
