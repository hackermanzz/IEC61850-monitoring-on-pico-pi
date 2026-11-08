#if MONITOR_TELEGRAM
#include "notification_port.h"
#include "wifi_notification.h"
#include "wifi_notification_config.h"
#include "../monitor_time.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "pico/rand.h"
#include "pico/time.h"
#include <string.h>
#include <stdbool.h>

static time_t utc_epoch;
static uint64_t utc_started;
static bool initialized;
static char pending[192];
static bool have_pending;
static uint64_t pending_since, next_attempt, last_report;
static bool in_flight;
static uint32_t attempts, successes_before, expired;

uint32_t monitor_notification_ms(void)
{
    return (uint32_t)(monitor_time_us() / 1000);
}

mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return (mbedtls_ms_time_t)(monitor_time_us() / 1000);
}

void monitor_notification_set_utc(time_t unix_seconds)
{
    utc_epoch = unix_seconds;
    utc_started = monitor_time_us();
}

time_t monitor_tls_time(time_t *out)
{
    time_t value = utc_epoch ? utc_epoch +
        (time_t)((monitor_time_us() - utc_started) / 1000000) : 0;
    if (out != NULL) *out = value;
    return value;
}

/* Use the SDK's ROSC/time entropy mixer, as Pico SDK pico_mbedtls.c does. */
int mbedtls_hardware_poll(void *data, unsigned char *output,
                          size_t length, size_t *written)
{
    (void)data;
    *written = 0;
    while (*written < length) {
        uint64_t value = get_rand_64();
        size_t remaining = length - *written;
        size_t count = remaining < sizeof(value) ? remaining : sizeof(value);
        memcpy(output + *written, &value, count);
        *written += count;
    }
    return 0;
}

/* The RNG waits briefly between ROSC samples; no SDK alarm pool is needed. */
void busy_wait_until(absolute_time_t target)
{
    while (time_us_64() < to_us_since_boot(target)) __asm volatile("nop");
}
void sleep_until(absolute_time_t target) { busy_wait_until(target); }

void monitor_notification_poll(void)
{
    wifi_notification_status_t status;
    if (!initialized) {
#if defined(MONITOR_UTC_AT_BOOT) && MONITOR_UTC_AT_BOOT > 0
        monitor_notification_set_utc(MONITOR_UTC_AT_BOOT);
#endif
        if (!wifi_notification_init()) return;
        initialized = true;
    }
    wifi_notification_service();
    wifi_notification_get_status(&status);
    uint64_t now = monitor_time_us();
    if (in_flight && !status.busy) {
        in_flight = false;
        if (status.succeeded != successes_before) have_pending = false;
        else if (attempts >= 3) have_pending = false;
        else next_attempt = now + UINT64_C(5000000);
    }
    if (have_pending && !in_flight && now - pending_since > UINT64_C(60000000)) {
        have_pending = false;
        expired++;
    }
    if (!have_pending && !status.busy &&
        monitor_notification_take(pending, sizeof(pending)) > 0) {
        have_pending = true;
        pending_since = now;
        next_attempt = now;
        attempts = 0;
    }
    /* Require credentials, a real trust root, and trusted wall time. */
    bool configured = TELEBOT_TOKEN[0] && CHATID[0] && sizeof(CA_ROOT_CERT) >= 64;
    if (have_pending && !in_flight && now >= next_attempt && !status.busy &&
        status.wifi_connected && utc_epoch > 0 && configured &&
        wifi_notification_submit(pending)) {
        in_flight = true;
        successes_before = status.succeeded;
        attempts++;
    }
    if (now - last_report >= 100000) {
        size_t current, peak;
        uint32_t failures;
        monitor_tls_memory_stats(&current, &peak, &failures);
        monitor_network_stats_t report = {0};
        report.configured = configured;
        report.utc_ready = utc_epoch > 0;
        report.wifi_up = status.wifi_connected;
        report.busy = status.busy || in_flight;
        report.succeeded = status.succeeded;
        report.failed = status.failed;
        report.expired = expired;
        report.result = status.last_result;
        report.http_status = status.last_http_status;
        report.tls_bytes = (uint32_t)current;
        report.tls_peak_bytes = (uint32_t)peak;
        report.tls_allocation_failures = failures;
        monitor_notification_report(&report);
        last_report = now;
    }
}
#endif
