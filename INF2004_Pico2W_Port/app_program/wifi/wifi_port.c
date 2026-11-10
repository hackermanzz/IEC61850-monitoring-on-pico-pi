/** @file wifi_port.c
 * @brief Core0 priority14 radio owner. Consumer owns all console/libc state.
 */
#include "wifi_port.h"
#include "ram_budget.h"
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include "pico/cyw43_arch.h"
#include "pico/time.h"
#include "pico/stdio.h"
#include "tk/tkernel.h"
#include "mbedtls/ssl.h"
#include "lwip/apps/altcp_tls_mbedtls_opts.h"
#include "notification_port.h"
#include "notification_queue.h"
#include "wifi_notification.h"
#include "wifi_settings.h"
#include "wifi_time.h"
#include "lwip/apps/sntp.h"

_Static_assert(PORT_RAM_CEILING_BYTES == PORT_PHYSICAL_SRAM_BYTES * 9u / 10u,
               "Pico2W RAM budget must preserve the ten percent reserve");

#define WIFI_STACK_WORDS   (3072u)
#define WIFI_STACK_PATTERN (0xa5a5a5a5u)
#define WIFI_RETRY_US      UINT64_C(10000000)
#define ALERT_EXPIRY_US    UINT64_C(60000000)
_Static_assert(ALTCP_MBEDTLS_AUTHMODE == MBEDTLS_SSL_VERIFY_REQUIRED,
               "TLS must reject unverified certificates");

_Alignas(8) static uint32_t g_stack[WIFI_STACK_WORDS];
static notification_queue_t g_queue;
static atomic_uint          g_started;
static atomic_uint          g_init_error;
static atomic_uint          g_configured;
static atomic_uint          g_connected;
static atomic_uint          g_busy;
static atomic_uint          g_success;
static atomic_uint          g_failed;
static atomic_uint          g_expired;
static atomic_uint          g_exhausted;
static atomic_uint          g_result;
static atomic_uint          g_http;
static atomic_uint          g_tls_current;
static atomic_uint          g_tls_peak;
static atomic_uint          g_tls_failures;
static atomic_uint          g_stack_used;
static atomic_uint          g_time_request;
static atomic_uint          g_time_ready;
static atomic_uint g_time_source; /* 0 unset, 1 network, 2 USB, 3 boot */
static atomic_uint g_time_syncs;
static atomic_uint g_time_rejected;
static atomic_uint g_joins;
static uint32_t    g_utc_epoch;
static uint64_t    g_utc_started;
static void        wifi_task(INT code, void * p_exinf);

/* Network time is a bootstrap source, not authenticated time. A successful
 * sample is range checked and never overrides an existing USB/boot clock.
 * Keep the SDK client alive across link changes: stopping during an outstanding
 * DNS lookup would allow its late callback to use a freed UDP endpoint.
 */
void
wifi_time_set_sntp (uint32_t seconds)
{
    if ((1704067200u > seconds) || (4102444800u <= seconds))
    {
        atomic_fetch_add(&g_time_rejected, 1u);
    }
    else if ((0u == g_utc_epoch) || (1u == atomic_load(&g_time_source)))
    {
        g_utc_epoch   = seconds;
        g_utc_started = time_us_64();
        atomic_store(&g_time_source, 1u);
        atomic_fetch_add(&g_time_syncs, 1u);
        atomic_store(&g_time_ready, 1u);
    }
}

void
wifi_time_get_sntp (uint32_t * p_seconds, uint32_t * p_microseconds)
{
    uint64_t now     = time_us_64();
    uint64_t elapsed = (0u == g_utc_epoch) ? now : now - g_utc_started;
    *p_seconds       = g_utc_epoch + (uint32_t) (elapsed / 1000000u);
    *p_microseconds  = (uint32_t) (elapsed % 1000000u);
}

uint32_t
monitor_notification_ms (void)
{
    return (uint32_t) (time_us_64() / 1000u);
}

/* TLS time is accessed only by the radio owner. Consumer publishes a request.
 */
time_t
monitor_tls_time (time_t * p_time)
{
    time_t result = (0u == g_utc_epoch)
                      ? 0
                      : (time_t) (g_utc_epoch
                                  + (time_us_64() - g_utc_started) / 1000000u);
    if (NULL != p_time)
    {
        *p_time = result;
    }
    return result;
}

int64_t
mbedtls_ms_time (void)
{
    return (int64_t) (time_us_64() / 1000u);
}

bool
wifi_port_start (void)
{
    T_CTSK task = {0};
    ID     id   = 0;
    /* Blank configuration is a buildable, explicitly offline profile. */
    bool configured = (0 != WIFI_SSID[0]) && (0 != TELEBOT_TOKEN[0])
                   && (0 != CHATID[0]) && (64u <= g_wifi_ca_root_size);
    atomic_store(&g_configured, configured ? 1u : 0u);
    if (!configured)
    {
        return true;
    }
    for (size_t index = 0u; WIFI_STACK_WORDS > index; index++)
    {
        g_stack[index] = WIFI_STACK_PATTERN;
    }
    task.tskatr  = TA_HLNG | TA_USERBUF | TA_ASSPRC;
    task.task    = (FP) wifi_task;
    task.itskpri = 14;
    task.stksz   = sizeof(g_stack);
    task.bufptr  = g_stack;
    task.assprc  = TP_PRC1;
    id           = tk_cre_tsk(&task);
    if (0 >= id)
    {
        return false;
    }
    if (E_OK != tk_sta_tsk(id, 0))
    {
        (void) tk_del_tsk(id);
        return false;
    }
    return true;
}

void
wifi_port_submit (const incident_event_t *  p_event,
                  const analyzer_result_t * p_result)
{
    notification_message_t             message = {0};
    const analyzer_packet_metadata_t * p_identity =
        &p_result->batch_packets[ANALYZER_NEWEST_FRAME_INDEX];
    /* This is the printf/libc-owning consumer, never the network task. */
    int count = snprintf(
        message.text, sizeof(message.text),
        "IEC61850 incident=%" PRIu32 " protocol=%s APPID=%u "
        "source=%02x:%02x:%02x:%02x:%02x:%02x "
        "decision_uptime_ms=%" PRIu64
        " evidence_ram=%u; inspect SD/serial details",
        p_event->incident_id,
        (ANALYZER_PROTOCOL_GOOSE == p_result->protocol) ? "GOOSE" : "SV",
        (unsigned int) p_identity->appid, p_identity->source_mac[0],
        p_identity->source_mac[1], p_identity->source_mac[2],
        p_identity->source_mac[3], p_identity->source_mac[4],
        p_identity->source_mac[5], p_event->decision_us / 1000u,
        p_event->evidence_saved ? 1u : 0u);
    message.created_us = p_event->decision_us;
    if ((0 < count) && ((size_t) count < sizeof(message.text)))
    {
        (void) notification_queue_put(&g_queue, &message);
    }
}

/* Strict decimal Unix time, 2024..2099. No Wi-Fi credentials in console input.
 */
void
wifi_port_console (void)
{
    static char   line[32];
    static size_t used;
    static bool   overflow;
    for (unsigned int index = 0u; 16u > index; index++)
    {
        int value = getchar_timeout_us(0);
        if (PICO_ERROR_TIMEOUT == value)
        {
            break;
        }
        if (('\r' == value) || ('\n' == value))
        {
            if (0u != used)
            {
                uint64_t epoch = 0u;
                bool     valid =
                    !overflow && (4u < used) && (0 == memcmp(line, "utc ", 4u));
                for (size_t digit = 4u; valid && (used > digit); digit++)
                {
                    valid = ('0' <= line[digit]) && ('9' >= line[digit]);
                    if (valid)
                    {
                        epoch =
                            epoch * 10u + (unsigned int) (line[digit] - '0');
                        valid = UINT32_MAX >= epoch;
                    }
                }
                valid = valid && (UINT64_C(1704067200) <= epoch)
                     && (UINT64_C(4102444800) > epoch);
                if (valid)
                {
                    atomic_store_explicit(&g_time_request, (uint32_t) epoch,
                                          memory_order_release);
                    printf("WIFI trusted UTC queued=%" PRIu64 "\n", epoch);
                }
                else
                {
                    printf("WIFI command: utc <trusted Unix seconds>\n");
                }
            }
            used     = 0u;
            overflow = false;
        }
        else if (sizeof(line) > used + 1u)
        {
            line[used++] = (char) value;
        }
        else
        {
            overflow = true;
        }
    }
}

static void
wifi_publish (void)
{
    wifi_notification_status_t status    = {0};
    size_t                     current   = 0u;
    size_t                     peak      = 0u;
    uint32_t                   failures  = 0u;
    uint32_t                   untouched = 0u;
    wifi_notification_get_status(&status);
    monitor_tls_memory_stats(&current, &peak, &failures);
    while ((WIFI_STACK_WORDS > untouched)
           && (WIFI_STACK_PATTERN == g_stack[untouched]))
    {
        untouched++;
    }
    atomic_store(&g_stack_used,
                 (WIFI_STACK_WORDS - untouched) * sizeof(uint32_t));
    atomic_store(&g_connected, status.wifi_connected ? 1u : 0u);
    atomic_store(&g_busy, status.busy ? 1u : 0u);
    atomic_store(&g_success, status.succeeded);
    atomic_store(&g_failed, status.failed);
    atomic_store(&g_result, (uint32_t) status.last_result);
    atomic_store(&g_http, status.last_http_status);
    atomic_store(&g_tls_current, (uint32_t) current);
    atomic_store(&g_tls_peak, (uint32_t) peak);
    atomic_store(&g_tls_failures, failures);
}

static void
wifi_task (INT code, void * p_exinf)
{
    notification_message_t pending          = {0};
    bool                   have_pending     = false;
    bool                   in_flight        = false;
    bool                   sntp_started     = false;
    unsigned int           attempts         = 0u;
    uint32_t               successes_before = 0u;
    uint64_t               next_attempt     = 0u;
    uint64_t               next_join        = 0u;
    uint64_t               last_publish     = 0u;
    (void) code;
    (void) p_exinf;
    if (0 != cyw43_arch_init())
    {
        atomic_store(&g_init_error, 1u);
        (void) tk_exd_tsk();
        return;
    }
    cyw43_arch_enable_sta_mode();
    (void) wifi_notification_init();
    atomic_store(&g_started, 1u);
    if ((1704067200u <= g_wifi_boot_utc) && (4102444800u > g_wifi_boot_utc))
    {
        g_utc_epoch   = g_wifi_boot_utc;
        g_utc_started = time_us_64();
        atomic_store(&g_time_ready, 1u);
        atomic_store(&g_time_source, 3u);
    }
    for (;;)
    {
        uint64_t now = time_us_64();
        uint32_t epoch =
            atomic_exchange_explicit(&g_time_request, 0u, memory_order_acquire);
        wifi_notification_status_t status = {0};
        if (0u != epoch)
        {
            g_utc_epoch   = epoch;
            g_utc_started = now;
            atomic_store(&g_time_ready, 1u);
            atomic_store(&g_time_source, 2u);
        }
        cyw43_arch_poll();
        wifi_notification_service();
        wifi_notification_get_status(&status);
        int link = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
        if (status.wifi_connected && (0u == g_utc_epoch) && !sntp_started)
        {
            sntp_setoperatingmode(SNTP_OPMODE_POLL);
            sntp_setservername(0u, g_wifi_ntp_server);
            sntp_setservername(1u, g_wifi_ntp_fallback);
            sntp_init();
            sntp_started = true;
        }

        /* Do not restart an in-progress DHCP exchange merely because an IP
         * has not arrived yet. Rejoin only after failure/down, rate limited.
         */
        if ((CYW43_LINK_DOWN >= link) && (now >= next_join))
        {
            (void) cyw43_arch_wifi_connect_async(WIFI_SSID, WIFI_PASSWORD,
                                                 (0 == WIFI_PASSWORD[0])
                                                     ? CYW43_AUTH_OPEN
                                                     : CYW43_AUTH_WPA2_AES_PSK);
            atomic_fetch_add(&g_joins, 1u);
            next_join = now + WIFI_RETRY_US;
        }
        if (in_flight && !status.busy)
        {
            in_flight = false;
            if (status.succeeded != successes_before)
            {
                have_pending = false;
            }
            else if (3u <= attempts)
            {
                have_pending = false;
                atomic_fetch_add(&g_exhausted, 1u);
            }
            else
            {
                next_attempt = now + UINT64_C(5000000);
            }
        }
        if (!have_pending)
        {
            have_pending = notification_queue_take(&g_queue, &pending);
            attempts     = 0u;
            next_attempt = now;
        }
        if (have_pending && !in_flight
            && (ALERT_EXPIRY_US <= now - pending.created_us))
        {
            have_pending = false;
            atomic_fetch_add(&g_expired, 1u);
        }
        if (have_pending && !in_flight && !status.busy && status.wifi_connected
            && (0u != g_utc_epoch) && (now >= next_attempt)
            && wifi_notification_submit(pending.text))
        {
            in_flight        = true;
            successes_before = status.succeeded;
            attempts++;
        }
        if (UINT64_C(100000) <= now - last_publish)
        {
            wifi_publish();
            last_publish = now;
        }
        (void) tk_dly_tsk(2u);
    }
}

void
wifi_port_report (void)
{
    printf("WIFI configured=%u started=%u init_error=%u up=%u utc=%u busy=%u "
           "joins=%u sent=%u failed=%u expired=%u exhausted=%u queue_drop=%u "
           "result=%u http=%u\n",
           atomic_load(&g_configured), atomic_load(&g_started),
           atomic_load(&g_init_error), atomic_load(&g_connected),
           atomic_load(&g_time_ready), atomic_load(&g_busy),
           atomic_load(&g_joins), atomic_load(&g_success),
           atomic_load(&g_failed), atomic_load(&g_expired),
           atomic_load(&g_exhausted), atomic_load(&g_queue.dropped),
           atomic_load(&g_result), atomic_load(&g_http));
    printf("WIFI time_source=%u time_syncs=%u time_rejected=%u "
           "(source: 0=unset 1=network 2=USB 3=boot)\n",
           atomic_load(&g_time_source), atomic_load(&g_time_syncs),
           atomic_load(&g_time_rejected));
    printf("WIFI TLS current=%u peak=%u arena=%u alloc_fail=%u "
           "stack_used=%u stack_size=%u bytes\n",
           atomic_load(&g_tls_current), atomic_load(&g_tls_peak),
           TLS_ARENA_BYTES, atomic_load(&g_tls_failures),
           atomic_load(&g_stack_used), (unsigned int) sizeof(g_stack));
}

/*** end of file ***/
