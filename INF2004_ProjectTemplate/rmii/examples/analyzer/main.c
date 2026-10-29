/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Pico RMII capture, analyzer, diagnostics, and dual-model LED application.
 */

#include "analyzer.h"
#include "incident.h"
#include "main.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hardware/clocks.h"
#include "hardware/watchdog.h"
#include "pico/unique_id.h"
#include "pico/cyw43_arch.h"
#include "pico/async_context_poll.h"
#include "pico/lwip_nosys.h"
#include "pico/multicore.h"
#include "pico/stdlib.h"
#include "pico/stdio_usb.h"
#include "rmii_ethernet/netif.h"
#include "sdcard.h"
#include "wifi_notification.h"

#define CAPTURE_SLICE_LIMIT (4u)
#define ALERT_QUEUE_CAPACITY (INCIDENT_MAXIMUM_CONTAINERS)
#define ALERT_RETRY_INTERVAL_MS (5000u)
#define ALERT_MAXIMUM_ATTEMPTS (3u)
#define FNV_HASH_OFFSET_BASIS (2166136261u)
#define FNV_HASH_PRIME (16777619u)
#define UINT32_WORD_SHIFT (32u)
#define USB_CONNECT_POLL_INTERVAL_MS (50u)
#define FIRST_SUMMARY_INTERVAL_MS (1000u)
#define BATCH_INDEX_THIRD_FROM_END (ANALYZER_BATCH_FRAME_COUNT - 2u)
#define BATCH_INDEX_LAST (ANALYZER_BATCH_FRAME_COUNT - 1u)

typedef struct
{
    bool     used;
    bool     in_flight;
    uint64_t incident_id;
    uint8_t  attempts;
    uint32_t succeeded_before_submit;
    uint32_t failed_before_submit;
    char     message[WIFI_NOTIFICATION_MESSAGE_CAPACITY];
} pending_alert_t;

typedef struct
{
    uint32_t goose_count;
    uint32_t sv_count;
    uint32_t parsed_goose;
    uint32_t predictions;
    uint32_t gaps;
    uint32_t previous_sequence;
    uint32_t analysis_max;
    uint32_t analysis_samples;
    uint64_t analysis_total;
    bool     have_sequence;
    uint32_t alert_submit_failures;
    uint32_t alert_queue_dropped;
} app_statistics_t;

static pending_alert_t g_pending_alerts[ALERT_QUEUE_CAPACITY];
static uint64_t        g_last_alert_attempt_us;
static uint64_t        g_last_active_id;
static bool            g_test_in_flight;
static uint32_t        g_test_succeeded_before;
static uint32_t        g_test_failed_before;

static void track_new_incident (app_statistics_t * statistics);

__attribute__((weak)) uint32_t
incident_persistent_session_id (const pico_unique_board_id_t * board_id,
                                uint64_t                       boot_time_us)
{
    uint32_t hash  = FNV_HASH_OFFSET_BASIS;
    size_t   index = 0u;

    for (index = 0u; index < PICO_UNIQUE_BOARD_ID_SIZE_BYTES; ++index)
    {
        hash = (hash ^ board_id->id[index]) * FNV_HASH_PRIME;
    }
    return hash ^ (uint32_t) boot_time_us ^
           (uint32_t) (boot_time_us >> UINT32_WORD_SHIFT);
}

static void
set_led (bool on)
{
    gpio_put(CLASS_LED_PIN, on);
}

static const char *
protocol_name (analyzer_protocol_t protocol)
{
    return protocol == ANALYZER_PROTOCOL_GOOSE ? "GOOSE" : "SV";
}

static void
print_result (const analyzer_result_t * result, uint32_t sequence)
{
    const unsigned int class_id = result->primary_label == MALICIOUS_LABEL
                                      ? MALICIOUS_LABEL
                                      : BENIGN_LABEL;

    (void) printf(
        "frame=%lu protocol=%s model=batch_rf window=4/stride=2 stream=%08lx "
        "appid=0x%04x class=%u label=%u probability_label_1=%.6f "
        "counter1=%lu counter2=%lu\r\n",
        (unsigned long) sequence, protocol_name(result->protocol),
        (unsigned long) result->stream_key, (unsigned int) result->appid,
        class_id, (unsigned int) result->primary_label,
        (double) result->primary_probability, (unsigned long) result->counter_1,
        (unsigned long) result->counter_2);
}

static void
link_callback (struct netif * network_interface)
{
    (void) printf("link=%s\r\n",
                  netif_is_link_up(network_interface) ? "up" : "down");
}

static bool
initialize_network_interface (struct netif * network_interface,
                              bool           wifi_stack_ready)
{
    struct netif_rmii_ethernet_config config =
        (struct netif_rmii_ethernet_config)
            NETIF_RMII_ETHERNET_DEFAULT_CONFIG();
    err_t network_init_error = ERR_OK;

    /* Pico W's CYW43 SPI transport claims a PIO1 state machine. Keep RMII on
     * PIO0 so the Wi-Fi and Ethernet drivers have independent PIO resources. */
    config.pio            = pio0;
    config.pio_sm_start   = 0u;
    config.rx_pin_start   = RMII_RECEIVE_PIN_START;
    config.crs_dv_pin     = RMII_CRS_DV_PIN;
    config.tx_pin_start   = RMII_TRANSMIT_PIN_START;
    config.mdio_pin_start = RMII_MANAGEMENT_PIN_START;
    config.capture_only   = true;
    if (wifi_stack_ready)
    {
        cyw43_arch_lwip_begin();
    }
    network_init_error = netif_rmii_ethernet_init(network_interface, &config);
    if (wifi_stack_ready)
    {
        cyw43_arch_lwip_end();
    }
    if (network_init_error != ERR_OK)
    {
        (void) printf(
            "error: RMII network interface initialization failed; err=%d\r\n",
            (int) network_init_error);
        stdio_flush();
        return false;
    }
    if (wifi_stack_ready)
    {
        cyw43_arch_lwip_begin();
    }
    netif_set_link_callback(network_interface, link_callback);
    netif_set_up(network_interface);
    if (wifi_stack_ready)
    {
        cyw43_arch_lwip_end();
    }
    (void) printf(
        "mac=%02x:%02x:%02x:%02x:%02x:%02x; listening for GOOSE and SV\r\n",
        network_interface->hwaddr[MAC_ADDRESS_BYTE_0],
        network_interface->hwaddr[MAC_ADDRESS_BYTE_1],
        network_interface->hwaddr[MAC_ADDRESS_BYTE_2],
        network_interface->hwaddr[MAC_ADDRESS_BYTE_3],
        network_interface->hwaddr[MAC_ADDRESS_BYTE_4],
        network_interface->hwaddr[MAC_ADDRESS_BYTE_5]);
    (void) printf("batch_frames=4 stride_frames=2 malicious_gate=%.2f "
                  "agreement_window_ms=%llu\r\n",
                  (double) MALICIOUS_PROBABILITY_GATE,
                  (unsigned long long) (MODEL_AGREEMENT_WINDOW_US /
                                        MICROSECONDS_PER_MILLISECOND));
    stdio_flush();
    return true;
}

static bool
initialize_lwip_fallback_once (void)
{
    async_context_poll_t context = {0};

    if (!async_context_poll_init_with_defaults(&context))
    {
        return false;
    }
    if (!lwip_nosys_init(&context.core))
    {
        async_context_deinit(&context.core);
        return false;
    }
    lwip_nosys_deinit(&context.core);
    async_context_deinit(&context.core);
    return true;
}

static void
halt_startup (const char * message)
{
    (void) printf("error: %s\r\n", message);
    stdio_flush();
    while (true)
    {
        sleep_ms(RETRY_DELAY_MS);
    }
}

static void
initialize_usb_console (void)
{
    absolute_time_t serial_deadline = {0};
    bool            usb_connected   = false;

    if (!stdio_init_all())
    {
        /* USB diagnostics cannot be used if their driver did not initialize. */
        while (true)
        {
            gpio_put(CLASS_LED_PIN, true);
            sleep_ms(USB_CONNECT_POLL_INTERVAL_MS);
            gpio_put(CLASS_LED_PIN, false);
            sleep_ms(USB_CONNECT_POLL_INTERVAL_MS);
        }
    }
    sleep_ms(USB_STARTUP_DELAY_MS);
    serial_deadline = make_timeout_time_ms(USB_SERIAL_WAIT_MS);
    while (!stdio_usb_connected() && !time_reached(serial_deadline))
    {
        sleep_ms(USB_CONNECT_POLL_INTERVAL_MS);
    }
    usb_connected = stdio_usb_connected();
    if (usb_connected)
    {
        sleep_ms(USB_POST_CONNECT_DELAY_MS);
    }
    (void) printf(
        "startup=usb_stdio_initialized; connected=%u clk_sys_khz=%u\r\n",
        (unsigned int) usb_connected, SYSTEM_CLOCK_KHZ);
    (void) printf("analyzer_stream_capacity goose=%u sv=%u\r\n",
                  ANALYZER_MAXIMUM_GOOSE_STREAMS, ANALYZER_MAXIMUM_SV_STREAMS);
    stdio_flush();
}

static void
print_periodic_summary (app_statistics_t * statistics)
{
    uint32_t               rx              = 0u;
    uint32_t               tx              = 0u;
    uint32_t               bad_crc         = 0u;
    uint16_t               phy             = 0u;
    unsigned int           speed           = 0u;
    analyzer_diagnostics_t diagnostics     = {0};
    incident_status_t      incident_status = {0};

    analyzer_get_diagnostics(&diagnostics);
    incident_get_status(&incident_status);
    netif_rmii_ethernet_get_stats(&tx, &rx, &bad_crc, &phy);
    speed = (unsigned int) ((phy >> PHY_SPEED_SHIFT) & PHY_SPEED_MASK);
    (void) printf(
        "stats rx=%lu bad_crc=%lu queue_dropped=%lu parsed_goose=%lu "
        "predictions=%lu goose_predictions=%lu sv_predictions=%lu "
        "sequence_gaps=%lu unsupported_streams=%lu "
        "unsupported_sv_asdu=%lu malformed=%lu analyze_avg_us=%lu "
        "analyze_max_us=%lu link=%s incidents=%lu lost_containers=%lu "
        "lost_batches=%lu lost_packets=%lu alert_submit_failed=%lu "
        "alert_queue_dropped=%lu\r\n",
        (unsigned long) rx, (unsigned long) bad_crc,
        (unsigned long) netif_rmii_ethernet_capture_dropped(),
        (unsigned long) statistics->parsed_goose,
        (unsigned long) statistics->predictions,
        (unsigned long) statistics->goose_count,
        (unsigned long) statistics->sv_count, (unsigned long) statistics->gaps,
        (unsigned long) diagnostics.unsupported_streams,
        (unsigned long) diagnostics.unsupported_sv_asdu,
        (unsigned long) diagnostics.malformed_frames,
        (unsigned long) (statistics->analysis_samples != 0u
                             ? statistics->analysis_total /
                                   statistics->analysis_samples
                             : 0u),
        (unsigned long) statistics->analysis_max,
        speed == PHY_SPEED_10_HALF    ? "10-half"
        : speed == PHY_SPEED_10_FULL  ? "10-full"
        : speed == PHY_SPEED_100_HALF ? "100-half"
        : speed == PHY_SPEED_100_FULL ? "100-full"
                                      : "down",
        (unsigned long) incident_status.completed_containers,
        (unsigned long) incident_status.lost_containers,
        (unsigned long) incident_status.lost_batches,
        (unsigned long) incident_status.lost_packets,
        (unsigned long) statistics->alert_submit_failures,
        (unsigned long) statistics->alert_queue_dropped);
    stdio_flush();
    statistics->analysis_total   = 0u;
    statistics->analysis_max     = 0u;
    statistics->analysis_samples = 0u;
}

static bool
process_captured_frame (uint8_t * frame, app_statistics_t * statistics)
{
    uint16_t                 length       = 0u;
    uint32_t                 sequence     = 0u;
    uint64_t                 timestamp_us = 0u;
    static analyzer_result_t result;
    uint64_t                 started = 0u;
    uint64_t                 elapsed = 0u;

    if (!netif_rmii_ethernet_dequeue_frame(frame, MAXIMUM_FRAME_LENGTH, &length,
                                           &sequence, &timestamp_us))
    {
        return false;
    }
    memset(&result, 0, sizeof(result));
    if (statistics->have_sequence &&
        sequence != statistics->previous_sequence + 1u)
    {
        analyzer_reset();
        incident_capture_gap(timestamp_us);
        ++statistics->gaps;
        (void) printf("capture_gap sequence=%lu previous=%lu; "
                      "feature_state_reset\r\n",
                      (unsigned long) sequence,
                      (unsigned long) statistics->previous_sequence);
    }
    statistics->previous_sequence = sequence;
    statistics->have_sequence     = true;

    started = time_us_64();
    if (!analyzer_process_ethernet_capture(frame, length, timestamp_us,
                                           sequence, &result))
    {
        elapsed = time_us_64() - started;
        statistics->analysis_total += elapsed;
        if (elapsed > statistics->analysis_max)
        {
            statistics->analysis_max = (uint32_t) elapsed;
        }
        ++statistics->analysis_samples;
        return true;
    }
    elapsed = time_us_64() - started;
    statistics->analysis_total += elapsed;
    if (elapsed > statistics->analysis_max)
    {
        statistics->analysis_max = (uint32_t) elapsed;
    }
    ++statistics->analysis_samples;

    if (result.protocol == ANALYZER_PROTOCOL_GOOSE)
    {
        ++statistics->parsed_goose;
    }
    if (!result.prediction_ready)
    {
        return true;
    }
    ++statistics->predictions;
    {
        const uint64_t now_us = time_us_64();
        incident_check_stale(now_us);
        if (now_us >= result.timestamp_us &&
            now_us - result.timestamp_us <= MODEL_AGREEMENT_WINDOW_US)
        {
            incident_observe_analyzer_prediction(&result);
        }
        incident_check_stale(time_us_64());
        track_new_incident(statistics);
    }
    if (result.protocol == ANALYZER_PROTOCOL_GOOSE)
    {
        ++statistics->goose_count;
    }
    else
    {
        ++statistics->sv_count;
    }
    if (statistics->predictions % PREDICTION_LOG_INTERVAL == 0u)
    {
        print_result(&result, sequence);
    }
    return true;
}

static bool
process_available_frames (uint8_t * frame, app_statistics_t * statistics)
{
    bool   received  = false;
    size_t processed = 0u;

    while (processed < CAPTURE_SLICE_LIMIT &&
           process_captured_frame(frame, statistics))
    {
        received = true;
        ++processed;
    }
    return received;
}

static bool
queue_open_incident_alert (size_t container_index, uint64_t id)
{
    static incident_batch_summary_t goose;
    static incident_batch_summary_t sv;
    static unsigned int             goose_sequence[ANALYZER_BATCH_FRAME_COUNT];
    static unsigned int             sv_sequence[ANALYZER_BATCH_FRAME_COUNT];
    size_t                          index = 0u;

    for (index = 0u; index < ALERT_QUEUE_CAPACITY; ++index)
    {
        pending_alert_t * pending      = &g_pending_alerts[index];
        int               written      = 0;
        size_t            packet_index = 0u;

        if (pending->used)
        {
            continue;
        }
        if (!incident_read_batch(container_index, 0u, &goose) ||
            !incident_read_batch(container_index, 1u, &sv))
        {
            return false;
        }
        for (packet_index = 0u; packet_index < ANALYZER_BATCH_FRAME_COUNT;
             ++packet_index)
        {
            goose_sequence[packet_index] =
                (unsigned int) goose.packets[packet_index].capture_sequence;
            sv_sequence[packet_index] =
                (unsigned int) sv.packets[packet_index].capture_sequence;
        }
        written = snprintf(
            pending->message, sizeof(pending->message),
            "ALERT IEC61850 id=%016llx GOOSE=%.1f%% app=0x%04x stream=%08lx "
            "seq=%u,%u,%u,%u count=%lu..%lu SV=%.1f%% app=0x%04x "
            "stream=%08lx seq=%u,%u,%u,%u count=%lu..%lu",
            (unsigned long long) id, (double) (goose.raw_score * 100.0f),
            (unsigned int) goose.appid, (unsigned long) goose.stream_key,
            goose_sequence[0], goose_sequence[1],
            goose_sequence[BATCH_INDEX_THIRD_FROM_END],
            goose_sequence[BATCH_INDEX_LAST],
            (unsigned long) goose.packets[0].counter_1,
            (unsigned long) goose.packets[BATCH_INDEX_LAST].counter_1,
            (double) (sv.raw_score * 100.0f), (unsigned int) sv.appid,
            (unsigned long) sv.stream_key, sv_sequence[0], sv_sequence[1],
            sv_sequence[BATCH_INDEX_THIRD_FROM_END],
            sv_sequence[BATCH_INDEX_LAST],
            (unsigned long) sv.packets[0].counter_1,
            (unsigned long) sv.packets[BATCH_INDEX_LAST].counter_1);
        if (written > 0 && (size_t) written < sizeof(pending->message))
        {
            pending->incident_id = id;
            pending->used        = true;
            return true;
        }
        return false;
    }
    return false;
}

static void
track_new_incident (app_statistics_t * statistics)
{
    incident_status_t         status = {0};
    incident_container_info_t info   = {0};
    size_t                    index  = 0u;

    incident_get_status(&status);
    if (status.active_container_id_wide == 0u ||
        status.active_container_id_wide == g_last_active_id)
    {
        return;
    }
    for (index = 0u; index < INCIDENT_MAXIMUM_CONTAINERS; ++index)
    {
        if (incident_peek(index, &info) && !info.complete &&
            info.id == status.active_container_id_wide)
        {
            if (queue_open_incident_alert(index, info.id))
            {
                g_last_active_id = status.active_container_id_wide;
            }
            else
            {
                ++statistics->alert_queue_dropped;
                g_last_active_id = status.active_container_id_wide;
            }
            set_led(true);
            return;
        }
    }
    ++statistics->alert_queue_dropped;
}

static void
service_pending_alerts (app_statistics_t * statistics)
{
    const uint64_t             now_us = time_us_64();
    size_t                     index  = 0u;
    wifi_notification_status_t status = {0};

    wifi_notification_service();
    wifi_notification_get_status(&status);
    if (g_test_in_flight && (status.succeeded != g_test_succeeded_before ||
                             status.failed != g_test_failed_before))
    {
        (void) printf("manual_test_result=%s stage=%u http=%u\r\n",
                      status.succeeded != g_test_succeeded_before ? "delivered"
                                                                  : "failed",
                      (unsigned int) status.last_result,
                      (unsigned int) status.last_http_status);
        g_test_in_flight = false;
    }
    if (g_test_in_flight)
    {
        return;
    }
    for (index = 0u; index < ALERT_QUEUE_CAPACITY; ++index)
    {
        pending_alert_t * pending = &g_pending_alerts[index];
        if (!pending->used || !pending->in_flight)
        {
            continue;
        }
        if (status.succeeded != pending->succeeded_before_submit)
        {
            (void) printf("alert_delivered id=%016llx\r\n",
                          (unsigned long long) pending->incident_id);
            memset(pending, 0, sizeof(*pending));
        }
        else if (status.failed != pending->failed_before_submit)
        {
            pending->in_flight = false;
            if (pending->attempts >= ALERT_MAXIMUM_ATTEMPTS)
            {
                (void) printf("alert_failed id=%016llx attempts=%u\r\n",
                              (unsigned long long) pending->incident_id,
                              (unsigned int) pending->attempts);
                memset(pending, 0, sizeof(*pending));
            }
        }
    }
    if (now_us - g_last_alert_attempt_us <
        (uint64_t) ALERT_RETRY_INTERVAL_MS * MICROSECONDS_PER_MILLISECOND)
    {
        return;
    }
    for (index = 0u; index < ALERT_QUEUE_CAPACITY; ++index)
    {
        if (!g_pending_alerts[index].used || g_pending_alerts[index].in_flight)
        {
            continue;
        }
        g_last_alert_attempt_us = now_us;
        if (wifi_notification_submit(g_pending_alerts[index].message))
        {
            g_pending_alerts[index].in_flight               = true;
            g_pending_alerts[index].succeeded_before_submit = status.succeeded;
            g_pending_alerts[index].failed_before_submit    = status.failed;
            ++g_pending_alerts[index].attempts;
            (void) printf(
                "alert_queued id=%016llx attempt=%u\r\n",
                (unsigned long long) g_pending_alerts[index].incident_id,
                (unsigned int) g_pending_alerts[index].attempts);
        }
        else
        {
            ++statistics->alert_submit_failures;
        }
        return;
    }
}

static void
service_usb_command (app_statistics_t * statistics)
{
    int character = getchar_timeout_us(0u);

    if (character != 't' && character != 'T')
    {
        return;
    }
    {
        wifi_notification_status_t wifi_status     = {0};
        incident_status_t          incident_status = {0};
        wifi_notification_get_status(&wifi_status);
        incident_get_status(&incident_status);
        (void) printf(
            "test_status stack=%u wifi=%u busy=%u sent=%lu "
            "failed=%lu last_stage=%u http=%u incidents=%lu "
            "active=%016llx\r\n",
            (unsigned int) wifi_status.stack_ready,
            (unsigned int) wifi_status.wifi_connected,
            (unsigned int) wifi_status.busy,
            (unsigned long) wifi_status.succeeded,
            (unsigned long) wifi_status.failed,
            (unsigned int) wifi_status.last_result,
            (unsigned int) wifi_status.last_http_status,
            (unsigned long) incident_status.completed_containers,
            (unsigned long long) incident_status.active_container_id_wide);
        if (wifi_status.busy || g_test_in_flight)
        {
            ++statistics->alert_submit_failures;
        }
        else if (wifi_notification_submit("IEC61850 monitor manual test"))
        {
            g_test_in_flight        = true;
            g_test_succeeded_before = wifi_status.succeeded;
            g_test_failed_before    = wifi_status.failed;
        }
        else
        {
            ++statistics->alert_submit_failures;
        }
    }
}

int
main (void)
{
    static struct netif network_interface;
    static uint8_t      frame[MAXIMUM_FRAME_LENGTH];
    absolute_time_t     next_summary     = {0};
    app_statistics_t    statistics       = {0};
    bool                led_on           = false;
    bool                wifi_stack_ready = false;

    set_sys_clock_khz(SYSTEM_CLOCK_KHZ, true);
    gpio_init(CLASS_LED_PIN);
    gpio_set_dir(CLASS_LED_PIN, GPIO_OUT);
    set_led(false);
    initialize_usb_console();

    (void) printf("startup=wifi_init_begin\r\n");
    stdio_flush();
    wifi_stack_ready = wifi_notification_init();
    {
        wifi_notification_status_t wifi_status = {0};
        wifi_notification_get_status(&wifi_status);
        wifi_stack_ready = wifi_status.stack_ready;
    }
    (void) printf("startup=wifi_init_complete; stack=%u\r\n",
                  (unsigned int) wifi_stack_ready);
    stdio_flush();
    if (!wifi_stack_ready)
    {
        /* The SDK guard prevents repeating lwIP pools after CYW43 failure. */
        if (!initialize_lwip_fallback_once())
        {
            halt_startup("lwIP fallback initialization failed");
        }
        (void) printf(
            "warning=wifi_notification_unavailable; continuing_rmii\r\n");
    }

    if (!initialize_network_interface(&network_interface, wifi_stack_ready))
    {
        halt_startup("RMII network interface initialization failed");
    }
    (void) printf("startup=rmii_init_complete\r\n");
    stdio_flush();

    analyzer_reset();
    {
        pico_unique_board_id_t board_id     = {0};
        const uint64_t         boot_time_us = time_us_64();
        pico_get_unique_board_id(&board_id);
        incident_initialize(
            incident_persistent_session_id(&board_id, boot_time_us));
    }
    (void) printf("startup=capture_core_starting\r\n");
    stdio_flush();
    multicore_launch_core1(netif_rmii_ethernet_loop);
    (void) printf("startup=main_loop\r\n");
    stdio_flush();
    next_summary = make_timeout_time_ms(FIRST_SUMMARY_INTERVAL_MS);
    watchdog_enable(WATCHDOG_TIMEOUT_MS, true);
    while (true)
    {

        bool received = false;
        watchdog_update();
        received = process_available_frames(frame, &statistics);
        incident_check_stale(time_us_64());
        track_new_incident(&statistics);
        {
            incident_status_t incident_status = {0};
            incident_get_status(&incident_status);
            const bool active = incident_status.active_container_id_wide != 0u;
            if (active != led_on)
            {
                led_on = active;
                set_led(led_on);
            }
        }
        service_pending_alerts(&statistics);
        service_usb_command(&statistics);

        if (time_reached(next_summary))
        {
            next_summary = make_timeout_time_ms(SUMMARY_INTERVAL_MS);
            print_periodic_summary(&statistics);
        }
        if (!received)
        {
            sleep_us(IDLE_DELAY_US);
        }
    }
}
