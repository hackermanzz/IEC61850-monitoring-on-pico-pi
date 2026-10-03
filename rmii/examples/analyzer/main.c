/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Pico RMII capture, analyzer, diagnostics, and dual-model LED application.
 */

#include "analyzer.h"
#include "main.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "hardware/clocks.h"
#include "hardware/watchdog.h"
#include "lwip/init.h"
#include "pico/multicore.h"
#include "pico/stdlib.h"
#include "rmii_ethernet/netif.h"
#include "sdcard.h"

typedef struct
{
    float    probability;
    uint64_t timestamp_us;
    bool     available;
} model_vote_t;

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
} app_statistics_t;

static bool
recent_malicious_vote (const model_vote_t * vote, uint64_t now_us)
{
    return vote->available && now_us >= vote->timestamp_us &&
           now_us - vote->timestamp_us <= MODEL_AGREEMENT_WINDOW_US &&
           vote->probability >= MALICIOUS_PROBABILITY_GATE;
}

static bool
models_agree_malicious (const model_vote_t * goose_vote,
                        const model_vote_t * sv_vote, uint64_t now_us)
{
    return recent_malicious_vote(goose_vote, now_us) &&
           recent_malicious_vote(sv_vote, now_us);
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

static void
initialize_network_interface (struct netif * network_interface)
{
    struct netif_rmii_ethernet_config config =
        (struct netif_rmii_ethernet_config)
            NETIF_RMII_ETHERNET_DEFAULT_CONFIG();
    err_t network_init_error = ERR_OK;

    lwip_init();
    config.pio            = pio1;
    config.pio_sm_start   = 0u;
    config.rx_pin_start   = RMII_RECEIVE_PIN_START;
    config.tx_pin_start   = RMII_TRANSMIT_PIN_START;
    config.mdio_pin_start = RMII_MANAGEMENT_PIN_START;
    network_init_error = netif_rmii_ethernet_init(network_interface, &config);
    if (network_init_error != ERR_OK)
    {
        while (true)
        {
            (void) printf(
                "error: RMII network interface initialization failed; "
                "err=%d\r\n",
                (int) network_init_error);
            sleep_ms(RETRY_DELAY_MS);
        }
    }
    netif_set_link_callback(network_interface, link_callback);
    netif_set_default(network_interface);
    netif_set_up(network_interface);
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
}

static void
print_periodic_summary (app_statistics_t * statistics)
{
    uint32_t rx = 0u;
    uint32_t tx = 0u;
    uint32_t bad_crc = 0u;
    uint16_t phy = 0u;
    unsigned int speed = 0u;
    analyzer_diagnostics_t diagnostics = {0};

    analyzer_get_diagnostics(&diagnostics);
    netif_rmii_ethernet_get_stats(&tx, &rx, &bad_crc, &phy);
    speed = (unsigned int) ((phy >> PHY_SPEED_SHIFT) & PHY_SPEED_MASK);
    (void) printf(
        "stats rx=%lu bad_crc=%lu queue_dropped=%lu parsed_goose=%lu "
        "predictions=%lu goose_predictions=%lu sv_predictions=%lu "
        "sequence_gaps=%lu unsupported_streams=%lu "
        "unsupported_sv_asdu=%lu malformed=%lu analyze_avg_us=%lu "
        "analyze_max_us=%lu link=%s\r\n",
        (unsigned long) rx, (unsigned long) bad_crc,
        (unsigned long) netif_rmii_ethernet_capture_dropped(),
        (unsigned long) statistics->parsed_goose,
        (unsigned long) statistics->predictions,
        (unsigned long) statistics->goose_count,
        (unsigned long) statistics->sv_count,
        (unsigned long) statistics->gaps,
        (unsigned long) diagnostics.unsupported_streams,
        (unsigned long) diagnostics.unsupported_sv_asdu,
        (unsigned long) diagnostics.malformed_frames,
        (unsigned long) (statistics->analysis_samples != 0u
                             ? statistics->analysis_total /
                                   statistics->analysis_samples
                             : 0u),
        (unsigned long) statistics->analysis_max,
        speed == PHY_SPEED_10_HALF    ? "10-half"
        : speed == PHY_SPEED_10_FULL ? "10-full"
        : speed == PHY_SPEED_100_HALF ? "100-half"
        : speed == PHY_SPEED_100_FULL ? "100-full"
                                      : "down");
    statistics->analysis_total   = 0u;
    statistics->analysis_max     = 0u;
    statistics->analysis_samples = 0u;
}

static bool
process_captured_frame (uint8_t * frame, app_statistics_t * statistics,
                       model_vote_t * goose_vote, model_vote_t * sv_vote)
{
    uint16_t length = 0u;
    uint32_t sequence = 0u;
    uint64_t timestamp_us = 0u;
    analyzer_result_t result = {0};
    uint64_t started = 0u;
    uint64_t elapsed = 0u;

    if (!netif_rmii_ethernet_dequeue_frame(frame, MAXIMUM_FRAME_LENGTH, &length,
                                           &sequence, &timestamp_us))
    {
        return false;
    }
    if (statistics->have_sequence &&
        sequence != statistics->previous_sequence + 1u)
    {
        analyzer_reset();
        *goose_vote = (model_vote_t){0.0f, 0u, false};
        *sv_vote    = (model_vote_t){0.0f, 0u, false};
        ++statistics->gaps;
        (void) printf("capture_gap sequence=%lu previous=%lu; "
                      "feature_state_reset\r\n",
                      (unsigned long) sequence,
                      (unsigned long) statistics->previous_sequence);
    }
    statistics->previous_sequence = sequence;
    statistics->have_sequence     = true;

    started = time_us_64();
    if (!analyzer_process_ethernet_frame(frame, length, timestamp_us, &result))
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
    if (result.protocol == ANALYZER_PROTOCOL_GOOSE)
    {
        goose_vote->probability  = result.primary_probability;
        goose_vote->timestamp_us = timestamp_us;
        goose_vote->available    = true;
        ++statistics->goose_count;
    }
    else
    {
        sv_vote->probability  = result.primary_probability;
        sv_vote->timestamp_us = timestamp_us;
        sv_vote->available    = true;
        ++statistics->sv_count;
    }
    if (result.label_changed ||
        statistics->predictions % PREDICTION_LOG_INTERVAL == 0u)
    {
        print_result(&result, sequence);
    }
    return true;
}

static bool
process_available_frames (uint8_t * frame, app_statistics_t * statistics,
                          model_vote_t * goose_vote, model_vote_t * sv_vote)
{
    bool received = false;

    while (process_captured_frame(frame, statistics, goose_vote, sv_vote))
    {
        received = true;
    }
    return received;
}

static void
update_model_agreement_led (const model_vote_t * goose_vote,
                            const model_vote_t * sv_vote, bool * led_on)
{
    const bool alarm =
        models_agree_malicious(goose_vote, sv_vote, time_us_64());

    if (alarm != *led_on)
    {
        *led_on = alarm;
        set_led(*led_on);
        (void) printf(
            "model_agreement led=%s goose_p=%.6f goose_seen=%u "
            "sv_p=%.6f sv_seen=%u gate=%.2f window_ms=%llu\r\n",
            *led_on ? "on" : "off", (double) goose_vote->probability,
            (unsigned int) goose_vote->available,
            (double) sv_vote->probability, (unsigned int) sv_vote->available,
            (double) MALICIOUS_PROBABILITY_GATE,
            (unsigned long long) (MODEL_AGREEMENT_WINDOW_US /
                                  MICROSECONDS_PER_MILLISECOND));
    }
}

int
main (void)
{
    static struct netif               network_interface;
    static uint8_t                    frame[MAXIMUM_FRAME_LENGTH];
    model_vote_t    goose_vote = {0.0f, 0u, false};
    model_vote_t    sv_vote    = {0.0f, 0u, false};
    absolute_time_t next_summary = {0};
    app_statistics_t statistics = {0};
    bool             led_on = false;

    stdio_init_all();
    set_sys_clock_khz(SYSTEM_CLOCK_KHZ, true);
    sleep_ms(USB_STARTUP_DELAY_MS);
    (void) printf("startup=usb_stdio_initialized; initializing_rmii\r\n");

    gpio_init(CLASS_LED_PIN);
    gpio_set_dir(CLASS_LED_PIN, GPIO_OUT);
    set_led(false);

    initialize_network_interface(&network_interface);

    analyzer_reset();
    multicore_launch_core1(netif_rmii_ethernet_loop);
    watchdog_enable(WATCHDOG_TIMEOUT_MS, true);
    next_summary = make_timeout_time_ms(SUMMARY_INTERVAL_MS);

    while (true)
    {

        bool received = false;
        watchdog_update();
        received = process_available_frames(frame, &statistics, &goose_vote,
                                            &sv_vote);
        update_model_agreement_led(&goose_vote, &sv_vote, &led_on);
        if (goose_vote.probability != sv_vote.probability){
            printf("GOOSE probabiliy: %f", goose_vote.probability);
            printf("SV probabiliy: %f", sv_vote.probability);
        } 

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
