#include "analyzer.h"
#include "hardware/clocks.h"
#include "hardware/watchdog.h"
#include "pico/multicore.h"
#include "pico/stdlib.h"
extern "C"
{
#include "lwip/init.h"
#include "rmii_ethernet/netif.h"
}

#include <cstddef>
#include <cstdint>
#include <cstdio>
namespace
{
constexpr unsigned int  kRmiiTransmitPinStart     = 0;
constexpr unsigned int  kRmiiManagementPinStart   = 4;
constexpr unsigned int  kRmiiReceivePinStart      = 6;
constexpr unsigned int  kClassLedPin              = 15;
constexpr std::size_t   kMaximumFrameLength       = 1518;
constexpr float         kMaliciousProbabilityGate = 0.30f;
constexpr std::uint64_t kModelAgreementWindowUs   = 1000000u;
struct ModelVote
{
    float         probability{};
    std::uint64_t timestamp_us{};
    bool          available{};
};
bool
recent_malicious_vote (const ModelVote & v, std::uint64_t now)
{
    return v.available && now >= v.timestamp_us &&
           now - v.timestamp_us <= kModelAgreementWindowUs &&
           v.probability >= kMaliciousProbabilityGate;
}
bool
models_agree_malicious (const ModelVote & g, const ModelVote & s,
                        std::uint64_t now)
{
    return recent_malicious_vote(g, now) && recent_malicious_vote(s, now);
}
void
set_led (bool on)
{
    gpio_put(kClassLedPin, on);
}
const char *
protocol_name (AnalyzerProtocol p)
{
    return p == AnalyzerProtocol::Goose ? "GOOSE" : "SV";
}
void
print_result (const AnalyzerResult & r, std::uint32_t seq)
{
    const unsigned int cls = r.primary_label == 1u ? 1u : 2u;
    std::printf("frame=%lu protocol=%s model=batch_rf window=4/stride=2 "
                "stream=%08lx appid=0x%04x class=%u label=%u "
                "probability_label_1=%.6f counter1=%lu counter2=%lu\r\n",
                static_cast<unsigned long>(seq), protocol_name(r.protocol),
                static_cast<unsigned long>(r.stream_key),
                static_cast<unsigned int>(r.appid), cls,
                static_cast<unsigned int>(r.primary_label),
                static_cast<double>(r.primary_probability),
                static_cast<unsigned long>(r.counter_1),
                static_cast<unsigned long>(r.counter_2));
}
void
link_callback (struct netif * n)
{
    std::printf("link=%s\r\n", netif_is_link_up(n) ? "up" : "down");
}
} // namespace
int
main ()
{
    stdio_init_all();
    set_sys_clock_khz(50000u, true);
    sleep_ms(1200);
    gpio_init(kClassLedPin);
    gpio_set_dir(kClassLedPin, GPIO_OUT);
    set_led(false);
    lwip_init();
    
    static struct netif               network_interface;
    struct netif_rmii_ethernet_config config =
        NETIF_RMII_ETHERNET_DEFAULT_CONFIG();
    config.pio            = pio1;
    config.pio_sm_start   = 0;
    config.rx_pin_start   = kRmiiReceivePinStart;
    config.tx_pin_start   = kRmiiTransmitPinStart;
    config.mdio_pin_start = kRmiiManagementPinStart;
    const err_t network_init_error =
        netif_rmii_ethernet_init(&network_interface, &config);
    if (network_init_error != ERR_OK)
    {
        while (true)
        {
            std::printf("error: RMII network interface initialization failed; "
                        "err=%d\r\n",
                        static_cast<int>(network_init_error));
            sleep_ms(2000);
        }
    }
    netif_set_link_callback(&network_interface, link_callback);
    netif_set_default(&network_interface);
    netif_set_up(&network_interface);
    std::printf(
        "mac=%02x:%02x:%02x:%02x:%02x:%02x; listening for GOOSE and SV\r\n",
        network_interface.hwaddr[0], network_interface.hwaddr[1],
        network_interface.hwaddr[2], network_interface.hwaddr[3],
        network_interface.hwaddr[4], network_interface.hwaddr[5]);
    std::printf(
        "batch_frames=4 stride_frames=2 malicious_gate=%.2f "
        "agreement_window_ms=%llu\r\n",
        static_cast<double>(kMaliciousProbabilityGate),
        static_cast<unsigned long long>(kModelAgreementWindowUs / 1000u));
    analyzer_reset();
    multicore_launch_core1(netif_rmii_ethernet_loop);
    watchdog_enable(8000u, true);
    static std::uint8_t frame[kMaximumFrameLength];
    std::uint32_t       goose_count = 0, sv_count = 0, parsed_goose = 0,
                        predictions = 0, gaps = 0;
    std::uint32_t previous_sequence = 0, analysis_max = 0, analysis_samples = 0;
    std::uint64_t analysis_total = 0;
    bool          have_sequence = false, led_on = false;
    ModelVote     goose_vote{}, sv_vote{};
    absolute_time_t next_summary = make_timeout_time_ms(10000);
    while (true)
    {
        watchdog_update();
        bool          received     = false;
        std::uint16_t length       = 0;
        std::uint32_t sequence     = 0;
        std::uint64_t timestamp_us = 0;
        while (netif_rmii_ethernet_dequeue_frame(frame, sizeof(frame), &length,
                                                 &sequence, &timestamp_us))
        {
            received = true;
            if (have_sequence && sequence != previous_sequence + 1u)
            {
                analyzer_reset();
                goose_vote = {};
                sv_vote    = {};
                ++gaps;
                std::printf("capture_gap sequence=%lu previous=%lu; "
                            "feature_state_reset\r\n",
                            static_cast<unsigned long>(sequence),
                            static_cast<unsigned long>(previous_sequence));
            }
            previous_sequence = sequence;
            have_sequence     = true;
            AnalyzerResult result{};
            const auto     started = time_us_64();
            const bool     parsed  = analyzer_process_ethernet_frame(
                frame, length, timestamp_us, &result);
            const auto elapsed = time_us_64() - started;
            analysis_total += elapsed;
            if (elapsed > analysis_max)
                analysis_max = static_cast<std::uint32_t>(elapsed);
            ++analysis_samples;
            if (!parsed)
                continue;
            if (result.protocol == AnalyzerProtocol::Goose)
                ++parsed_goose;
            if (!result.prediction_ready)
                continue;
            ++predictions;
            ModelVote & vote = (result.protocol == AnalyzerProtocol::Goose)
                                   ? goose_vote
                                   : sv_vote;
            vote             = {result.primary_probability, timestamp_us, true};
            if (result.protocol == AnalyzerProtocol::Goose)
                ++goose_count;
            else
                ++sv_count;
            if (result.label_changed || predictions % 1000u == 0u)
                print_result(result, sequence);
        }
        const bool alarm =
            models_agree_malicious(goose_vote, sv_vote, time_us_64());
        if (alarm != led_on)
        {
            led_on = alarm;
            set_led(led_on);
            std::printf("model_agreement led=%s goose_p=%.6f goose_seen=%u "
                        "sv_p=%.6f sv_seen=%u gate=%.2f window_ms=%llu\r\n",
                        led_on ? "on" : "off",
                        static_cast<double>(goose_vote.probability),
                        static_cast<unsigned>(goose_vote.available),
                        static_cast<double>(sv_vote.probability),
                        static_cast<unsigned>(sv_vote.available),
                        static_cast<double>(kMaliciousProbabilityGate),
                        static_cast<unsigned long long>(
                            kModelAgreementWindowUs / 1000u));
        }
        if (time_reached(next_summary))
        {
            next_summary           = make_timeout_time_ms(10000);
            std::uint32_t       tx = 0, rx = 0, bad_crc = 0;
            std::uint16_t       phy = 0;
            AnalyzerDiagnostics d{};
            analyzer_get_diagnostics(&d);
            netif_rmii_ethernet_get_stats(&tx, &rx, &bad_crc, &phy);
            const unsigned speed = (phy >> 2u) & 7u;
            std::printf(
                "stats rx=%lu bad_crc=%lu queue_dropped=%lu parsed_goose=%lu "
                "predictions=%lu goose_predictions=%lu sv_predictions=%lu "
                "sequence_gaps=%lu unsupported_streams=%lu "
                "unsupported_sv_asdu=%lu malformed=%lu analyze_avg_us=%lu "
                "analyze_max_us=%lu link=%s\r\n",
                static_cast<unsigned long>(rx),
                static_cast<unsigned long>(bad_crc),
                static_cast<unsigned long>(
                    netif_rmii_ethernet_capture_dropped()),
                static_cast<unsigned long>(parsed_goose),
                static_cast<unsigned long>(predictions),
                static_cast<unsigned long>(goose_count),
                static_cast<unsigned long>(sv_count),
                static_cast<unsigned long>(gaps),
                static_cast<unsigned long>(d.unsupported_streams),
                static_cast<unsigned long>(d.unsupported_sv_asdu),
                static_cast<unsigned long>(d.malformed_frames),
                static_cast<unsigned long>(
                    analysis_samples ? analysis_total / analysis_samples : 0),
                static_cast<unsigned long>(analysis_max),
                speed == 1u   ? "10-half"
                : speed == 5u ? "10-full"
                : speed == 2u ? "100-half"
                : speed == 6u ? "100-full"
                              : "down");
            analysis_total   = 0;
            analysis_max     = 0;
            analysis_samples = 0;
        }
        if (!received)
            sleep_us(100);
    }
}
