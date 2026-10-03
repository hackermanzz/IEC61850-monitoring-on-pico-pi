#include "analyzer.h"

#include "generated_batch_models.h"

#include <cmath>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace
{

constexpr std::uint16_t kGooseEtherType = 0x88b8;
constexpr std::uint16_t kSvEtherType = 0x88ba;

constexpr std::size_t kBatchFrames = pico_ml_batch::kBatchSizeFrames;
constexpr std::size_t kBatchStride = pico_ml_batch::kBatchStrideFrames;
constexpr std::size_t kTimingHistory = pico_ml_batch::kTimingHistoryFrames;
constexpr std::size_t kWaveHistory = pico_ml_batch::kWaveHistorySamples;
constexpr std::size_t kMaximumAsdus = 14u;
// State capacity is fixed for RP2040. Streams are never silently evicted.
constexpr std::size_t kMaximumGooseStreams = 4u;
constexpr std::size_t kMaximumSvStreams = 2u;
constexpr std::size_t kMaximumTrackedStreamIdLength = 64u;
constexpr std::size_t kMaximumDestinationMacLength = 6u;
static_assert(
    kBatchFrames == 4u && kBatchStride == 2u,
    "Analyzer supports the trained four-frame/stride-two batch contract");
static_assert(pico_ml_batch::kSvChannelCount == 6u &&
                  pico_ml_batch::kSvChannelFormat[0] == '>' &&
                  pico_ml_batch::kSvChannelFormat[1] == 'f',
              "Analyzer currently supports six big-endian float32 SV channels");
static_assert(
    kWaveHistory == 128u && kTimingHistory == 32u,
    "Review state-memory sizing when training history settings change");

struct EthernetPayload
{
    std::uint16_t type;
    const std::uint8_t* data;
    std::size_t length;
};

struct Tlv
{
    std::uint8_t tag;
    const std::uint8_t* value;
    std::size_t length;
    const std::uint8_t* next;
};

struct GooseFields
{
    std::uint16_t appid;
    const std::uint8_t* gocb_ref;
    std::size_t gocb_ref_length;
    const std::uint8_t* dataset;
    std::size_t dataset_length;
    const std::uint8_t* go_id;
    std::size_t go_id_length;
    const std::uint8_t* timestamp;
    std::size_t timestamp_length;
    const std::uint8_t* all_data;
    std::size_t all_data_length;
    std::uint32_t ttl_ms;
    std::uint32_t st_num;
    std::uint32_t sq_num;
    std::uint32_t conf_rev;
    std::uint32_t num_entries;
    bool simulation;
    bool nds_com;
};

struct SvFields
{
    struct Asdu
    {
        const std::uint8_t* sv_id{};
        std::size_t sv_id_length{};
        std::uint32_t smp_cnt{};
        std::uint32_t conf_rev{};
        std::uint32_t smp_synch{};
        const std::uint8_t* seq_data{};
        std::size_t seq_data_length{};
    } asdus[kMaximumAsdus]{};
    std::uint16_t appid;
    std::uint32_t no_asdu;
    std::size_t asdu_count;
};

struct StreamIdentity
{
    std::uint8_t destination_mac[6]{};
    std::uint16_t appid{};
    std::size_t stream_id_length{};
    std::uint8_t stream_id[kMaximumTrackedStreamIdLength]{};
};

struct GooseState
{
    bool used{};
    std::uint32_t key{};
    StreamIdentity identity{};
    float previous_intervals[kTimingHistory]{};
    std::size_t interval_count{}, interval_next{};
    std::uint64_t timestamp_us{};
    std::uint32_t st_num{}, sq_num{};
    bool has_time{}, has_st{}, has_sq{}, has_source{}, has_boolean{};
    std::uint8_t source[6]{}, boolean{};
    float batch[kBatchFrames][13]{};
    std::size_t batch_count{};
    bool has_prediction{};
    std::uint8_t previous_label{};
};

struct SvState
{
    bool used{};
    std::uint32_t key{};
    StreamIdentity identity{};
    float previous_intervals[kTimingHistory]{};
    std::size_t interval_count{}, interval_next{};
    std::uint64_t timestamp_us{};
    bool has_time{}, has_source{};
    std::uint8_t source[6]{};
    std::uint32_t counters[kMaximumAsdus]{};
    bool has_counter[kMaximumAsdus]{};
    float wave[kMaximumAsdus][6][kWaveHistory]{};
    std::uint16_t wave_count[kMaximumAsdus][6]{};
    std::uint16_t wave_next[kMaximumAsdus][6]{};
    float wave_deltas[kWaveHistory]{};
    std::size_t wave_delta_count{}, wave_delta_next{};
    float batch[kBatchFrames][18]{};
    std::size_t batch_count{};
    bool has_prediction{};
    std::uint8_t previous_label{};
};

// Separate protocol-specific state banks are what keep the packet bundles
// independent. The stream key further separates publishers within each bank.
GooseState goose_states[kMaximumGooseStreams];
SvState sv_states[kMaximumSvStreams];
std::uint64_t latest_goose_us{}, latest_sv_us{};
bool have_latest_goose{}, have_latest_sv{};
std::uint32_t unsupported_streams{}, unsupported_sv_asdu{}, malformed_frames{};
bool unsupported_parse{};
float median_scratch[kWaveHistory]{};
float timing_scratch[kTimingHistory]{};
float sv_changes[kMaximumAsdus * 6u]{};
float sv_channel_values[6][kMaximumAsdus]{};
float sv_history_scratch[kWaveHistory]{};
float last_batch_features[72]{};
std::size_t last_batch_feature_count{};
AnalyzerProtocol last_batch_protocol{AnalyzerProtocol::Goose};

std::uint16_t read_be16(const std::uint8_t* value)
{
    return static_cast<std::uint16_t>(
        (static_cast<std::uint32_t>(value[0]) << 8u) |
        static_cast<std::uint32_t>(value[1]));
}

bool read_ber_uint(const std::uint8_t* value, std::size_t length,
                   std::uint32_t* output)
{
    if (value == nullptr || output == nullptr || length == 0u || length > 5u)
    {
        return false;
    }

    // A fifth octet is valid only as BER's sign-protection zero before uint32.
    const bool has_sign_protection = length == 5u;
    if (has_sign_protection)
    {
        if (value[0] != 0u)
        {
            return false;
        }
        ++value;
        --length;
    }
    if (!has_sign_protection && (value[0] & 0x80u) != 0u)
    {
        return false;
    }

    std::uint32_t parsed = 0u;
    for (std::size_t index = 0; index < length; ++index)
    {
        parsed = (parsed << 8u) | value[index];
    }
    *output = parsed;
    return true;
}

bool read_ber_boolean(const std::uint8_t* value, std::size_t length,
                      bool* output)
{
    if (value == nullptr || output == nullptr || length != 1u)
    {
        return false;
    }
    *output = value[0] != 0u;
    return true;
}

bool read_tlv(const std::uint8_t* cursor, const std::uint8_t* end, Tlv* output)
{
    if (cursor == nullptr || end == nullptr || output == nullptr)
    {
        return false;
    }
    const std::ptrdiff_t initial_available = end - cursor;
    if (initial_available < 2)
    {
        return false;
    }

    output->tag = *cursor++;
    const std::uint8_t first_length = *cursor++;
    std::size_t length = 0;

    if ((first_length & 0x80u) == 0u)
    {
        length = first_length;
    }
    else
    {
        const std::size_t octets = first_length & 0x7fu;
        if (octets == 0u || octets > sizeof(std::size_t) ||
            static_cast<std::size_t>(end - cursor) < octets)
        {
            return false;
        }
        for (std::size_t index = 0; index < octets; ++index)
        {
            if (length > (std::numeric_limits<std::size_t>::max() >> 8u))
            {
                return false;
            }
            length = (length << 8u) | cursor[index];
        }
        cursor += octets;
    }

    const std::ptrdiff_t value_available = end - cursor;
    if (value_available < 0 ||
        length > static_cast<std::size_t>(value_available))
    {
        return false;
    }
    output->value = cursor;
    output->length = length;
    output->next = cursor + length;
    return true;
}

bool find_ethernet_payload(const std::uint8_t* frame, std::size_t length,
                           EthernetPayload* output)
{
    if (frame == nullptr || output == nullptr || length < 14u)
    {
        return false;
    }

    // TCPIP transmit in BE order. RP2040 works in LE.
    std::uint16_t type = read_be16(frame + 12u);
    std::size_t payload_offset = 14u;

    // Accept up to two 802.1Q/802.1ad tags because process-bus traffic is
    // commonly VLAN tagged.
    for (std::size_t tag = 0;
         tag < 2u && (type == 0x8100u || type == 0x88a8u || type == 0x9100u);
         ++tag)
    {
        if (payload_offset + 4u > length)
        {
            return false;
        }
        type = read_be16(frame + payload_offset + 2u);
        payload_offset += 4u;
    }

    output->type = type;
    output->data = frame + payload_offset;
    output->length = length - payload_offset;
    return true;
}

bool parse_goose(const EthernetPayload& payload, GooseFields* output)
{
    if (output == nullptr || payload.length < 10u)
    {
        return false;
    }

    const std::uint16_t apdu_length = read_be16(payload.data + 2u);
    if (apdu_length < 10u || apdu_length > payload.length)
    {
        return false;
    }
    Tlv pdu{};
    const std::uint8_t* end = payload.data + apdu_length;
    if (!read_tlv(payload.data + 8u, end, &pdu) || pdu.tag != 0x61u)
    {
        return false;
    }

    GooseFields fields{};
    fields.appid = read_be16(payload.data);
    bool have_ref = false;
    bool have_st_num = false;
    bool have_sq_num = false;

    const std::uint8_t* cursor = pdu.value;
    const std::uint8_t* pdu_end = pdu.value + pdu.length;
    while (cursor < pdu_end)
    {
        Tlv field{};
        if (!read_tlv(cursor, pdu_end, &field))
        {
            return false;
        }
        switch (field.tag)
        {
        case 0x80u:
            fields.gocb_ref = field.value;
            fields.gocb_ref_length = field.length;
            have_ref = true;
            break;
        case 0x81u:
            if (!read_ber_uint(field.value, field.length, &fields.ttl_ms))
            {
                return false;
            }
            break;
        case 0x82u:
            fields.dataset = field.value;
            fields.dataset_length = field.length;
            break;
        case 0x83u:
            fields.go_id = field.value;
            fields.go_id_length = field.length;
            break;
        case 0x84u:
            fields.timestamp = field.value;
            fields.timestamp_length = field.length;
            break;
        case 0x85u:
            if (!read_ber_uint(field.value, field.length, &fields.st_num))
            {
                return false;
            }
            have_st_num = true;
            break;
        case 0x86u:
            if (!read_ber_uint(field.value, field.length, &fields.sq_num))
            {
                return false;
            }
            have_sq_num = true;
            break;
        case 0x87u:
            if (!read_ber_boolean(field.value, field.length,
                                  &fields.simulation))
            {
                return false;
            }
            break;
        case 0x88u:
            if (!read_ber_uint(field.value, field.length, &fields.conf_rev))
            {
                return false;
            }
            break;
        case 0x89u:
            if (!read_ber_boolean(field.value, field.length, &fields.nds_com))
            {
                return false;
            }
            break;
        case 0x8au:
            if (!read_ber_uint(field.value, field.length, &fields.num_entries))
            {
                return false;
            }
            break;
        case 0xabu:
            fields.all_data = field.value;
            fields.all_data_length = field.length;
            break;
        default:
            break;
        }
        cursor = field.next;
    }

    if (!have_ref || !have_st_num || !have_sq_num)
    {
        return false;
    }
    *output = fields;
    return true;
}

bool parse_sv(const EthernetPayload& payload, SvFields* output)
{
    unsupported_parse = false;
    if (output == nullptr || payload.length < 10u)
        return false;
    const std::uint16_t apdu_length = read_be16(payload.data + 2u);
    if (apdu_length < 10u || apdu_length > payload.length)
        return false;
    Tlv apdu{};
    const std::uint8_t* end = payload.data + apdu_length;
    if (!read_tlv(payload.data + 8u, end, &apdu) || apdu.tag != 0x60u)
        return false;

    SvFields fields{};
    fields.appid = read_be16(payload.data);
    bool have_count = false;
    const std::uint8_t* sequence = nullptr;
    std::size_t sequence_length = 0u;
    const std::uint8_t* cursor = apdu.value;
    const std::uint8_t* apdu_end = apdu.value + apdu.length;
    while (cursor < apdu_end)
    {
        Tlv field{};
        if (!read_tlv(cursor, apdu_end, &field))
            return false;
        if (field.tag == 0x80u)
        {
            if (!read_ber_uint(field.value, field.length, &fields.no_asdu))
                return false;
            have_count = true;
        }
        else if (field.tag == 0xa2u)
        {
            sequence = field.value;
            sequence_length = field.length;
        }
        cursor = field.next;
    }
    if (!have_count || fields.no_asdu == 0u || fields.no_asdu > 256u ||
        sequence == nullptr)
        return false;
    if (fields.no_asdu > kMaximumAsdus)
    {
        ++unsupported_sv_asdu;
        unsupported_parse = true;
        return false;
    }

    const std::uint8_t* seq_end = sequence + sequence_length;
    cursor = sequence;
    while (cursor < seq_end)
    {
        Tlv raw{};
        if (!read_tlv(cursor, seq_end, &raw) || raw.tag != 0x30u ||
            fields.asdu_count >= kMaximumAsdus)
            return false;
        SvFields::Asdu& asdu = fields.asdus[fields.asdu_count];
        bool have_id = false, have_cnt = false;
        const std::uint8_t* field_cursor = raw.value;
        const std::uint8_t* raw_end = raw.value + raw.length;
        while (field_cursor < raw_end)
        {
            Tlv f{};
            if (!read_tlv(field_cursor, raw_end, &f))
                return false;
            if (f.tag == 0x80u)
            {
                asdu.sv_id = f.value;
                asdu.sv_id_length = f.length;
                have_id = true;
            }
            else if (f.tag == 0x82u)
            {
                if (!read_ber_uint(f.value, f.length, &asdu.smp_cnt))
                    return false;
                have_cnt = true;
            }
            else if (f.tag == 0x83u)
            {
                if (!read_ber_uint(f.value, f.length, &asdu.conf_rev))
                    return false;
            }
            else if (f.tag == 0x85u)
            {
                if (!read_ber_uint(f.value, f.length, &asdu.smp_synch))
                    return false;
            }
            else if (f.tag == 0x87u)
            {
                asdu.seq_data = f.value;
                asdu.seq_data_length = f.length;
            }
            field_cursor = f.next;
        }
        if (!have_id || !have_cnt || asdu.seq_data == nullptr)
            return false;
        ++fields.asdu_count;
        cursor = raw.next;
    }
    if (fields.asdu_count != fields.no_asdu)
        return false;
    *output = fields;
    return true;
}

} // namespace
namespace
{
std::uint32_t batch_hash(std::uint16_t appid, const std::uint8_t* id,
                         std::size_t n, const std::uint8_t* dst)
{
    std::uint32_t h = 2166136261u;
    for (std::size_t i = 0; i < 6u; ++i)
    {
        h = (h ^ dst[i]) * 16777619u;
    }
    h = (h ^ static_cast<std::uint8_t>(appid >> 8u)) * 16777619u;
    h = (h ^ static_cast<std::uint8_t>(appid)) * 16777619u;
    for (std::size_t i = 0; i < n; ++i)
        h = (h ^ id[i]) * 16777619u;
    return h;
}
template <class S, std::size_t N>
S* batch_state(S (&bank)[N], std::uint16_t appid, const std::uint8_t* id,
               std::size_t n, const std::uint8_t* dst, std::uint32_t key)
{
    if (!id)
        return nullptr;
    if (n > kMaximumTrackedStreamIdLength)
    {
        ++unsupported_streams;
        return nullptr;
    }
    S* free = nullptr;
    for (auto& s : bank)
    {
        if (s.used && s.identity.appid == appid &&
            s.identity.stream_id_length == n &&
            !std::memcmp(s.identity.destination_mac, dst, 6u) &&
            (!n || !std::memcmp(s.identity.stream_id, id, n)))
            return &s;
        if (!s.used && !free)
            free = &s;
    }
    if (!free)
    {
        ++unsupported_streams;
        return nullptr;
    }
    *free = S{};
    free->used = true;
    free->key = key;
    free->identity.appid = appid;
    free->identity.stream_id_length = n;
    std::memcpy(free->identity.destination_mac, dst, 6u);
    if (n)
        std::memcpy(free->identity.stream_id, id, n);
    return free;
}
float batch_median(const float* v, std::size_t n)
{
    if (n > kWaveHistory)
        n = kWaveHistory;
    for (std::size_t i = 0; i < n; ++i)
        median_scratch[i] = v[i];
    if (!n)
        return 0.0f;
    const std::size_t middle = n / 2u;
    std::nth_element(median_scratch, median_scratch + middle,
                     median_scratch + n);
    if (n & 1u)
        return median_scratch[middle];
    const float upper = median_scratch[middle];
    const float lower =
        *std::max_element(median_scratch, median_scratch + middle);
    return (lower + upper) * 0.5f;
}
template <std::size_t N>
float ring_median(const float (&v)[N], std::size_t n, std::size_t next)
{
    for (std::size_t i = 0; i < n; ++i)
        timing_scratch[i] = v[(next + N - n + i) % N];
    return batch_median(timing_scratch, n);
}
void push_time(float (&a)[kTimingHistory], std::size_t& n, std::size_t& next,
               float x)
{
    a[next] = x;
    next = (next + 1u) % kTimingHistory;
    if (n < kTimingHistory)
        ++n;
}
template <std::size_t F, std::size_t D>
void predict_batch(float (&batch)[kBatchFrames][F], std::size_t& n,
                   const float* frame, AnalyzerResult* r, std::uint8_t& old,
                   bool& had, float threshold, float (*predict)(const float*))
{
    std::memcpy(batch[n++], frame, F * sizeof(float));
    if (n < kBatchFrames)
        return;
    float out[D]{};
    for (std::size_t f = 0; f < F; ++f)
    {
        float sum = 0, mx = batch[0][f];
        for (std::size_t j = 0; j < kBatchFrames; ++j)
        {
            sum += batch[j][f];
            mx = std::max(mx, batch[j][f]);
        }
        out[4u * f] = sum / static_cast<float>(kBatchFrames);
        out[4u * f + 1u] = mx;
        out[4u * f + 2u] = batch[kBatchFrames - 1u][f];
        float sq = 0;
        for (std::size_t j = 0; j < kBatchFrames; ++j)
        {
            float d = batch[j][f] - out[4u * f];
            sq += d * d;
        }
        out[4u * f + 3u] = std::sqrt(sq / static_cast<float>(kBatchFrames));
    }
    const float p = predict(out);
    std::memcpy(last_batch_features, out, D * sizeof(float));
    last_batch_feature_count = D;
    last_batch_protocol = r->protocol;
    const std::uint8_t label = p >= threshold;
    r->prediction_ready = true;
    r->primary_probability = p;
    r->primary_label = label;
    r->label_changed = !had || label != old;
    had = true;
    old = label;
    n -= kBatchStride;
    for (std::size_t i = 0; i < n; ++i)
        std::memcpy(batch[i], batch[i + kBatchStride], F * sizeof(float));
    (void)D;
}
float goose_predict(const float* x)
{
    return pico_ml_batch::predict_goose(x);
}
float sv_predict(const float* x)
{
    return pico_ml_batch::predict_sv(x);
}
void printable(char* out, std::size_t cap, const std::uint8_t* in,
               std::size_t n)
{
    if (!cap)
        return;
    std::size_t m = in ? std::min(n, cap - 1u) : 0;
    for (std::size_t i = 0; i < m; ++i)
        out[i] = (in[i] >= 32 && in[i] < 127) ? static_cast<char>(in[i]) : '.';
    out[m] = 0;
}
bool process_goose_batch(const std::uint8_t* src, const std::uint8_t* dst,
                         const GooseFields& f, std::uint64_t ts,
                         AnalyzerResult* r)
{
    const auto key = batch_hash(f.appid, f.gocb_ref, f.gocb_ref_length, dst);
    auto* s = batch_state(goose_states, f.appid, f.gocb_ref, f.gocb_ref_length,
                          dst, key);
    if (!s)
    {
        // Python's capture-wide age context observes every valid frame, even
        // when this bounded device cannot allocate a per-stream slot for it.
        if (!have_latest_goose || ts > latest_goose_us)
            latest_goose_us = ts;
        have_latest_goose = true;
        return false;
    }
    if (s->has_time && ts < s->timestamp_us)
    {
        ++malformed_frames;
        return false;
    }
    *r = AnalyzerResult{};
    r->protocol = AnalyzerProtocol::Goose;
    r->appid = f.appid;
    r->stream_key = key;
    r->counter_1 = f.st_num;
    r->counter_2 = f.sq_num;
    printable(r->goose_gocb_ref, sizeof(r->goose_gocb_ref), f.gocb_ref,
              f.gocb_ref_length);
    printable(r->goose_dataset, sizeof(r->goose_dataset), f.dataset,
              f.dataset_length);
    printable(r->goose_go_id, sizeof(r->goose_go_id), f.go_id, f.go_id_length);
    r->goose_ttl_ms = f.ttl_ms;
    r->goose_conf_rev = f.conf_rev;
    r->goose_num_entries = f.num_entries;
    r->goose_simulation = f.simulation;
    r->goose_nds_com = f.nds_com;
    const float dt =
        s->has_time ? static_cast<float>(ts - s->timestamp_us) * 1e-6f : 0.0f;
    const float prior =
        ring_median(s->previous_intervals, s->interval_count, s->interval_next);
    const float ratio = prior > 0 ? dt / prior : 1.0f;
    bool bvalid = false, b = false;
    if (f.all_data && f.all_data_length)
    {
        Tlv t{};
        if (read_tlv(f.all_data, f.all_data + f.all_data_length, &t) &&
            t.tag == 0x83u && t.length)
        {
            b = t.value[t.length - 1u] != 0;
            bvalid = true;
        }
    }
    const bool source_changed =
        s->has_source && std::memcmp(s->source, src, 6u) != 0;
    const std::int64_t sd =
        s->has_st ? static_cast<std::int64_t>(f.st_num) - s->st_num : 0;
    const std::int64_t qd =
        s->has_sq && f.st_num == s->st_num
            ? static_cast<std::int64_t>(f.sq_num) - s->sq_num
            : 0;
    const float age =
        have_latest_sv && ts >= latest_sv_us
            ? static_cast<float>(ts - latest_sv_us) * 1e-6f
            : (have_latest_sv ? 0.0f : pico_ml_batch::kTimingMissingAgeSeconds);
    const float x[13] = {dt,
                         ratio,
                         std::fabs(static_cast<float>(sd)),
                         float(sd < 0),
                         float(sd > pico_ml_batch::kCounterMaxStnumStep),
                         std::fabs(static_cast<float>(qd)),
                         float(qd < 0),
                         float(source_changed),
                         float(s->has_time && s->has_st),
                         age,
                         float(bvalid && b),
                         float(!bvalid),
                         float(s->has_boolean && bvalid && s->boolean != b)};
    if (s->has_time && dt > 0)
        push_time(s->previous_intervals, s->interval_count, s->interval_next,
                  dt);
    s->timestamp_us = ts;
    s->has_time = true;
    s->st_num = f.st_num;
    s->sq_num = f.sq_num;
    s->has_st = s->has_sq = true;
    std::memcpy(s->source, src, 6u);
    s->has_source = true;
    if (bvalid)
    {
        s->boolean = b;
        s->has_boolean = true;
    }
    latest_goose_us = ts;
    have_latest_goose = true;
    predict_batch<13, 52>(s->batch, s->batch_count, x, r, s->previous_label,
                          s->has_prediction, pico_ml_batch::kGooseThreshold,
                          goose_predict);
    r->feature_count = 8u;
    for (std::size_t i = 0; i < 8u; ++i)
        r->features[i] = x[i];
    return true;
}
void wave_push(float (&v)[kWaveHistory], std::uint16_t& n, std::uint16_t& next,
               float x)
{
    v[next] = x;
    next = static_cast<std::uint16_t>((next + 1u) % kWaveHistory);
    if (n < kWaveHistory)
        ++n;
}
bool process_sv_batch(const std::uint8_t* src, const std::uint8_t* dst,
                      const SvFields& f, std::uint64_t ts, AnalyzerResult* r)
{
    // Validate every ASDU before mutating counters or waveform histories.
    std::size_t required_length = 0u;
    for (std::size_t ch = 0; ch < pico_ml_batch::kSvChannelCount; ++ch)
        required_length = std::max(
            required_length,
            static_cast<std::size_t>(pico_ml_batch::kSvChannelOffsets[ch]) +
                4u);
    for (std::size_t i = 0; i < f.asdu_count; ++i)
    {
        const auto& asdu = f.asdus[i];
        if (asdu.seq_data_length < required_length)
        {
            ++malformed_frames;
            return false;
        }
        for (std::size_t ch = 0; ch < pico_ml_batch::kSvChannelCount; ++ch)
        {
            const std::size_t offset = pico_ml_batch::kSvChannelOffsets[ch];
            const std::uint32_t bits =
                (std::uint32_t(asdu.seq_data[offset]) << 24u) |
                (std::uint32_t(asdu.seq_data[offset + 1u]) << 16u) |
                (std::uint32_t(asdu.seq_data[offset + 2u]) << 8u) |
                asdu.seq_data[offset + 3u];
            float value;
            std::memcpy(&value, &bits, sizeof(value));
            if (!std::isfinite(value))
            {
                ++malformed_frames;
                return false;
            }
        }
    }
    const auto& a0 = f.asdus[0];
    const auto key = batch_hash(f.appid, a0.sv_id, a0.sv_id_length, dst);
    auto* s =
        batch_state(sv_states, f.appid, a0.sv_id, a0.sv_id_length, dst, key);
    if (!s)
    {
        // Keep capture-wide context consistent when the stream bank is full.
        if (!have_latest_sv || ts > latest_sv_us)
            latest_sv_us = ts;
        have_latest_sv = true;
        return false;
    }
    if (s->has_time && ts < s->timestamp_us)
    {
        ++malformed_frames;
        return false;
    }
    *r = AnalyzerResult{};
    r->protocol = AnalyzerProtocol::SampledValues;
    r->appid = f.appid;
    r->stream_key = key;
    r->counter_1 = a0.smp_cnt;
    const float dt =
        s->has_time ? static_cast<float>(ts - s->timestamp_us) * 1e-6f : 0.0f;
    const float prior =
        ring_median(s->previous_intervals, s->interval_count, s->interval_next);
    const float ratio = prior > 0 ? dt / prior : 1.0f;
    std::memset(sv_changes, 0, sizeof(sv_changes));
    std::memset(sv_channel_values, 0, sizeof(sv_channel_values));
    std::memset(sv_history_scratch, 0, sizeof(sv_history_scratch));
    unsigned back = 0, repeat = 0, gap = 0, jumps = 0, flat = 0, nvalue = 0;
    float delta_max = 0;
    std::size_t nc = 0;
    for (std::size_t i = 0; i < f.asdu_count; ++i)
    {
        const auto& a = f.asdus[i];
        if (s->has_counter[i])
        {
            const auto d =
                static_cast<std::int32_t>(a.smp_cnt - s->counters[i]);
            const float ad = std::fabs(static_cast<float>(d));
            delta_max = std::max(delta_max, ad);
            back += d < 0;
            repeat += d == 0;
            gap += ad > pico_ml_batch::kCounterMaxSmpDelta;
        }
        s->counters[i] = a.smp_cnt;
        s->has_counter[i] = true;
        for (std::size_t ch = 0; ch < pico_ml_batch::kSvChannelCount; ++ch)
        {
            const std::size_t off = pico_ml_batch::kSvChannelOffsets[ch];
            const std::uint32_t bits =
                (std::uint32_t(a.seq_data[off]) << 24u) |
                (std::uint32_t(a.seq_data[off + 1]) << 16u) |
                (std::uint32_t(a.seq_data[off + 2]) << 8u) |
                a.seq_data[off + 3];
            float cur;
            std::memcpy(&cur, &bits, 4);
            sv_channel_values[ch][i] = cur;
            const auto hn = s->wave_count[i][ch], next = s->wave_next[i][ch];
            if (hn)
            {
                for (std::size_t k = 0; k < hn; ++k)
                    sv_history_scratch[k] =
                        s->wave[i][ch]
                               [(next + kWaveHistory - hn + k) % kWaveHistory];
                const float base = batch_median(sv_history_scratch, hn);
                const float rel = std::fabs(cur - base) /
                                  std::max({std::fabs(base),
                                            pico_ml_batch::kSvRelativeScale[ch],
                                            pico_ml_batch::kWaveEpsilon});
                sv_changes[nc++] = rel;
                jumps += rel >= pico_ml_batch::kWaveRelativeJumpLimit;
                flat += rel <= pico_ml_batch::kWavePlateauRelativeLimit;
                ++nvalue;
            }
            wave_push(s->wave[i][ch], s->wave_count[i][ch], s->wave_next[i][ch],
                      cur);
        }
    }
    const auto previous_wave_count = s->wave_delta_count;
    for (std::size_t i = 0; i < s->wave_delta_count; ++i)
        sv_history_scratch[i] =
            s->wave_deltas[(s->wave_delta_next + kWaveHistory -
                            s->wave_delta_count + i) %
                           kWaveHistory];
    const float robust = batch_median(sv_history_scratch, s->wave_delta_count);
    float sum = 0, mx = 0;
    for (std::size_t i = 0; i < nc; ++i)
    {
        sum += sv_changes[i];
        mx = std::max(mx, sv_changes[i]);
        s->wave_deltas[s->wave_delta_next] = sv_changes[i];
        s->wave_delta_next = (s->wave_delta_next + 1u) % kWaveHistory;
        if (s->wave_delta_count < kWaveHistory)
            ++s->wave_delta_count;
    }
    float ranges[6]{};
    std::size_t nr = 0;
    for (std::size_t ch = 0; ch < pico_ml_batch::kSvChannelCount; ++ch)
    {
        float v[kMaximumAsdus]{};
        for (std::size_t i = 0; i < f.asdu_count; ++i)
            v[i] = sv_channel_values[ch][i];
        const float center = std::fabs(batch_median(v, f.asdu_count));
        float lo = v[0], hi = v[0];
        for (std::size_t i = 1; i < f.asdu_count; ++i)
        {
            lo = std::min(lo, v[i]);
            hi = std::max(hi, v[i]);
        }
        ranges[nr++] =
            (hi - lo) / std::max({center, pico_ml_batch::kSvRelativeScale[ch],
                                  pico_ml_batch::kWaveEpsilon});
    }
    float rsum = 0, rmax = 0;
    for (std::size_t i = 0; i < nr; ++i)
    {
        rsum += ranges[i];
        rmax = std::max(rmax, ranges[i]);
    }
    const float age =
        have_latest_goose && ts >= latest_goose_us
            ? static_cast<float>(ts - latest_goose_us) * 1e-6f
            : (have_latest_goose ? 0.0f
                                 : pico_ml_batch::kTimingMissingAgeSeconds);
    const float x[18] = {
        dt,
        ratio,
        age,
        float(f.no_asdu),
        float(back),
        float(repeat),
        float(gap),
        delta_max,
        nc ? sum / nc : 0.0f,
        mx,
        nvalue ? float(jumps) / nvalue : 0.0f,
        nvalue ? float(flat) / nvalue : 0.0f,
        float(jumps),
        std::min(1.0f, float(previous_wave_count) /
                           pico_ml_batch::kWaveHistoryMinSamples),
        std::min(pico_ml_batch::kWaveRobustRatioCap,
                 mx / std::max(robust, pico_ml_batch::kWaveEpsilon)),
        rsum / nr,
        rmax,
        float(s->has_source && std::memcmp(s->source, src, 6u) != 0)};
    if (s->has_time && dt > 0)
        push_time(s->previous_intervals, s->interval_count, s->interval_next,
                  dt);
    s->timestamp_us = ts;
    s->has_time = true;
    std::memcpy(s->source, src, 6u);
    s->has_source = true;
    latest_sv_us = ts;
    have_latest_sv = true;
    predict_batch<18, 72>(s->batch, s->batch_count, x, r, s->previous_label,
                          s->has_prediction, pico_ml_batch::kSvThreshold,
                          sv_predict);
    r->feature_count = 8u;
    for (std::size_t i = 0; i < 8u; ++i)
        r->features[i] = x[i];
    return true;
}
} // namespace
void analyzer_reset()
{
    std::memset(goose_states, 0, sizeof(goose_states));
    std::memset(sv_states, 0, sizeof(sv_states));
    latest_goose_us = latest_sv_us = 0;
    have_latest_goose = have_latest_sv = false;
    last_batch_feature_count = 0u;
}
void analyzer_get_diagnostics(AnalyzerDiagnostics* d)
{
    if (d)
    {
        d->unsupported_streams = unsupported_streams;
        d->unsupported_sv_asdu = unsupported_sv_asdu;
        d->malformed_frames = malformed_frames;
    }
}
bool analyzer_copy_last_batch_features(float* output, std::size_t capacity,
                                       std::size_t* count,
                                       AnalyzerProtocol* protocol)
{
    if (count)
        *count = last_batch_feature_count;
    if (protocol)
        *protocol = last_batch_protocol;
    if (!output || capacity < last_batch_feature_count ||
        last_batch_feature_count == 0u)
        return false;
    std::memcpy(output, last_batch_features,
                last_batch_feature_count * sizeof(float));
    return true;
}
bool analyzer_process_ethernet_frame(const std::uint8_t* frame,
                                     std::size_t length, std::uint64_t ts,
                                     AnalyzerResult* r)
{
    if (!frame || !r || length < 14u)
    {
        ++malformed_frames;
        return false;
    }
    EthernetPayload p{};
    if (!find_ethernet_payload(frame, length, &p))
    {
        ++malformed_frames;
        return false;
    }
    const auto* src = frame + 6u;
    const auto* dst = frame;
    if (p.type == kGooseEtherType)
    {
        GooseFields f{};
        if (!parse_goose(p, &f))
        {
            ++malformed_frames;
            return false;
        }
        return process_goose_batch(src, dst, f, ts, r);
    }
    if (p.type == kSvEtherType)
    {
        SvFields f{};
        if (!parse_sv(p, &f))
        {
            if (!unsupported_parse)
                ++malformed_frames;
            unsupported_parse = false;
            return false;
        }
        return process_sv_batch(src, dst, f, ts, r);
    }
    return false;
}
