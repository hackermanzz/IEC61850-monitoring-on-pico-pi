#include "incident.h"

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#define TEST_FRAME_LENGTH (64u)
#define TEST_SEQUENCE_BASE (100u)
#define TEST_STEP_US (100000u)
#define TEST_GATE (0.65f)

static uint8_t g_frames[2][ANALYZER_BATCH_FRAME_COUNT][TEST_FRAME_LENGTH];
static const uint8_t * g_frame_pointers[ANALYZER_BATCH_FRAME_COUNT];
static size_t          g_frame_lengths[ANALYZER_BATCH_FRAME_COUNT];

static analyzer_result_t
make_result (analyzer_protocol_t protocol, float score, uint64_t end_us,
             uint32_t sequence_base)
{
    analyzer_result_t result = {0};
    size_t            index  = 0u;

    result.protocol   = protocol;
    result.stream_key = protocol == ANALYZER_PROTOCOL_GOOSE ? 11u : 22u;
    result.appid      = protocol == ANALYZER_PROTOCOL_GOOSE ? 0x1001u : 0x4001u;
    result.timestamp_us        = end_us;
    result.prediction_ready    = true;
    result.primary_probability = score;
    result.batch_frame_count   = ANALYZER_BATCH_FRAME_COUNT;
    for (index = 0u; index < ANALYZER_BATCH_FRAME_COUNT; ++index)
    {
        analyzer_packet_metadata_t * packet     = &result.batch_packets[index];
        size_t                       byte_index = 0u;
        packet->timestamp_us =
            end_us - (ANALYZER_BATCH_FRAME_COUNT - 1u - index) * TEST_STEP_US;
        packet->capture_sequence   = sequence_base + (uint32_t) index;
        packet->protocol           = protocol;
        packet->stream_key         = result.stream_key;
        packet->appid              = result.appid;
        packet->counter_1          = sequence_base + (uint32_t) index;
        packet->frame_length       = TEST_FRAME_LENGTH;
        packet->source_mac[5]      = (uint8_t) protocol;
        packet->destination_mac[5] = 0xaau;
        for (byte_index = 0u; byte_index < TEST_FRAME_LENGTH; ++byte_index)
        {
            g_frames[protocol][index][byte_index] =
                (uint8_t) (sequence_base + (uint32_t) index + byte_index);
        }
        g_frame_pointers[index] = g_frames[protocol][index];
        g_frame_lengths[index]  = TEST_FRAME_LENGTH;
    }
    return result;
}

static void
submit (analyzer_result_t * result)
{
    incident_observe_prediction(result, g_frame_pointers, g_frame_lengths);
}

static void
open_pair (uint64_t time_us, uint32_t sequence)
{
    analyzer_result_t goose =
        make_result(ANALYZER_PROTOCOL_GOOSE, TEST_GATE, time_us, sequence);
    submit(&goose);
    analyzer_result_t sv =
        make_result(ANALYZER_PROTOCOL_SAMPLED_VALUES, TEST_GATE,
                    time_us + TEST_STEP_US, sequence + 10u);
    submit(&sv);
}

static void
open_pair_with_shared_packets (uint64_t time_us, uint64_t packet_time_us,
                               uint32_t sequence)
{
    analyzer_result_t goose =
        make_result(ANALYZER_PROTOCOL_GOOSE, TEST_GATE, time_us, sequence);
    size_t index = 0u;
    for (index = 0u; index < ANALYZER_BATCH_FRAME_COUNT; ++index)
    {
        goose.batch_packets[index].timestamp_us =
            packet_time_us -
            (ANALYZER_BATCH_FRAME_COUNT - 1u - index) * TEST_STEP_US;
    }
    submit(&goose);
    {
        analyzer_result_t sv =
            make_result(ANALYZER_PROTOCOL_SAMPLED_VALUES, TEST_GATE,
                        time_us + TEST_STEP_US, sequence + 10u);
        for (index = 0u; index < ANALYZER_BATCH_FRAME_COUNT; ++index)
        {
            sv.batch_packets[index].timestamp_us =
                packet_time_us + TEST_STEP_US -
                (ANALYZER_BATCH_FRAME_COUNT - 1u - index) * TEST_STEP_US;
        }
        submit(&sv);
    }
}

static size_t
active_index (void)
{
    incident_status_t         status = {0};
    incident_container_info_t info   = {0};
    size_t                    index  = 0u;

    incident_get_status(&status);
    for (index = 0u; index < INCIDENT_MAXIMUM_CONTAINERS; ++index)
    {
        if (incident_peek(index, &info) && !info.complete &&
            info.id == status.active_container_id_wide)
        {
            return index;
        }
    }
    return INCIDENT_MAXIMUM_CONTAINERS;
}

static void
test_consensus_and_evidence (void)
{
    incident_container_info_t  info                                 = {0};
    incident_batch_summary_t   batch                                = {0};
    incident_packet_metadata_t metadata                             = {0};
    uint8_t                    frame[INCIDENT_MAXIMUM_FRAME_LENGTH] = {0};
    size_t                     index                                = 0u;
    const size_t               container_index                      = 0u;

    incident_initialize(0x12345678u);
    open_pair(1000000u, TEST_SEQUENCE_BASE);
    {
        analyzer_result_t duplicate = make_result(
            ANALYZER_PROTOCOL_GOOSE, TEST_GATE, 1000000u, TEST_SEQUENCE_BASE);
        submit(&duplicate);
    }
    assert(active_index() == container_index);
    assert(incident_peek(container_index, &info));
    assert(info.goose_score == TEST_GATE && info.sv_score == TEST_GATE);
    assert(info.batch_count == 2u && info.packet_count == 8u);
    assert(!incident_acknowledge(container_index, info.id));
    assert(incident_read_batch(container_index, 0u, &batch));
    assert(batch.protocol == ANALYZER_PROTOCOL_GOOSE);
    assert(batch.packets[3].capture_sequence == TEST_SEQUENCE_BASE + 3u);
    assert(!incident_read_batch(container_index, info.batch_count, &batch));
    for (index = 0u; index < INCIDENT_MAXIMUM_PACKETS; ++index)
    {
        size_t        byte_index = 0u;
        const uint8_t expected_sequence =
            (uint8_t) (index < 4u ? TEST_SEQUENCE_BASE + (uint32_t) index
                                  : TEST_SEQUENCE_BASE + 10u +
                                        (uint32_t) (index - 4u));
        assert(incident_read_packet(container_index, index, &metadata, frame,
                                    sizeof(frame)));
        assert(metadata.capture_sequence ==
               (index < 4u
                    ? TEST_SEQUENCE_BASE + (uint32_t) index
                    : TEST_SEQUENCE_BASE + 10u + (uint32_t) (index - 4u)));
        assert(frame[0] == (uint8_t) metadata.capture_sequence);
        for (byte_index = 0u; byte_index < TEST_FRAME_LENGTH; ++byte_index)
        {
            assert(frame[byte_index] ==
                   (uint8_t) (expected_sequence + (uint8_t) byte_index));
        }
    }
    assert(!incident_read_packet(container_index, info.packet_count, &metadata,
                                 frame, sizeof(frame)));
    assert(!incident_read_packet(container_index, 0u, &metadata, frame,
                                 TEST_FRAME_LENGTH - 1u));
    {
        analyzer_result_t safe = make_result(ANALYZER_PROTOCOL_GOOSE, 0.649f,
                                             1000000u, TEST_SEQUENCE_BASE);
        submit(&safe);
    }
    assert(incident_peek(container_index, &info));
    assert(info.complete &&
           info.closure_reason == INCIDENT_CLOSURE_SAFE_PREDICTION);
    assert(!incident_acknowledge(container_index, info.id + 1u));
    assert(incident_peek(container_index, &info) && info.complete);
    assert(incident_read_batch(container_index, 0u, &batch));
    assert(incident_read_packet(container_index, 0u, &metadata, frame,
                                sizeof(frame)));
    assert(metadata.capture_sequence == TEST_SEQUENCE_BASE);
    assert(incident_acknowledge(container_index, info.id));
}

static void
test_stale_gap_invalid_and_single_model (void)
{
    incident_container_info_t info = {0};
    analyzer_result_t         result;
    size_t                    index = 0u;

    incident_initialize(7u);
    result = make_result(ANALYZER_PROTOCOL_GOOSE, 0.9f, 1000000u, 100u);
    submit(&result);
    assert(active_index() == INCIDENT_MAXIMUM_CONTAINERS);
    submit(&(analyzer_result_t){0});
    open_pair(2000000u, 200u);
    index = active_index();
    incident_check_stale(3000001u + TEST_STEP_US);
    assert(incident_peek(index, &info));
    assert(info.complete &&
           info.closure_reason == INCIDENT_CLOSURE_STALE_SCORE);

    incident_initialize(8u);
    open_pair(4000000u, 300u);
    index = active_index();
    incident_capture_gap(5000000u);
    assert(incident_peek(index, &info));
    assert(info.complete &&
           info.closure_reason == INCIDENT_CLOSURE_CAPTURE_GAP);

    incident_initialize(9u);
    open_pair(6000000u, 400u);
    index  = active_index();
    result = make_result(ANALYZER_PROTOCOL_SAMPLED_VALUES, NAN, 6500000u, 500u);
    submit(&result);
    assert(incident_peek(index, &info));
    assert(info.complete &&
           info.closure_reason == INCIDENT_CLOSURE_INVALID_SCORE);
}

static void
test_shared_packet_references_and_limits (void)
{
    incident_container_info_t  first    = {0};
    incident_container_info_t  second   = {0};
    incident_container_info_t  info     = {0};
    incident_status_t          status   = {0};
    incident_packet_metadata_t metadata = {0};
    analyzer_result_t          result;
    uint8_t                    frame[INCIDENT_MAXIMUM_FRAME_LENGTH] = {0};
    size_t                     first_index                          = 0u;
    size_t                     second_index                         = 0u;
    size_t                     index                                = 0u;

    incident_initialize(10u);
    open_pair(1000000u, 700u);
    first_index = active_index();
    assert(incident_peek(first_index, &first));
    result = make_result(ANALYZER_PROTOCOL_GOOSE, 0.64f, 1600000u, 800u);
    submit(&result);
    open_pair_with_shared_packets(2000000u, 1000000u, 700u);
    second_index = active_index();
    assert(second_index != first_index);
    assert(incident_peek(second_index, &second));
    assert(incident_acknowledge(first_index, first.id));
    assert(incident_read_packet(second_index, 0u, &metadata, frame,
                                sizeof(frame)));
    assert(metadata.capture_sequence == 700u);

    result = make_result(ANALYZER_PROTOCOL_GOOSE, 0.64f, 2600000u, 900u);
    submit(&result);
    open_pair(3000000u, 1000u);
    result =
        make_result(ANALYZER_PROTOCOL_SAMPLED_VALUES, 0.9f, 3100000u, 1100u);
    submit(&result);
    result = make_result(ANALYZER_PROTOCOL_GOOSE, 0.9f, 3200000u, 1200u);
    submit(&result);
    result =
        make_result(ANALYZER_PROTOCOL_SAMPLED_VALUES, 0.9f, 3300000u, 1300u);
    submit(&result);
    result = make_result(ANALYZER_PROTOCOL_GOOSE, 0.9f, 3400000u, 1400u);
    submit(&result);
    result =
        make_result(ANALYZER_PROTOCOL_SAMPLED_VALUES, 0.9f, 3500000u, 1500u);
    submit(&result);
    result = make_result(ANALYZER_PROTOCOL_GOOSE, 0.9f, 3600000u, 1600u);
    submit(&result);
    result =
        make_result(ANALYZER_PROTOCOL_SAMPLED_VALUES, 0.9f, 3700000u, 1700u);
    submit(&result);
    result = make_result(ANALYZER_PROTOCOL_GOOSE, 0.9f, 3800000u, 1800u);
    submit(&result);
    second_index = active_index();
    assert(incident_peek(second_index, &info));
    assert(info.batch_count == INCIDENT_MAXIMUM_BATCHES_PER_CONTAINER);
    assert(info.lost_batches > 0u && info.truncated);
    incident_capture_gap(3900000u);

    for (index = 0u; index < INCIDENT_MAXIMUM_CONTAINERS - 1u; ++index)
    {
        const uint32_t sequence = 2000u + (uint32_t) index * 20u;
        open_pair(5000000u + index * 2000000u, sequence);
        result = make_result(ANALYZER_PROTOCOL_GOOSE, 0.6f,
                             5100000u + index * 2000000u, sequence + 10u);
        submit(&result);
    }
    incident_get_status(&status);
    assert(status.lost_containers > 0u);
    assert(status.lost_packets > 0u);
}

int
main (void)
{
    test_consensus_and_evidence();
    test_stale_gap_invalid_and_single_model();
    test_shared_packet_references_and_limits();
    return 0;
}
