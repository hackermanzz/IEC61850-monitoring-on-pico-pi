/** @file capture_test.c
 * @brief Match test identities instead of counting unrelated background frames.
 */
#include "capture_test.h"

#include <string.h> /* Bounded copies/comparisons, used only by Core 0. */

#define TEST_ETH_HEADER    14u
#define TEST_IP_MIN_HEADER 20u
#define TEST_UDP_HEADER    8u
#define TEST_MARKER_HEADER 20u

typedef struct
{
    const uint8_t * p_mac;
    const uint8_t * p_ip;
    const uint8_t * p_payload;
    size_t          payload_length;
    uint32_t        run_id;
    uint32_t        sequence;
    uint32_t        expected;
} test_packet_t;

static uint16_t capture_test_read16(const uint8_t * p_bytes);
static uint32_t capture_test_read32(const uint8_t * p_bytes);
static bool     capture_test_parse(const uint8_t * p_data, size_t length,
                                   test_packet_t * p_packet);
static bool     capture_test_valid(const test_packet_t * p_packet);
static capture_test_run_t *
capture_test_find(capture_test_tracker_t * p_tracker,
                  const test_packet_t *    p_packet);

static uint16_t
capture_test_read16 (const uint8_t * p_bytes)
{
    return (uint16_t) (((uint16_t) p_bytes[0] << 8u) | p_bytes[1]);
}

static uint32_t
capture_test_read32 (const uint8_t * p_bytes)
{
    return ((uint32_t) p_bytes[0] << 24u) | ((uint32_t) p_bytes[1] << 16u)
         | ((uint32_t) p_bytes[2] << 8u) | p_bytes[3];
}

/** @brief Find a safely bounded, unfragmented IPv4/UDP test candidate. */
static bool
capture_test_parse (const uint8_t * p_data, size_t length,
                    test_packet_t * p_packet)
{
    size_t          offset     = TEST_ETH_HEADER;
    size_t          tags       = 0u;
    size_t          ip_header  = 0u;
    size_t          ip_total   = 0u;
    size_t          udp_length = 0u;
    uint16_t        type       = 0u;
    const uint8_t * p_ip       = NULL;
    const uint8_t * p_udp      = NULL;

    if ((NULL == p_data) || (TEST_ETH_HEADER > length))
    {
        return false;
    }
    type = capture_test_read16(p_data + 12u);
    while (((0x8100u == type) || (0x88a8u == type)) && (2u > tags))
    {
        if (length - offset < 4u)
        {
            return false;
        }
        type = capture_test_read16(p_data + offset + 2u);
        offset += 4u;
        tags++;
    }
    if ((0x0800u != type) || (length - offset < TEST_IP_MIN_HEADER))
    {
        return false;
    }
    p_ip      = p_data + offset;
    ip_header = (p_ip[0] & 15u) * 4u;
    ip_total  = capture_test_read16(p_ip + 2u);
    if ((4u != (p_ip[0] >> 4u)) || (TEST_IP_MIN_HEADER > ip_header)
        || (ip_total > length - offset)
        || (ip_total < ip_header + TEST_UDP_HEADER) || (17u != p_ip[9])
        || (0u != (capture_test_read16(p_ip + 6u) & 0xbfffu)))
    {
        return false;
    }
    p_udp      = p_ip + ip_header;
    udp_length = capture_test_read16(p_udp + 4u);
    if ((49153u != capture_test_read16(p_udp))
        || (49152u != capture_test_read16(p_udp + 2u))
        || (ip_total - ip_header != udp_length)
        || (TEST_UDP_HEADER + TEST_MARKER_HEADER > udp_length)
        || (0 != memcmp(p_udp + TEST_UDP_HEADER, "P2RXTEST", 8u)))
    {
        return false;
    }
    p_packet->p_mac          = p_data + 6u;
    p_packet->p_ip           = p_ip + 12u;
    p_packet->p_payload      = p_udp + TEST_UDP_HEADER;
    p_packet->payload_length = udp_length - TEST_UDP_HEADER;
    p_packet->run_id         = capture_test_read32(p_packet->p_payload + 8u);
    p_packet->sequence       = capture_test_read32(p_packet->p_payload + 12u);
    p_packet->expected       = capture_test_read32(p_packet->p_payload + 16u);
    return true;
}

static bool
capture_test_valid (const test_packet_t * p_packet)
{
    size_t index = TEST_MARKER_HEADER;

    if ((0u == p_packet->expected)
        || (CAPTURE_TEST_MAX_PACKETS < p_packet->expected)
        || (p_packet->sequence >= p_packet->expected)
        || (64u > p_packet->payload_length)
        || (1400u < p_packet->payload_length))
    {
        return false;
    }
    for (index = TEST_MARKER_HEADER; p_packet->payload_length > index; index++)
    {
        if ((uint8_t) (p_packet->sequence + index - TEST_MARKER_HEADER)
            != p_packet->p_payload[index])
        {
            return false;
        }
    }
    return true;
}

static capture_test_run_t *
capture_test_find (capture_test_tracker_t * p_tracker,
                   const test_packet_t *    p_packet)
{
    uint32_t             index = 0u;
    capture_test_run_t * p_run = NULL;

    for (index = 0u; CAPTURE_TEST_RUNS > index; index++)
    {
        p_run = &p_tracker->runs[index];
        if (p_run->b_used && (p_run->run_id == p_packet->run_id)
            && (0 == memcmp(p_run->source_mac, p_packet->p_mac, 6u))
            && (0 == memcmp(p_run->source_ip, p_packet->p_ip, 4u)))
        {
            return p_run;
        }
    }
    return NULL;
}

void
capture_test_init (capture_test_tracker_t * p_tracker)
{
    if (NULL != p_tracker)
    {
        memset(p_tracker, 0, sizeof(*p_tracker));
    }
}

capture_test_result_t
capture_test_observe (capture_test_tracker_t * p_tracker,
                      const uint8_t * p_data, size_t length)
{
    test_packet_t        packet = {0};
    capture_test_run_t * p_run  = NULL;
    uint32_t             index  = 0u;
    uint8_t              mask   = 0u;

    if ((NULL == p_tracker) || (!capture_test_parse(p_data, length, &packet)))
    {
        return CAPTURE_TEST_BACKGROUND;
    }
    if (!capture_test_valid(&packet))
    {
        p_tracker->rejected++;
        return CAPTURE_TEST_REJECTED;
    }
    p_run = capture_test_find(p_tracker, &packet);
    if (NULL == p_run)
    {
        for (index = 0u; CAPTURE_TEST_RUNS > index; index++)
        {
            if (!p_tracker->runs[index].b_used)
            {
                p_run = &p_tracker->runs[index];
                break;
            }
        }
        if (NULL == p_run)
        {
            p_tracker->run_capacity_drops++;
            return CAPTURE_TEST_CAPACITY;
        }
        p_run->b_used        = true;
        p_run->run_id        = packet.run_id;
        p_run->expected      = packet.expected;
        p_run->payload_bytes = (uint16_t) packet.payload_length;
        memcpy(p_run->source_mac, packet.p_mac, 6u);
        memcpy(p_run->source_ip, packet.p_ip, 4u);
    }
    if ((p_run->expected != packet.expected)
        || (p_run->payload_bytes != packet.payload_length))
    {
        p_run->conflicts++;
        p_tracker->rejected++;
        return CAPTURE_TEST_REJECTED;
    }
    mask = (uint8_t) (1u << (packet.sequence & 7u));
    if (0u != (p_run->seen[packet.sequence / 8u] & mask))
    {
        p_run->duplicates++;
        return CAPTURE_TEST_DUPLICATE;
    }
    p_run->seen[packet.sequence / 8u] |= mask;
    if ((0u < p_run->unique) && (p_run->highest_sequence > packet.sequence))
    {
        p_run->reordered++;
    }
    if (packet.sequence > p_run->highest_sequence)
    {
        p_run->highest_sequence = packet.sequence;
    }
    p_run->unique++;
    return CAPTURE_TEST_UNIQUE;
}

/*** end of file ***/
