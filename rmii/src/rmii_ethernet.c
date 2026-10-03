/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rmii_ethernet.h"

#include <string.h>

#include "hardware/dma.h"
#include "hardware/sync.h"

#include "pico/critical_section.h"
#include "pico/stdlib.h"
#include "pico/unique_id.h"

#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"

#include "rmii_ethernet_phy_rx.pio.h"
#include "rmii_ethernet_phy_tx.pio.h"

enum
{
    ETHERNET_MIN_FRAME_SIZE             = 60U,
    ETHERNET_HEADER_SIZE                = 14U,
    ETHERNET_MAC_ADDRESS_LENGTH         = 6U,
    ETHERNET_FCS_OCTET_OFFSET_2         = 2U,
    ETHERNET_FCS_OCTET_OFFSET_3         = 3U,
    ETHERNET_MTU_SIZE                   = 1500U,
    ETHERNET_MAC_OUI_LAST_OFFSET        = 2U,
    ETHERNET_UNIQUE_ID_START_OFFSET     = 5U,
    RMII_RX_SAMPLE_WORD_COUNT           = 3900U,
    RMII_SAMPLES_PER_WORD               = 16U,
    RMII_SAMPLE_WORD_SHIFT              = 4U,
    RMII_SAMPLE_WORD_INDEX_MASK         = 15U,
    RMII_DIBIT_WIDTH_BITS               = 2U,
    RMII_DIBITS_PER_BYTE                = 4U,
    RMII_BITS_PER_OCTET                 = 8U,
    RMII_DIBIT_VALUE_MASK               = 3U,
    RMII_CAPTURE_END_SENTINEL           = 255U,
    RMII_CYCLES_PER_DIBIT               = 10U,
    RMII_DIBIT_ROUNDING_BIAS            = 5U,
    RMII_PREAMBLE_DIBIT_COUNT           = 31U,
    RMII_PIO_DATA_SYMBOL                = 4U,
    RMII_PIO_PREAMBLE_SYMBOL            = 5U,
    RMII_PIO_SFD_SYMBOL                 = 7U,
    RMII_DIBIT_STATE_SFD                = 3U,
    RMII_CRC_SECOND_OCTET_SHIFT         = 8U,
    RMII_CRC_THIRD_OCTET_SHIFT          = 16U,
    RMII_CRC_FOURTH_OCTET_SHIFT         = 24U,
    RMII_CRS_DV_PIN_OFFSET              = 2U,
    RMII_PIO_TX_FIFO_BYTE_OFFSET        = 3U,
    RMII_RECEIVE_PIN_COUNT              = 3U,
    RMII_MDIO_PIN_COUNT                 = 2U,
    MDIO_PREAMBLE_BIT_COUNT             = 32U,
    MDIO_ADDRESS_FIELD_BIT_COUNT        = 5U,
    MDIO_REGISTER_FIELD_BIT_COUNT       = 5U,
    MDIO_DATA_FIELD_BIT_COUNT           = 16U,
    MDIO_PHY_ADDRESS_COUNT              = 32U,
    MDIO_PHY_ID1_REGISTER               = 2U,
    MDIO_PHY_ID2_REGISTER               = 3U,
    MDIO_PHY_CONTROL_REGISTER           = 0U,
    MDIO_PHY_STATUS_REGISTER            = 1U,
    MDIO_PHY_ADVERTISEMENT_REGISTER     = 4U,
    MDIO_VENDOR_STATUS_REGISTER         = 31U,
    PHY_STATUS_LINK_BIT                 = 4U,
    PHY_STATUS_LINK_MASK                = 4U,
    RMII_RECEIVE_READY_WORD_COUNT       = 4U,
    RMII_SAMPLE_WORDS_PER_CAPTURE       = 4U,
    ETHERNET_LINK_POLL_INTERVAL_MS      = 100U,
    ETHERNET_PHY_DIAGNOSTIC_INTERVAL_MS = 2000U,
};

#define ETHERNET_CRC_INITIAL_VALUE UINT32_MAX
#define ETHERNET_CRC_OCTET_MASK UINT8_MAX
#define ETHERNET_PHY_ID_UNDRIVEN_VALUE UINT16_MAX
#define ETHERNET_MAC_OUI_BYTE_0 0xb8U
#define ETHERNET_MAC_OUI_BYTE_1 0x27U
#define ETHERNET_MAC_OUI_BYTE_2 0xebU
#define ETHERNET_PHY_AUTONEGOTIATION_ADVERTISEMENT 0x61U
#define ETHERNET_PHY_AUTONEGOTIATION_RESTART 0x1200U

#define ETHERNET_FRAME_MAX_SIZE 1518U
#define ETHERNET_PREAMBLE_SIZE 8U
#define ETHERNET_FCS_SIZE 4U
#define ETHERNET_IFG_SIZE 12U
#define ETHERNET_TX_BUFFER_SIZE                                                \
    ((ETHERNET_FRAME_MAX_SIZE + ETHERNET_PREAMBLE_SIZE + ETHERNET_FCS_SIZE +   \
      ETHERNET_IFG_SIZE) *                                                     \
     4U)

#define PICO_RMII_ETHERNET_PIO (g_rmii_eth_netif_config.pio)
#define PICO_RMII_ETHERNET_SM_RX (g_rmii_eth_netif_config.pio_sm_start)
#define PICO_RMII_ETHERNET_SM_TX (g_rmii_eth_netif_config.pio_sm_start + 1)
#define PICO_RMII_ETHERNET_RX_PIN (g_rmii_eth_netif_config.rx_pin_start)
#define PICO_RMII_ETHERNET_TX_PIN (g_rmii_eth_netif_config.tx_pin_start)
#define PICO_RMII_ETHERNET_MDIO_PIN (g_rmii_eth_netif_config.mdio_pin_start)
#define PICO_RMII_ETHERNET_MDC_PIN (g_rmii_eth_netif_config.mdio_pin_start + 1)
#define PICO_RMII_ETHERNET_MAC_ADDR (g_rmii_eth_netif_config.mac_addr)

static struct netif *         gp_rmii_eth_netif;
static err_t                  g_rmii_init_error = ERR_IF;
static rmii_ethernet_config_t g_rmii_eth_netif_config =
    NETIF_RMII_ETHERNET_DEFAULT_CONFIG();

static uint g_rx_sm_offset;
static uint g_tx_sm_offset;

static int g_rx_dma_chan = -1;
static int g_tx_dma_chan = -1;

static dma_channel_config g_rx_dma_channel_config;
static dma_channel_config g_tx_dma_channel_config;

static int g_phy_address = 0;

// debug counters, read with netif_rmii_ethernet_get_stats()
static volatile uint32_t g_stat_tx_frames;
static volatile uint32_t g_stat_rx_frames;
static volatile uint32_t g_stat_rx_bad_crc;
static volatile uint16_t g_stat_phy_status;
// most recent good frame, copied out for the frame printer on core0
static uint8_t            g_stat_good_frame[ETHERNET_FRAME_MAX_SIZE];
static uint16_t           g_stat_good_frame_len;
static uint32_t           g_stat_good_frame_seq;
static uint8_t            g_stat_good_frame_snapshot[ETHERNET_FRAME_MAX_SIZE];
static critical_section_t g_frame_snapshot_lock;
static bool               g_frame_snapshot_lock_initialized;

// Single-producer (RMII core) / single-consumer (analysis core) queue. Eight
// full Ethernet frames require about 12 KiB of SRAM. When inference cannot keep
// up, new frames are counted and dropped instead of silently overwriting the
// only frame visible to the analyzer.
#define CAPTURE_QUEUE_CAPACITY 8U
#define CAPTURE_QUEUE_SLOT_COUNT (CAPTURE_QUEUE_CAPACITY + 1U)
typedef struct
{
    uint8_t  data[ETHERNET_FRAME_MAX_SIZE];
    uint16_t len;
    uint32_t seq;
    uint64_t timestamp_us;
} captured_frame_t;

static captured_frame_t  g_capture_queue[CAPTURE_QUEUE_SLOT_COUNT];
static volatile uint32_t g_capture_queue_head;
static volatile uint32_t g_capture_queue_tail;
static volatile uint32_t g_capture_queue_dropped;

static void
capture_queue_push (const uint8_t * frame, uint16_t len, uint32_t seq,
                    uint64_t timestamp_us)
{
    uint32_t head = g_capture_queue_head;
    uint32_t next = (head + 1U) % CAPTURE_QUEUE_SLOT_COUNT;

    if (next == g_capture_queue_tail)
    {
        g_capture_queue_dropped++;
        return;
    }

    captured_frame_t * slot = &g_capture_queue[head];
    memcpy(slot->data, frame, len);
    slot->len          = len;
    slot->seq          = seq;
    slot->timestamp_us = timestamp_us;
    __dmb();
    g_capture_queue_head = next;
}

// raw 50 MHz capture of RXD0/RXD1, 16 samples per word, 62400 samples is
// 1.25 ms which covers a maximum size frame at 10 Mbps
static uint32_t g_rx_samples[RMII_RX_SAMPLE_WORD_COUNT];

static uint8_t       g_rx_frame[ETHERNET_FRAME_MAX_SIZE];
static uint8_t       g_tx_frame[ETHERNET_FRAME_MAX_SIZE];
static uint8_t       g_tx_frame_bits[ETHERNET_TX_BUFFER_SIZE];
static uint64_t      g_rx_frame_timestamp_us;
static volatile bool g_rx_frame_completed;

static const uint32_t g_ethernet_polynomial_le = 0xedb88320U;

static bool
rmii_pin_ranges_overlap (uint first_start, uint first_count, uint second_start,
                         uint second_count)
{
    uint first_end  = first_start + first_count;
    uint second_end = second_start + second_count;

    return (first_start < second_end) && (second_start < first_end);
}

static uint32_t
ethernet_frame_crc (const uint8_t * data, size_t length)
{
    uint32_t crc = ETHERNET_CRC_INITIAL_VALUE;

    for (size_t index = 0U; index < length; index++)
    {
        uint8_t current_octet = data[index];

        for (uint8_t bit = 0U; bit < RMII_BITS_PER_OCTET; bit++)
        {
            if (((crc ^ current_octet) & 1U) != 0U)
            {
                crc >>= 1;
                crc ^= g_ethernet_polynomial_le;
            }
            else
            {
                crc >>= 1;
            }
            current_octet >>= 1;
        }
    }

    return ~crc;
}

static size_t
ethernet_frame_length (const uint8_t * data, size_t length)
{
    uint32_t crc = ETHERNET_CRC_INITIAL_VALUE;

    for (size_t index = 0U; index < length; index++)
    {
        uint8_t current_octet = data[index];

        for (uint8_t bit = 0U; bit < RMII_BITS_PER_OCTET; bit++)
        {
            if (((crc ^ current_octet) & 1U) != 0U)
            {
                crc >>= 1;
                crc ^= g_ethernet_polynomial_le;
            }
            else
            {
                crc >>= 1;
            }
            current_octet >>= 1;
        }

        size_t remaining_length = length - index - 1U;
        if (remaining_length >= ETHERNET_FCS_SIZE)
        {
            uint32_t        inverted_crc = ~crc;
            const uint8_t * fcs          = &data[index + 1U];

            if ((fcs[0] ==
                 (uint8_t) (inverted_crc & ETHERNET_CRC_OCTET_MASK)) &&
                (fcs[1] ==
                 (uint8_t) ((inverted_crc >> RMII_CRC_SECOND_OCTET_SHIFT) &
                            ETHERNET_CRC_OCTET_MASK)) &&
                (fcs[ETHERNET_FCS_OCTET_OFFSET_2] ==
                 (uint8_t) ((inverted_crc >> RMII_CRC_THIRD_OCTET_SHIFT) &
                            ETHERNET_CRC_OCTET_MASK)) &&
                (fcs[ETHERNET_FCS_OCTET_OFFSET_3] ==
                 (uint8_t) ((inverted_crc >> RMII_CRC_FOURTH_OCTET_SHIFT) &
                            ETHERNET_CRC_OCTET_MASK)))
            {
                return index + 1U;
            }
        }
    }

    return 0;
}

// Recovers dibits from the oversampled capture. Each dibit is held for about
// ten cycles, so a run of constant data of length L is round(L / 10) dibits.
// Rounding per run means the 9 cycle runs the PHY produces do not accumulate
// into a lost dibit the way a fixed cadence sampler does.
static uint
rmii_decode_samples (const uint32_t * samples, uint words, uint8_t * out,
                     uint out_size)
{
    uint    total    = words * RMII_SAMPLES_PER_WORD;
    uint    prev     = samples[0] & RMII_DIBIT_VALUE_MASK;
    uint    run      = 0;
    bool    in_frame = false;
    uint    out_len  = 0;
    uint    dibits   = 0;
    uint8_t byte     = 0;

    for (uint i = 0; i <= total; i++)
    {
        // one past the end flushes the final run
        uint v = (i < total) ? ((samples[i >> RMII_SAMPLE_WORD_SHIFT] >>
                                 ((i & RMII_SAMPLE_WORD_INDEX_MASK) *
                                  RMII_DIBIT_WIDTH_BITS)) &
                                RMII_DIBIT_VALUE_MASK)
                             : RMII_CAPTURE_END_SENTINEL;

        if (v == prev)
        {
            run++;

            continue;
        }

        uint n = (run + RMII_DIBIT_ROUNDING_BIAS) / RMII_CYCLES_PER_DIBIT;

        if (n == 0)
        {
            n = 1;
        }

        // the preamble is a run of 01, the SFD ends with the first 11 dibit,
        // any further dibits in that same run are already frame data
        uint first = 0;

        if (!in_frame)
        {
            if (prev == RMII_DIBIT_STATE_SFD)
            {
                in_frame = true;
                first    = 1;
            }
            else
            {
                prev = v;
                run  = 1;

                continue;
            }
        }

        for (uint k = first; k < n && out_len < out_size; k++)
        {
            byte |= prev << (dibits * RMII_DIBIT_WIDTH_BITS);

            if (++dibits == RMII_DIBITS_PER_BYTE)
            {
                out[out_len++] = byte;
                byte           = 0;
                dibits         = 0;
            }
        }

        prev = v;
        run  = 1;
    }

    return out_len;
}

static void
rmii_mdio_clock_out (int bit)
{
    gpio_put(PICO_RMII_ETHERNET_MDC_PIN, 0);
    sleep_us(1);
    gpio_put(PICO_RMII_ETHERNET_MDIO_PIN, bit);
    gpio_put(PICO_RMII_ETHERNET_MDC_PIN, 1);
    sleep_us(1);
}

static uint
rmii_mdio_clock_in (void)
{
    gpio_put(PICO_RMII_ETHERNET_MDC_PIN, 0);
    sleep_us(1);
    gpio_put(PICO_RMII_ETHERNET_MDC_PIN, 1);

    int bit = gpio_get(PICO_RMII_ETHERNET_MDIO_PIN);
    sleep_us(1);

    return bit;
}

static uint16_t
netif_rmii_ethernet_mdio_read (uint addr, uint reg)
{
    gpio_init(PICO_RMII_ETHERNET_MDIO_PIN);
    gpio_init(PICO_RMII_ETHERNET_MDC_PIN);

    gpio_set_dir(PICO_RMII_ETHERNET_MDIO_PIN, GPIO_OUT);
    gpio_set_dir(PICO_RMII_ETHERNET_MDC_PIN, GPIO_OUT);

    // PRE_32
    for (int i = 0; i < MDIO_PREAMBLE_BIT_COUNT; i++)
    {
        rmii_mdio_clock_out(1);
    }

    // ST
    rmii_mdio_clock_out(0);
    rmii_mdio_clock_out(1);

    // OP
    rmii_mdio_clock_out(1);
    rmii_mdio_clock_out(0);

    // PA5
    for (int i = 0; i < MDIO_ADDRESS_FIELD_BIT_COUNT; i++)
    {
        uint bit = (addr >> (MDIO_ADDRESS_FIELD_BIT_COUNT - 1U - i)) & 0x01U;

        rmii_mdio_clock_out(bit);
    }

    // RA5
    for (int i = 0; i < MDIO_REGISTER_FIELD_BIT_COUNT; i++)
    {
        uint bit = (reg >> (MDIO_REGISTER_FIELD_BIT_COUNT - 1U - i)) & 0x01U;

        rmii_mdio_clock_out(bit);
    }

    // TA
    gpio_set_dir(PICO_RMII_ETHERNET_MDIO_PIN, GPIO_IN);
    rmii_mdio_clock_out(0);
    rmii_mdio_clock_out(0);

    uint16_t data = 0;

    for (int i = 0; i < MDIO_DATA_FIELD_BIT_COUNT; i++)
    {
        data <<= 1;

        data |= rmii_mdio_clock_in();
    }

    return data;
}

static void
rmii_mdio_write (uint8_t addr, uint8_t reg, uint16_t value)
{
    gpio_init(PICO_RMII_ETHERNET_MDIO_PIN);
    gpio_init(PICO_RMII_ETHERNET_MDC_PIN);

    gpio_set_dir(PICO_RMII_ETHERNET_MDIO_PIN, GPIO_OUT);
    gpio_set_dir(PICO_RMII_ETHERNET_MDC_PIN, GPIO_OUT);

    // PRE_32
    for (int i = 0; i < MDIO_PREAMBLE_BIT_COUNT; i++)
    {
        rmii_mdio_clock_out(1);
    }

    // ST
    rmii_mdio_clock_out(0);
    rmii_mdio_clock_out(1);

    // OP
    rmii_mdio_clock_out(0);
    rmii_mdio_clock_out(1);

    // PA5
    uint32_t address_bits = addr;
    for (int i = 0; i < MDIO_ADDRESS_FIELD_BIT_COUNT; i++)
    {
        uint bit =
            (address_bits >> (MDIO_ADDRESS_FIELD_BIT_COUNT - 1U - i)) & 0x01U;

        rmii_mdio_clock_out(bit);
    }

    // RA5
    uint32_t register_bits = reg;
    for (int i = 0; i < MDIO_REGISTER_FIELD_BIT_COUNT; i++)
    {
        uint bit =
            (register_bits >> (MDIO_REGISTER_FIELD_BIT_COUNT - 1U - i)) & 0x01U;

        rmii_mdio_clock_out(bit);
    }

    // TA
    rmii_mdio_clock_out(1);
    rmii_mdio_clock_out(0);

    uint32_t write_data = value;
    for (int i = 0; i < MDIO_DATA_FIELD_BIT_COUNT; i++)
    {
        uint bit = (write_data >> (MDIO_DATA_FIELD_BIT_COUNT - 1U - i)) & 0x01U;

        rmii_mdio_clock_out(bit);
    }

    gpio_set_dir(PICO_RMII_ETHERNET_MDIO_PIN, GPIO_IN);
}

static void
rmii_encode_octet (uint8_t octet, uint32_t * output_index)
{
    for (uint8_t dibit = 0U; dibit < RMII_DIBITS_PER_BYTE; dibit++)
    {
        g_tx_frame_bits[(*output_index)++] =
            RMII_PIO_DATA_SYMBOL | ((octet >> (dibit * RMII_DIBIT_WIDTH_BITS)) &
                                    RMII_DIBIT_VALUE_MASK);
    }
}

static err_t
netif_rmii_ethernet_output (struct netif * netif, struct pbuf * p)
{
    size_t total_length = 0U;

    (void) netif;

    if (p == NULL)
    {
        return ERR_ARG;
    }

    memset(g_tx_frame, 0x00, sizeof(g_tx_frame));

    for (struct pbuf * q = p; q != NULL; q = q->next)
    {
        if ((size_t) q->len > (sizeof(g_tx_frame) - total_length))
        {
            return ERR_BUF;
        }

        if ((q->len > 0U) && (q->payload == NULL))
        {
            return ERR_ARG;
        }

        if (q->len > 0U)
        {
            memcpy(&g_tx_frame[total_length], q->payload, q->len);
        }

        total_length += q->len;

        if (q->len == q->tot_len)
        {
            break;
        }
    }

    if (total_length != p->tot_len)
    {
        return ERR_BUF;
    }

    if (total_length < ETHERNET_MIN_FRAME_SIZE)
    {
        // pad
        total_length = ETHERNET_MIN_FRAME_SIZE;
    }

    size_t encoded_length = (total_length + ETHERNET_PREAMBLE_SIZE +
                             ETHERNET_FCS_SIZE + ETHERNET_IFG_SIZE) *
                            RMII_DIBITS_PER_BYTE;
    if (encoded_length > sizeof(g_tx_frame_bits))
    {
        return ERR_BUF;
    }

    uint32_t crc = ethernet_frame_crc(g_tx_frame, total_length);

    dma_channel_wait_for_finish_blocking(g_tx_dma_chan);

    uint32_t index = 0U;

    for (uint8_t i = 0U; i < RMII_PREAMBLE_DIBIT_COUNT; i++)
    {
        g_tx_frame_bits[index++] = RMII_PIO_PREAMBLE_SYMBOL;
    }

    g_tx_frame_bits[index++] = RMII_PIO_SFD_SYMBOL;

    for (size_t i = 0U; i < total_length; i++)
    {
        rmii_encode_octet(g_tx_frame[i], &index);
    }

    for (uint8_t i = 0U; i < ETHERNET_FCS_SIZE; i++)
    {
        uint8_t octet = (uint8_t) (crc >> (i * RMII_BITS_PER_OCTET));

        rmii_encode_octet(octet, &index);
    }

    for (uint8_t i = 0U; i < (ETHERNET_IFG_SIZE * RMII_DIBITS_PER_BYTE); i++)
    {
        g_tx_frame_bits[index++] = 0x00;
    }

    dma_channel_configure(
        g_tx_dma_chan, &g_tx_dma_channel_config,
        ((uint8_t *) &PICO_RMII_ETHERNET_PIO->txf[PICO_RMII_ETHERNET_SM_TX]) +
            RMII_PIO_TX_FIFO_BYTE_OFFSET,
        g_tx_frame_bits, index, false);

    dma_channel_start(g_tx_dma_chan);

    g_stat_tx_frames++;

    return ERR_OK;
}

static void
rmii_rx_falling_isr (uint gpio, uint32_t events)
{
    (void) events;

    if ((PICO_RMII_ETHERNET_RX_PIN + RMII_CRS_DV_PIN_OFFSET) == gpio)
    {
        // CRS_DV falling marks the end of the received frame. Capture here so
        // queue timestamps do not include CRC checking or packet processing.
        g_rx_frame_timestamp_us = time_us_64();
        g_rx_frame_completed    = true;
        pio_sm_set_enabled(PICO_RMII_ETHERNET_PIO, PICO_RMII_ETHERNET_SM_RX,
                           false);
        dma_channel_abort(g_rx_dma_chan);
        gpio_set_irq_enabled_with_callback(
            PICO_RMII_ETHERNET_RX_PIN + RMII_CRS_DV_PIN_OFFSET,
            GPIO_IRQ_EDGE_FALL, false, rmii_rx_falling_isr);
    }
}

static void
rmii_release_setup (PIO pio, int rx_offset, int tx_offset, bool tx_sm_started)
{
    if (tx_sm_started)
    {
        pio_sm_set_enabled(pio, PICO_RMII_ETHERNET_SM_TX, false);
    }

    if (g_tx_dma_chan >= 0)
    {
        dma_channel_unclaim((uint) g_tx_dma_chan);
        g_tx_dma_chan = -1;
    }

    if (g_rx_dma_chan >= 0)
    {
        dma_channel_unclaim((uint) g_rx_dma_chan);
        g_rx_dma_chan = -1;
    }

    if (tx_offset >= 0)
    {
        pio_remove_program(pio, &rmii_ethernet_phy_tx_data_program,
                           (uint) tx_offset);
    }

    if (rx_offset >= 0)
    {
        pio_remove_program(pio, &rmii_ethernet_phy_rx_data_program,
                           (uint) rx_offset);
    }

    pio_sm_unclaim(pio, PICO_RMII_ETHERNET_SM_RX);
    pio_sm_unclaim(pio, PICO_RMII_ETHERNET_SM_TX);

    gp_rmii_eth_netif = NULL;
}

static err_t
rmii_init_failed (PIO pio, int rx_offset, int tx_offset, bool tx_sm_started,
                  err_t error)
{
    rmii_release_setup(pio, rx_offset, tx_offset, tx_sm_started);
    g_rmii_init_error = error;
    return error;
}

static void
rmii_configure_netif (struct netif * netif)
{
    gp_rmii_eth_netif = netif;
    netif->linkoutput = netif_rmii_ethernet_output;
    netif->output     = etharp_output;
    netif->mtu        = ETHERNET_MTU_SIZE;
    netif->flags      = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP |
                        NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP | NETIF_FLAG_MLD6;

    if (PICO_RMII_ETHERNET_MAC_ADDR != NULL)
    {
        memcpy(netif->hwaddr, PICO_RMII_ETHERNET_MAC_ADDR,
               ETHERNET_MAC_ADDRESS_LENGTH);
    }
    else
    {
        pico_unique_board_id_t board_id;

        pico_get_unique_board_id(&board_id);
        netif->hwaddr[0]                            = ETHERNET_MAC_OUI_BYTE_0;
        netif->hwaddr[1]                            = ETHERNET_MAC_OUI_BYTE_1;
        netif->hwaddr[ETHERNET_MAC_OUI_LAST_OFFSET] = ETHERNET_MAC_OUI_BYTE_2;
        memcpy(&netif->hwaddr[ETHERNET_MAC_OUI_LAST_OFFSET + 1U],
               &board_id.id[ETHERNET_UNIQUE_ID_START_OFFSET],
               ETHERNET_MAC_ADDRESS_LENGTH -
                   (ETHERNET_MAC_OUI_LAST_OFFSET + 1U));
    }

    netif->hwaddr_len = ETH_HWADDR_LEN;
}

static err_t
rmii_load_pio_programs (PIO pio, int * rx_offset, int * tx_offset)
{
    if (!pio_can_add_program(pio, &rmii_ethernet_phy_rx_data_program))
    {
        return ERR_MEM;
    }

    *rx_offset = pio_add_program(pio, &rmii_ethernet_phy_rx_data_program);
    if (*rx_offset < 0)
    {
        *rx_offset = -1;
        return ERR_MEM;
    }

    if (!pio_can_add_program(pio, &rmii_ethernet_phy_tx_data_program))
    {
        return ERR_MEM;
    }

    *tx_offset = pio_add_program(pio, &rmii_ethernet_phy_tx_data_program);
    if (*tx_offset < 0)
    {
        *tx_offset = -1;
        return ERR_MEM;
    }

    return ERR_OK;
}

static err_t
rmii_claim_and_configure_dma (PIO pio)
{
    g_rx_dma_chan = dma_claim_unused_channel(false);
    if (g_rx_dma_chan < 0)
    {
        return ERR_MEM;
    }

    g_tx_dma_chan = dma_claim_unused_channel(false);
    if (g_tx_dma_chan < 0)
    {
        return ERR_MEM;
    }

    g_rx_dma_channel_config = dma_channel_get_default_config(g_rx_dma_chan);
    channel_config_set_read_increment(&g_rx_dma_channel_config, false);
    channel_config_set_write_increment(&g_rx_dma_channel_config, true);
    channel_config_set_dreq(&g_rx_dma_channel_config,
                            pio_get_dreq(pio, PICO_RMII_ETHERNET_SM_RX, false));
    channel_config_set_transfer_data_size(&g_rx_dma_channel_config,
                                          DMA_SIZE_32);

    g_tx_dma_channel_config = dma_channel_get_default_config(g_tx_dma_chan);
    channel_config_set_read_increment(&g_tx_dma_channel_config, true);
    channel_config_set_write_increment(&g_tx_dma_channel_config, false);
    channel_config_set_dreq(&g_tx_dma_channel_config,
                            pio_get_dreq(pio, PICO_RMII_ETHERNET_SM_TX, true));
    channel_config_set_transfer_data_size(&g_tx_dma_channel_config, DMA_SIZE_8);

    return ERR_OK;
}

static bool
rmii_find_phy_address (void)
{
    for (int address = 0; address < MDIO_PHY_ADDRESS_COUNT; address++)
    {
        uint16_t phy_id1 = netif_rmii_ethernet_mdio_read((uint) address,
                                                         MDIO_PHY_ID1_REGISTER);
        uint16_t phy_id2 = netif_rmii_ethernet_mdio_read((uint) address,
                                                         MDIO_PHY_ID2_REGISTER);

        if ((phy_id1 != 0U) && (phy_id1 != ETHERNET_PHY_ID_UNDRIVEN_VALUE) &&
            (phy_id2 != 0U) && (phy_id2 != ETHERNET_PHY_ID_UNDRIVEN_VALUE))
        {
            g_phy_address = address;
            return true;
        }
    }

    return false;
}

static err_t
netif_rmii_ethernet_low_init (struct netif * netif)
{
    PIO  pio           = PICO_RMII_ETHERNET_PIO;
    int  rx_offset     = -1;
    int  tx_offset     = -1;
    bool tx_sm_started = false;

    if ((netif == NULL) || (pio == NULL) || ((pio != pio0) && (pio != pio1)) ||
        (PICO_RMII_ETHERNET_SM_TX >= NUM_PIO_STATE_MACHINES) ||
        (PICO_RMII_ETHERNET_SM_RX >= NUM_PIO_STATE_MACHINES) ||
        (PICO_RMII_ETHERNET_RX_PIN >
         (NUM_BANK0_GPIOS - RMII_RECEIVE_PIN_COUNT)) ||
        (PICO_RMII_ETHERNET_TX_PIN >
         (NUM_BANK0_GPIOS - RMII_RECEIVE_PIN_COUNT)) ||
        (PICO_RMII_ETHERNET_MDIO_PIN >
         (NUM_BANK0_GPIOS - RMII_MDIO_PIN_COUNT)) ||
        rmii_pin_ranges_overlap(
            PICO_RMII_ETHERNET_RX_PIN, RMII_RECEIVE_PIN_COUNT,
            PICO_RMII_ETHERNET_TX_PIN, RMII_RECEIVE_PIN_COUNT) ||
        rmii_pin_ranges_overlap(
            PICO_RMII_ETHERNET_RX_PIN, RMII_RECEIVE_PIN_COUNT,
            PICO_RMII_ETHERNET_MDIO_PIN, RMII_MDIO_PIN_COUNT) ||
        rmii_pin_ranges_overlap(
            PICO_RMII_ETHERNET_TX_PIN, RMII_RECEIVE_PIN_COUNT,
            PICO_RMII_ETHERNET_MDIO_PIN, RMII_MDIO_PIN_COUNT))
    {
        g_rmii_init_error = ERR_ARG;
        return g_rmii_init_error;
    }

    if (pio_sm_is_claimed(pio, PICO_RMII_ETHERNET_SM_RX) ||
        pio_sm_is_claimed(pio, PICO_RMII_ETHERNET_SM_TX))
    {
        g_rmii_init_error = ERR_USE;
        return g_rmii_init_error;
    }

    pio_sm_claim(pio, PICO_RMII_ETHERNET_SM_RX);
    pio_sm_claim(pio, PICO_RMII_ETHERNET_SM_TX);

    rmii_configure_netif(netif);

    err_t setup_error = rmii_load_pio_programs(pio, &rx_offset, &tx_offset);
    if (setup_error != ERR_OK)
    {
        return rmii_init_failed(pio, rx_offset, tx_offset, tx_sm_started,
                                setup_error);
    }

    g_rx_sm_offset = (uint) rx_offset;
    g_tx_sm_offset = (uint) tx_offset;

    setup_error = rmii_claim_and_configure_dma(pio);
    if (setup_error != ERR_OK)
    {
        return rmii_init_failed(pio, rx_offset, tx_offset, tx_sm_started,
                                setup_error);
    }

    rmii_ethernet_phy_tx_init(pio, PICO_RMII_ETHERNET_SM_TX, g_tx_sm_offset,
                              PICO_RMII_ETHERNET_TX_PIN);
    tx_sm_started = true;

    bool phy_found = rmii_find_phy_address();

    printf("phy %s at address %d\n", phy_found ? "found" : "NOT FOUND on MDIO",
           g_phy_address);

    if (!phy_found)
    {
        return rmii_init_failed(pio, rx_offset, tx_offset, tx_sm_started,
                                ERR_IF);
    }

    // advertise 10 Mbps only, then restart auto negotiation. At 100 Mbps the
    // PHY toggles CRS_DV as each frame ends, which this driver reads as a new
    // frame, so it re-arms hundreds of times per second and captures noise.
    rmii_mdio_write((uint8_t) g_phy_address, MDIO_PHY_ADVERTISEMENT_REGISTER,
                    ETHERNET_PHY_AUTONEGOTIATION_ADVERTISEMENT);
    rmii_mdio_write((uint8_t) g_phy_address, MDIO_PHY_CONTROL_REGISTER,
                    ETHERNET_PHY_AUTONEGOTIATION_RESTART);

    g_rmii_init_error = ERR_OK;
    return g_rmii_init_error;
}

err_t
netif_rmii_ethernet_init (struct netif * netif, rmii_ethernet_config_t * config)
{
    if (netif == NULL)
    {
        return ERR_ARG;
    }

    if (gp_rmii_eth_netif != NULL)
    {
        return ERR_USE;
    }

    if (config != NULL)
    {
        memcpy(&g_rmii_eth_netif_config, config,
               sizeof(g_rmii_eth_netif_config));
    }

    if (!g_frame_snapshot_lock_initialized)
    {
        critical_section_init(&g_frame_snapshot_lock);
        g_frame_snapshot_lock_initialized = true;
    }

    gp_rmii_eth_netif = NULL;
    g_rmii_init_error = ERR_IF;
    if (netif_add(netif, IP4_ADDR_ANY, IP4_ADDR_ANY, IP4_ADDR_ANY, NULL,
                  netif_rmii_ethernet_low_init, netif_input) == NULL)
    {
        gp_rmii_eth_netif = NULL;
        return g_rmii_init_error;
    }

    netif->name[0] = 'e';
    netif->name[1] = '0';

    return ERR_OK;
}

static void
rmii_publish_frame (size_t frame_length)
{
    g_stat_rx_frames++;

    uint16_t frame_copy_length = (uint16_t) frame_length;
    uint32_t frame_sequence    = 0U;

    critical_section_enter_blocking(&g_frame_snapshot_lock);
    memcpy(g_stat_good_frame, g_rx_frame, frame_copy_length);
    g_stat_good_frame_len = frame_copy_length;
    g_stat_good_frame_seq++;
    frame_sequence = g_stat_good_frame_seq;
    critical_section_exit(&g_frame_snapshot_lock);
    capture_queue_push(g_rx_frame, frame_copy_length, frame_sequence,
                       g_rx_frame_timestamp_us);

    struct pbuf * packet =
        pbuf_alloc(PBUF_RAW, (u16_t) frame_length, PBUF_POOL);
    if (packet == NULL)
    {
        return;
    }

    if (pbuf_take(packet, g_rx_frame, (u16_t) frame_length) != ERR_OK)
    {
        pbuf_free(packet);
        return;
    }

    if (gp_rmii_eth_netif->input(packet, gp_rmii_eth_netif) != ERR_OK)
    {
        pbuf_free(packet);
    }
}

static size_t
rmii_decode_captured_frame (bool frame_completed)
{
    uintptr_t write_address  = dma_hw->ch[g_rx_dma_chan].write_addr;
    uintptr_t capture_start  = (uintptr_t) g_rx_samples;
    uintptr_t capture_end    = capture_start + sizeof(g_rx_samples);
    uint32_t  captured_bytes = 0U;

    if ((write_address > capture_start) && (write_address <= capture_end))
    {
        captured_bytes = (uint32_t) (write_address - capture_start);
    }

    if (!frame_completed || (captured_bytes < RMII_RECEIVE_READY_WORD_COUNT))
    {
        return 0U;
    }

    uint decoded_length = rmii_decode_samples(
        g_rx_samples, captured_bytes / RMII_SAMPLE_WORDS_PER_CAPTURE,
        g_rx_frame, sizeof(g_rx_frame));
    if (decoded_length == 0U)
    {
        return 0U;
    }

    return ethernet_frame_length(g_rx_frame, decoded_length);
}

static void
rmii_rearm_receiver (void)
{
    memset(g_rx_frame, 0x00, sizeof(g_rx_frame));
    g_rx_frame_timestamp_us = 0U;
    g_rx_frame_completed    = false;
    dma_channel_configure(
        g_rx_dma_chan, &g_rx_dma_channel_config, g_rx_samples,
        &PICO_RMII_ETHERNET_PIO->rxf[PICO_RMII_ETHERNET_SM_RX],
        count_of(g_rx_samples), false);
    dma_channel_start(g_rx_dma_chan);
    rmii_ethernet_phy_rx_init(PICO_RMII_ETHERNET_PIO, PICO_RMII_ETHERNET_SM_RX,
                              g_rx_sm_offset, PICO_RMII_ETHERNET_RX_PIN);
    gpio_set_irq_enabled_with_callback(
        PICO_RMII_ETHERNET_RX_PIN + RMII_CRS_DV_PIN_OFFSET, GPIO_IRQ_EDGE_FALL,
        true, &rmii_rx_falling_isr);
}

static void
rmii_process_completed_capture (void)
{
    bool frame_completed = g_rx_frame_completed;
    g_rx_frame_completed = false;

    size_t frame_length = rmii_decode_captured_frame(frame_completed);
    if (frame_length == 0U)
    {
        for (int index = 0; index < ETHERNET_HEADER_SIZE; index++)
        {
            if (g_rx_frame[index] != 0U)
            {
                g_stat_rx_bad_crc++;
                break;
            }
        }
    }
    else if (frame_length >= ETHERNET_HEADER_SIZE)
    {
        rmii_publish_frame(frame_length);
    }

    rmii_rearm_receiver();
}

static void
rmii_poll_phy (absolute_time_t * next_link_check,
               absolute_time_t * next_phy_dump)
{
    if (time_reached(*next_link_check))
    {
        *next_link_check = make_timeout_time_ms(ETHERNET_LINK_POLL_INTERVAL_MS);
        uint16_t status  = netif_rmii_ethernet_mdio_read(
            (uint) g_phy_address, MDIO_PHY_STATUS_REGISTER);
        if ((status & PHY_STATUS_LINK_MASK) == 0U)
        {
            status = netif_rmii_ethernet_mdio_read((uint) g_phy_address,
                                                   MDIO_PHY_STATUS_REGISTER);
        }

        bool link_up = (status & PHY_STATUS_LINK_MASK) != 0U;
        if ((netif_is_link_up(gp_rmii_eth_netif) != 0) != link_up)
        {
            if (link_up)
            {
                g_stat_phy_status = netif_rmii_ethernet_mdio_read(
                    (uint) g_phy_address, MDIO_VENDOR_STATUS_REGISTER);
                netif_set_link_up(gp_rmii_eth_netif);
            }
            else
            {
                netif_set_link_down(gp_rmii_eth_netif);
            }
        }
    }

    if (time_reached(*next_phy_dump))
    {
        *next_phy_dump =
            make_timeout_time_ms(ETHERNET_PHY_DIAGNOSTIC_INTERVAL_MS);
        g_stat_phy_status = netif_rmii_ethernet_mdio_read(
            (uint) g_phy_address, MDIO_VENDOR_STATUS_REGISTER);
    }
}

void
netif_rmii_ethernet_poll (void)
{
    static absolute_time_t next_link_check;
    static absolute_time_t next_phy_dump;

    if (gp_rmii_eth_netif == NULL)
    {
        return;
    }

    if (!dma_channel_is_busy(g_rx_dma_chan))
    {
        rmii_process_completed_capture();
    }

    // Service link management after RX work because MDIO bit-banging is slow.
    rmii_poll_phy(&next_link_check, &next_phy_dump);
    sys_check_timeouts();
}

void
netif_rmii_ethernet_get_stats (uint32_t * tx_frames, uint32_t * rx_frames,
                               uint32_t * rx_bad_crc, uint16_t * phy_status)
{
    if (tx_frames != NULL)
    {
        *tx_frames = g_stat_tx_frames;
    }

    if (rx_frames != NULL)
    {
        *rx_frames = g_stat_rx_frames;
    }

    if (rx_bad_crc != NULL)
    {
        *rx_bad_crc = g_stat_rx_bad_crc;
    }

    if (phy_status != NULL)
    {
        *phy_status = g_stat_phy_status;
    }
}

bool
netif_rmii_ethernet_dequeue_frame (uint8_t * frame, uint16_t capacity,
                                   uint16_t * len, uint32_t * seq,
                                   uint64_t * timestamp_us)
{
    if ((frame == NULL) || (len == NULL) || (seq == NULL) ||
        (timestamp_us == NULL))
    {
        return false;
    }

    uint32_t tail = g_capture_queue_tail;

    if (tail == g_capture_queue_head)
    {
        return false;
    }

    __dmb();
    const captured_frame_t * slot = &g_capture_queue[tail];
    if (slot->len > capacity)
    {
        *len = slot->len;
        return false;
    }

    memcpy(frame, slot->data, slot->len);
    *len          = slot->len;
    *seq          = slot->seq;
    *timestamp_us = slot->timestamp_us;

    __dmb();
    g_capture_queue_tail = (tail + 1U) % CAPTURE_QUEUE_SLOT_COUNT;
    return true;
}

uint32_t
netif_rmii_ethernet_capture_dropped (void)
{
    return g_capture_queue_dropped;
}

bool
rmii_ethernet_copy_last_frame (uint8_t * frame, uint16_t capacity,
                               uint16_t * len, uint32_t * seq)
{
    if ((frame == NULL) || (len == NULL) || (seq == NULL))
    {
        return false;
    }

    if (!g_frame_snapshot_lock_initialized)
    {
        return false;
    }

    critical_section_enter_blocking(&g_frame_snapshot_lock);

    uint16_t frame_length = g_stat_good_frame_len;
    if ((frame_length == 0U) || (frame_length > capacity))
    {
        critical_section_exit(&g_frame_snapshot_lock);
        return false;
    }

    memcpy(frame, g_stat_good_frame, frame_length);
    *len = frame_length;
    *seq = g_stat_good_frame_seq;

    critical_section_exit(&g_frame_snapshot_lock);
    return true;
}

const uint8_t *
netif_rmii_ethernet_last_good_frame (uint16_t * len, uint32_t * seq)
{
    if ((len == NULL) || (seq == NULL))
    {
        return NULL;
    }

    if (!g_frame_snapshot_lock_initialized)
    {
        *len = 0U;
        *seq = 0U;
        return NULL;
    }

    critical_section_enter_blocking(&g_frame_snapshot_lock);
    uint16_t frame_length = g_stat_good_frame_len;
    memcpy(g_stat_good_frame_snapshot, g_stat_good_frame, frame_length);
    *len = frame_length;
    *seq = g_stat_good_frame_seq;
    critical_section_exit(&g_frame_snapshot_lock);

    return g_stat_good_frame_snapshot;
}

void
netif_rmii_ethernet_loop (void)
{
    while (true)
    {
        netif_rmii_ethernet_poll();
    }
}
