/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"

#include "hardware/clocks.h"
#include "hardware/watchdog.h"

#include "lwip/dhcp.h"
#include "lwip/init.h"

#include "lwip/apps/httpd.h"

#include "rmii_ethernet/netif.h"

// counts how often the RMII reference clock on GP20 stopped, the RP2040 resus
// logic then falls back to clk_ref instead of the chip freezing
static volatile uint32_t clk_resus_count;

static void clk_resus_callback(void)
{
    clk_resus_count++;
}

void netif_link_callback(struct netif* netif)
{
    printf("link %s\n", netif_is_link_up(netif) ? "up" : "down");
}

void netif_status_callback(struct netif* netif)
{
    printf("ip address %s\n", ip4addr_ntoa(netif_ip4_addr(netif)));
}

static const char* ethertype_name(uint16_t type)
{
    switch (type)
    {
    case 0x0800:
        return "IPv4";
    case 0x0806:
        return "ARP";
    case 0x8100:
        return "VLAN tagged";
    case 0x86dd:
        return "IPv6";
    case 0x88b8:
        return "GOOSE";
    case 0x88ba:
        return "Sampled Values";
    case 0x88cc:
        return "LLDP";
    default:
        return "unknown";
    }
}

static void print_mac(const uint8_t* mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
           mac[4], mac[5]);
}

static void print_quoted(const uint8_t* v, uint len)
{
    putchar('"');

    for (uint i = 0; i < len; i++)
    {
        putchar(v[i] >= 0x20 && v[i] < 0x7f ? v[i] : '.');
    }

    putchar('"');
}

static bool ber_uint(const uint8_t* v, uint len, uint32_t* out)
{
    if ((v == NULL) || (out == NULL) || (len == 0U) || (len > 5U))
    {
        return false;
    }

    const bool prefixed = len == 5U;
    if (prefixed)
    {
        if (v[0] != 0U)
        {
            return false;
        }
        ++v;
        --len;
    }
    else if ((v[0] & 0x80U) != 0U)
    {
        return false;
    }

    uint32_t value = 0U;
    for (uint index = 0U; index < len; ++index)
    {
        value = (value << 8U) | v[index];
    }

    *out = value;
    return true;
}

// Decodes the IEC 61850 GOOSE header and the BER encoded PDU fields that follow
// it. Field tags are context specific, 0x80 gocbRef through 0x8a entries.
static void print_goose(const uint8_t* p, uint len)
{
    if (len < 10 || p[8] != 0x61)
    {
        printf("  (not a GOOSE PDU)\n");

        return;
    }

    printf("  APPID %u (0x%04x), PDU length %u\n", (p[0] << 8) | p[1],
           (p[0] << 8) | p[1], (p[2] << 8) | p[3]);

    const uint8_t* f = p + 8;
    uint pdu_len = f[1];
    uint header = 2;
    const size_t available = len - 8U;

    if ((f[1] == 0x81) && (available >= 3U))
    {
        pdu_len = f[2];
        header = 3;
    }
    else if ((f[1] == 0x82) && (available >= 4U))
    {
        pdu_len = (f[2] << 8) | f[3];
        header = 4;
    }
    else if ((f[1] & 0x80U) != 0U)
    {
        printf("  (invalid GOOSE PDU length)\n");
        return;
    }

    if (pdu_len > (available - header))
    {
        pdu_len = (uint)(available - header);
    }

    const uint8_t* end = f + header + pdu_len;
    f += header;

    // first line carries the names, second the counters, so both stay readable
    printf(" ");

    for (const uint8_t* scan = f; (size_t)(end - scan) >= 2U;)
    {
        uint8_t tag = scan[0];
        uint flen = scan[1];
        uint field_header = 2U;

        if (flen == 0x81)
        {
            if ((size_t)(end - scan) < 3U)
            {
                break;
            }
            flen = scan[2];
            field_header = 3U;
        }
        else if (flen == 0x82)
        {
            if ((size_t)(end - scan) < 4U)
            {
                break;
            }
            flen = (scan[2] << 8) | scan[3];
            field_header = 4U;
        }
        else if ((flen & 0x80U) != 0U)
        {
            break;
        }

        const uint8_t* v = scan + field_header;
        if (flen > (size_t)(end - v))
        {
            break;
        }

        switch (tag)
        {
        case 0x80:
            printf(" gocbRef ");
            print_quoted(v, flen);
            break;
        case 0x82:
            printf("  datSet ");
            print_quoted(v, flen);
            break;
        case 0x83:
            printf("  goID ");
            print_quoted(v, flen);
            break;
        default:
            break;
        }

        scan = v + flen;
    }

    printf("\n ");

    for (const uint8_t* scan = f; (size_t)(end - scan) >= 2U;)
    {
        uint8_t tag = scan[0];
        uint flen = scan[1];
        uint field_header = 2U;

        if (flen == 0x81)
        {
            if ((size_t)(end - scan) < 3U)
            {
                break;
            }
            flen = scan[2];
            field_header = 3U;
        }
        else if (flen == 0x82)
        {
            if ((size_t)(end - scan) < 4U)
            {
                break;
            }
            flen = (scan[2] << 8) | scan[3];
            field_header = 4U;
        }
        else if ((flen & 0x80U) != 0U)
        {
            break;
        }

        const uint8_t* v = scan + field_header;
        if (flen > (size_t)(end - v))
        {
            break;
        }

        uint32_t number = 0U;
        const bool valid_number = ber_uint(v, flen, &number);
        switch (tag)
        {
        case 0x81:
            if (valid_number)
            {
                printf(" TTL %u ms", (unsigned)number);
            }
            break;
        case 0x85:
            if (valid_number)
            {
                printf("  stNum %u", (unsigned)number);
            }
            break;
        case 0x86:
            if (valid_number)
            {
                printf("  sqNum %u", (unsigned)number);
            }
            break;
        case 0x87:
            if (flen == 1U)
            {
                printf("  simulation %s", v[0] != 0U ? "yes" : "no");
            }
            break;
        case 0x88:
            if (valid_number)
            {
                printf("  confRev %u", (unsigned)number);
            }
            break;
        case 0x89:
            if (flen == 1U)
            {
                printf("  ndsCom %s", v[0] != 0U ? "yes" : "no");
            }
            break;
        case 0x8a:
            if (valid_number)
            {
                printf("  entries %u", (unsigned)number);
            }
            break;
        case 0xab:
            printf("  allData %u bytes", flen);
            break;
        default:
            break;
        }

        scan = v + flen;
    }

    printf("\n");
}

static void print_frame(uint32_t number, const uint8_t* frame, uint len)
{
    if (len < 14)
    {
        printf("frame %u  %u bytes  (too short to decode)\n", (unsigned)number,
               len);

        return;
    }

    uint16_t type = (frame[12] << 8) | frame[13];
    uint32_t ms = to_ms_since_boot(get_absolute_time());

    printf("\nframe %u  at %u.%03us  %u bytes  %s (0x%04x)\n", (unsigned)number,
           (unsigned)(ms / 1000), (unsigned)(ms % 1000), len,
           ethertype_name(type), type);

    printf("  ");
    print_mac(frame + 6);
    printf("  ->  ");
    print_mac(frame);
    printf("\n");

    const uint8_t* payload = frame + 14;
    uint payload_len = len - 14;

    if (type == 0x88b8)
    {
        print_goose(payload, payload_len);

        return;
    }

    // anything else gets a short hex preview of its payload
    uint show = payload_len > 32 ? 32 : payload_len;

    printf("  payload %u bytes:", payload_len);

    for (uint i = 0; i < show; i++)
    {
        printf(" %02x", payload[i]);
    }

    printf(payload_len > show ? " ...\n" : "\n");
}

int main()
{
    // LWIP network interface
    struct netif netif;

    //
    struct netif_rmii_ethernet_config netif_config = {
        pio0, // PIO:            0
        0,    // pio SM:         0 and 1
        6,    // rx pin start:   6, 7, 8    => RX0, RX1, CRS
        10,   // tx pin start:   10, 11, 12 => TX0, TX1, TX-EN
        14,   // mdio pin start: 14, 15   => ?MDIO, MDC
        NULL, // MAC address (optional - NULL generates one based on flash id)
    };

    // drive TX0, TX1 and TX_EN low straight away, if left floating (only the
    // weak pad pull-downs) noise can raise TX_EN and the PHY transmits garbage
    for (uint pin = 10; pin <= 12; pin++)
    {
        gpio_init(pin);
        gpio_set_dir(pin, GPIO_OUT);
        gpio_put(pin, 0);
    }

    stdio_init_all();

    // wait for a serial terminal to be opened so no output is missed
    while (!stdio_usb_connected())
    {
        sleep_ms(100);
    }
    sleep_ms(500);

    // reboot if the main loop ever wedges, so the board can still be reflashed
    // over usb instead of needing a manual BOOTSEL
    watchdog_enable(8000, 1);

    printf("pico rmii ethernet receiver\n");

    // the PHY supplies the 50 MHz RMII reference clock, switching clk_sys to a
    // missing clock hangs the chip, so check it is there first
    gpio_set_function(20, GPIO_FUNC_GPCK);

    while (1)
    {
        uint32_t khz = frequency_count_khz(CLOCKS_FC0_SRC_VALUE_CLKSRC_GPIN0);

        if (khz > 49000 && khz < 51000)
        {
            break;
        }

        printf("waiting for 50 MHz GP20 reference clock, reading %u kHz\n",
               (unsigned)khz);
        watchdog_update();
        sleep_ms(1000);
    }

    clock_configure_gpin(clk_sys, 20, 50 * MHZ, 50 * MHZ);
    sleep_ms(100);

    // if GP20 stops, recover to clk_ref and count it instead of freezing
    clocks_enable_resus(&clk_resus_callback);

    // initilize LWIP in NO SYS mode
    lwip_init();

    // initialize the PIO base RMII Ethernet network interface
    if (netif_rmii_ethernet_init(&netif, &netif_config) != ERR_OK)
    {
        printf("RMII network interface initialization failed\n");
        return 1;
    }

    // assign callbacks for link and status
    netif_set_link_callback(&netif, netif_link_callback);
    netif_set_status_callback(&netif, netif_status_callback);

    // set the default interface and bring it up
    netif_set_default(&netif);
    netif_set_up(&netif);

    // Start DHCP client and httpd
    dhcp_start(&netif);
    httpd_init();

    printf("mac %02x:%02x:%02x:%02x:%02x:%02x, waiting for frames\n",
           netif.hwaddr[0], netif.hwaddr[1], netif.hwaddr[2], netif.hwaddr[3],
           netif.hwaddr[4], netif.hwaddr[5]);

    // setup core 1 to monitor the RMII ethernet interface
    // this let's core 0 do other things :)
    multicore_launch_core1(netif_rmii_ethernet_loop);

    static uint8_t frame[1518];

    uint32_t last_seq = 0;
    uint32_t last_reported = 0;
    absolute_time_t next_summary = make_timeout_time_ms(10000);

    while (1)
    {
        watchdog_update();

        uint16_t len = 0;
        uint32_t seq = 0;
        if ((rmii_ethernet_copy_last_frame(frame, (uint16_t)sizeof(frame), &len,
                                           &seq)) &&
            (seq != last_seq))
        {
            last_seq = seq;
            print_frame(seq, frame, len);
        }

        if (time_reached(next_summary))
        {
            next_summary = make_timeout_time_ms(10000);

            uint32_t tx_frames, rx_frames, rx_bad_crc;
            uint16_t phy_status;

            netif_rmii_ethernet_get_stats(&tx_frames, &rx_frames, &rx_bad_crc,
                                          &phy_status);

            uint speed = (phy_status >> 2) & 0x7;

            if (rx_frames != last_reported || rx_bad_crc)
            {
                last_reported = rx_frames;

                printf("\n-- %u frames received, %u corrupt, link %s\n",
                       (unsigned)rx_frames, (unsigned)rx_bad_crc,
                       speed == 0x1   ? "10 half"
                       : speed == 0x5 ? "10 full"
                       : speed == 0x2 ? "100 half"
                       : speed == 0x6 ? "100 full"
                                      : "down");
            }

            if (clk_resus_count)
            {
                printf("!! GP20 50 MHz clock stopped %u times; "
                       "check PHY power\n",
                       (unsigned)clk_resus_count);
            }
        }

        sleep_ms(1);
    }

    return 0;
}
