/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PICO_RMII_ETHERNET_H
#define PICO_RMII_ETHERNET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hardware/pio.h"

#include "lwip/netif.h"

struct netif_rmii_ethernet_config
{
    PIO       pio;
    uint      pio_sm_start;   // uses 2 PIO sm's
    uint      rx_pin_start;   // RX0, RX1, CRS
    uint      tx_pin_start;   // TX0, TX1, TX-EN
    uint      mdio_pin_start; // MDIO, MDC
    uint8_t * mac_addr;       // 6 bytes
};
typedef struct netif_rmii_ethernet_config rmii_ethernet_config_t;

#define NETIF_RMII_ETHERNET_DEFAULT_CONFIG()                                   \
    {.pio            = pio0,                                                   \
     .pio_sm_start   = 0,                                                      \
     .rx_pin_start   = 6,                                                      \
     .tx_pin_start   = 10,                                                     \
     .mdio_pin_start = 14,                                                     \
     .mac_addr       = NULL}

err_t netif_rmii_ethernet_init (struct netif *           netif,
                                rmii_ethernet_config_t * config);

void netif_rmii_ethernet_poll (void);

void netif_rmii_ethernet_loop (void);

void netif_rmii_ethernet_get_stats (uint32_t * tx_frames, uint32_t * rx_frames,
                                    uint32_t * rx_bad_crc,
                                    uint16_t * phy_status);

// Copies and removes the oldest CRC-valid frame. On insufficient capacity,
// returns false, stores the required length in len, and leaves the frame
// queued.
bool netif_rmii_ethernet_dequeue_frame (uint8_t * frame, uint16_t capacity,
                                        uint16_t * len, uint32_t * seq,
                                        uint64_t * timestamp_us);

// Copies a stable snapshot of the most recent CRC-valid frame. Returns false
// if no frame is available or capacity is too small.
bool rmii_ethernet_copy_last_frame (uint8_t * frame, uint16_t capacity,
                                    uint16_t * len, uint32_t * seq);

// Number of CRC-valid frames discarded because the capture queue was full.
uint32_t netif_rmii_ethernet_capture_dropped (void);

// Compatibility API: the returned snapshot remains stable until the next call.
// Use rmii_ethernet_copy_last_frame() for cross-core consumers.
const uint8_t * netif_rmii_ethernet_last_good_frame (uint16_t * len,
                                                     uint32_t * seq);

#endif /* PICO_RMII_ETHERNET_H */
