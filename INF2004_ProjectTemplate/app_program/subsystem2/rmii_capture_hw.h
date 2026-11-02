/** @file rmii_capture_hw.h
 *
 * @brief Hardware layer of the RMII capture: the PIO0 sampler, one DMA
 * channel, two (ping-pong) sample buffers, the CRS_DV interrupt body and
 * the MDIO management bus of the LAN8720 PHY.
 *
 * @par
 * This module uses plain C types only. The micro T-Kernel side lives in
 * task_producer.c, so Pico SDK and micro T-Kernel headers never meet in one
 * translation unit.
 *
 * @par
 * Call these functions from the capture owner's core (core 1 in SMP, core 0
 * in UP). Task-side calls mask that core's interrupts; no direct access from
 * the other core is allowed.
 *
 * @par
 * Ported from rmii_ethernet.c by Sandeep Mistry (BSD-3-Clause).
 */
#ifndef RMII_CAPTURE_HW_H
#define RMII_CAPTURE_HW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RMII_HW_BUFFER_COUNT (2u)

// A finished capture waiting to be decoded.
//
typedef struct
{
    uint8_t          buffer;       // Sample buffer index, 0 or 1.
    uint32_t const * p_samples;    // The captured sample words.
    size_t           word_count;   // Number of sample words; 0 if too short.
    uint64_t         timestamp_us; // Frame end time (CRS_DV falling edge).
} rmii_capture_hw_capture_t;

// PHY registers and pin levels for the health report.
//
typedef struct
{
    uint16_t id1;
    uint16_t id2;
    uint16_t control;
    uint16_t status;
    uint16_t advertise;
    uint16_t partner;
    uint16_t special;
    uint16_t io_levels; // Bits 0, 1, 2: CRS_DV, RXD0, RXD1 levels.
} rmii_capture_hw_phy_diag_t;

// NOTE: The shared monitor_status.h still uses this older name.
//
typedef rmii_capture_hw_phy_diag_t rmii_hw_phy_diag_t;

bool     rmii_capture_hw_phy_init(uint32_t * p_phy_address);
bool     rmii_capture_hw_is_link_up(void);
void     rmii_capture_hw_read_phy_diag(rmii_capture_hw_phy_diag_t * p_diag);
bool     rmii_capture_hw_rx_start(void);
uint32_t rmii_capture_hw_irq_number(void);
bool     rmii_capture_hw_next_capture(rmii_capture_hw_capture_t * p_capture);
void     rmii_capture_hw_release(uint8_t buffer);
uint64_t rmii_capture_hw_time_us(void);
uint32_t rmii_capture_hw_isr_count(void);
uint32_t rmii_capture_hw_overrun_count(void);
uint32_t rmii_capture_hw_dma_full_count(void);
bool     rmii_capture_hw_isr(void);

#endif /* RMII_CAPTURE_HW_H */

/*** end of file ***/
