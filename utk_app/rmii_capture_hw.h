/*
 * rmii_capture_hw.h  (owner: Buddy 2, Jonathan)
 * Hardware layer of the RMII capture: PIO0 sampler, one DMA channel, two
 * sample buffers (ping pong), the CRS_DV interrupt body and MDIO.
 *
 * This file uses plain C types only. The µT-Kernel side lives in
 * rmii_capture_task.c, so Pico SDK and µT-Kernel headers never meet in one
 * translation unit (the port keeps them apart the same way).
 *
 * Every function here must be called from processor 2 (core 1), except the
 * read only counters.
 */
#ifndef RMII_CAPTURE_HW_H
#define RMII_CAPTURE_HW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RMII_HW_BUFFER_COUNT (2u)

/* A finished capture waiting to be decoded. */
typedef struct
{
    uint8_t          buffer;       /* 0 or 1 */
    const uint32_t * samples;
    size_t           word_count;
    uint64_t         timestamp_us;
} rmii_hw_capture_t;

/* MDIO: scan addresses 0 to 31, soft reset the PHY, advertise 10 Mbps only
 * and restart auto negotiation. Returns false if no PHY answers. */
bool rmii_hw_phy_init (uint32_t * phy_address);
bool rmii_hw_link_up (void);

/* Load the PIO program, claim SM and DMA, enable the CRS_DV edge interrupt
 * for this core only, and arm buffer 0. */
bool rmii_hw_rx_start (void);

/* NVIC number of the GPIO bank interrupt (IO_IRQ_BANK0). */
uint32_t rmii_hw_irq_number (void);

/* Interrupt body. Returns true when a capture finished and the task must be
 * woken. Re-arms into the other buffer when it is free. */
bool rmii_hw_isr (void);

/* Task side: oldest finished capture, or false if none. */
bool rmii_hw_next_capture (rmii_hw_capture_t * capture);
/* Task side: decoding of this buffer is done; re-arm if the receiver had to
 * pause because both buffers were full. */
void rmii_hw_release_capture (uint8_t buffer);

uint64_t rmii_hw_time_us (void);
uint32_t rmii_hw_isr_count (void);
uint32_t rmii_hw_overrun_count (void);

#endif /* RMII_CAPTURE_HW_H */
