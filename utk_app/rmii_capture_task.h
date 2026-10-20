/*
 * rmii_capture_task.h  (owner: Buddy 2, Jonathan)
 * LAN8720 RMII receive path as a µT-Kernel task pinned to processor 2
 * (core 1). Tribunal 1 decisions:
 *   - capture is a real µT task, priority 1, alone on core 1;
 *   - the CRS_DV ISR only stamps the time, stops PIO/DMA, re-arms into the
 *     second sample buffer and wakes the task (no SIO FIFO doorbell);
 *   - about three kernel calls per frame: wake, tk_get_mpf, tk_snd_mbx;
 *   - receive only: no TX state machine, no TX buffers, no lwIP netif.
 */
#ifndef RMII_CAPTURE_TASK_H
#define RMII_CAPTURE_TASK_H

#include <tk/tkernel.h>
#include <stdbool.h>
#include <stdint.h>

/* Counters written only by core 1, read by any task. Each field is an
 * aligned 32 bit word, so a single read is never torn. */
typedef struct
{
    uint32_t heartbeat;       /* +1 every loop, also when idle (Health Mon.) */
    uint32_t isr_count;       /* CRS_DV falling edges handled */
    uint32_t rx_frames;       /* frames with a good FCS */
    uint32_t bad_crc;         /* captures that looked like frames, bad FCS */
    uint32_t non_iec_dropped; /* good frames that were not GOOSE or SV */
    uint32_t pool_empty;      /* GOOSE/SV frames lost: no free pool block */
    uint32_t rx_overrun;      /* both sample buffers busy: receiver paused */
    uint32_t decode_last_us;
    uint32_t decode_max_us;
    uint32_t phy_found;       /* 1 when a PHY answered on MDIO */
    uint32_t phy_address;
    uint32_t link_up;
    uint32_t last_seq;        /* sequence of the newest GOOSE/SV frame */
} rmii_capture_stats_t;

extern volatile rmii_capture_stats_t g_rmii_capture_stats;

/* Create (not start) the capture task. Call from usermain after the frame
 * pool and mailbox exist. Returns the task id or a negative error. */
ID rmii_capture_task_create (ID frame_pool_id, ID frame_mailbox_id);

#endif /* RMII_CAPTURE_TASK_H */
