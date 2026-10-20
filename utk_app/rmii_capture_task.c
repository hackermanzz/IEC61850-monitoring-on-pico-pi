/*
 * rmii_capture_task.c  (owner: Buddy 2, Jonathan)
 * µT-Kernel side of the RMII capture. Runs pinned to processor 2 (core 1).
 *
 * Per frame the task makes about three kernel calls (Tribunal 1):
 *   ISR: tk_wup_tsk  ->  task: tk_get_mpf (no wait)  ->  tk_snd_mbx
 * Fewer calls on core 1 means fewer moments with the big kernel lock held
 * and local interrupts masked (port measurement: up to 85 us).
 */
/* µT-Kernel's syslib.h would typedef size_t as a signed type, which
 * clashes with <stddef.h> used by the analyzer and SDK. Keep the C one. */
#define PROHIBIT_DEF_SIZE_T (1)
#include <stddef.h>

#include <tk/tkernel.h>
#include <tm/tmonitor.h>

#include <stddef.h>
#include <stdint.h>

#include "app_config.h"
#include "app_messages.h"
#include "rmii_capture_hw.h"
#include "rmii_capture_task.h"
#include "rmii_frame.h"

#define ETHERNET_HEADER_BYTES (14u)
#define ETHERTYPE_OFFSET      (12u)
#define VLAN_TAG_BYTES        (4u)
#define MAXIMUM_VLAN_TAGS     (2u)
#define ETHERTYPE_GOOSE       (0x88B8u)
#define ETHERTYPE_SV          (0x88BAu)
#define ETHERTYPE_VLAN_8021Q  (0x8100u)
#define ETHERTYPE_VLAN_8021AD (0x88A8u)
#define ETHERTYPE_VLAN_QINQ   (0x9100u)
#define PHY_FAULT_REPORT_MS   (2000)
#define LINK_POLL_US          ((uint64_t) IS18_CAPTURE_IDLE_MS * 1000u)

volatile rmii_capture_stats_t g_rmii_capture_stats;

static ID       g_task_id;
static ID       g_pool_id;
static ID       g_mailbox_id;
static uint32_t g_sequence;
/* Decode target when the pool is empty: the frame must still be decoded so
 * its sequence number is counted and analysis sees the gap. */
static uint8_t  g_scratch[IS18_FRAME_DATA_BYTES];

static void
publish (void)
{
    /* Make counter writes visible to core 0 before it reads them. */
    __asm volatile("dmb" ::: "memory");
}

static void
crs_dv_handler (UINT intno)
{
    (void) intno;
    if (rmii_hw_isr())
    {
        /* Wake-up requests are counted, so one arriving while the task is
         * busy is not lost. Legal from an interrupt handler. */
        (void) tk_wup_tsk(g_task_id);
    }
}

static bool
is_goose_or_sv (const uint8_t * frame, size_t length)
{
    size_t   offset    = ETHERTYPE_OFFSET;
    uint32_t tags      = 0u;
    uint16_t ethertype = 0u;

    while (offset + 2u <= length)
    {
        ethertype = (uint16_t) (((uint16_t) frame[offset] << 8u) |
                                frame[offset + 1u]);
        if ((ethertype == ETHERTYPE_VLAN_8021Q ||
             ethertype == ETHERTYPE_VLAN_8021AD ||
             ethertype == ETHERTYPE_VLAN_QINQ) &&
            tags < MAXIMUM_VLAN_TAGS)
        {
            offset += VLAN_TAG_BYTES;
            ++tags;
            continue;
        }
        return ethertype == ETHERTYPE_GOOSE || ethertype == ETHERTYPE_SV;
    }
    return false;
}

static bool
header_has_data (const uint8_t * data, size_t length)
{
    size_t index = 0u;

    for (index = 0u; index < length && index < ETHERNET_HEADER_BYTES; ++index)
    {
        if (data[index] != 0u)
        {
            return true;
        }
    }
    return false;
}

static void
handle_capture (const rmii_hw_capture_t * capture)
{
    is18_frame_block_t * block   = NULL;
    uint8_t *            target  = g_scratch;
    size_t               decoded = 0u;
    size_t               length  = 0u;
    uint64_t             started = 0u;
    uint32_t             elapsed = 0u;
    ER                   er      = E_OK;

    if (capture->word_count == 0u)
    {
        return; /* spurious edge, nothing captured */
    }
    er = tk_get_mpf(g_pool_id, (void **) &block, TMO_POL);
    if (er == E_OK)
    {
        target = block->data;
    }
    else
    {
        block = NULL;
    }

    started = rmii_hw_time_us();
    decoded = rmii_frame_decode_samples(capture->samples, capture->word_count,
                                        target, IS18_FRAME_DATA_BYTES);
    length  = decoded != 0u ? rmii_frame_find_length(target, decoded) : 0u;
    elapsed = (uint32_t) (rmii_hw_time_us() - started);
    g_rmii_capture_stats.decode_last_us = elapsed;
    if (elapsed > g_rmii_capture_stats.decode_max_us)
    {
        g_rmii_capture_stats.decode_max_us = elapsed;
    }

    if (length < ETHERNET_HEADER_BYTES)
    {
        if (header_has_data(target, decoded))
        {
            ++g_rmii_capture_stats.bad_crc;
        }
    }
    else
    {
        ++g_rmii_capture_stats.rx_frames;
        if (!is_goose_or_sv(target, length))
        {
            ++g_rmii_capture_stats.non_iec_dropped;
        }
        else
        {
            ++g_sequence; /* every GOOSE/SV frame takes a number */
            g_rmii_capture_stats.last_seq = g_sequence;
            if (block == NULL)
            {
                ++g_rmii_capture_stats.pool_empty; /* analysis sees a gap */
            }
            else
            {
                block->seq          = g_sequence;
                block->timestamp_us = capture->timestamp_us;
                block->length       = (uint16_t) length;
                if (tk_snd_mbx(g_mailbox_id, &block->header) == E_OK)
                {
                    block = NULL; /* now owned by Stream Analysis */
                }
            }
        }
    }
    if (block != NULL)
    {
        (void) tk_rel_mpf(g_pool_id, block);
    }
}

static void
capture_task (INT stacd, void * exinf)
{
    T_DINT            dint      = {0};
    rmii_hw_capture_t capture   = {0};
    uint32_t          phy_addr  = 0u;
    uint64_t          next_poll = 0u;
    ER                er        = E_OK;

    (void) stacd;
    (void) exinf;

    if (!rmii_hw_phy_init(&phy_addr))
    {
        /* FR10: no PHY, no monitoring. Keep the heartbeat alive so the
         * Health Monitor reports the fault instead of resetting forever. */
        for (;;)
        {
            ++g_rmii_capture_stats.heartbeat;
            publish();
            tm_printf((UB *) "capture: PHY not found on MDIO\n");
            (void) tk_dly_tsk(PHY_FAULT_REPORT_MS);
        }
    }
    g_rmii_capture_stats.phy_found   = 1u;
    g_rmii_capture_stats.phy_address = phy_addr;

    /* Register the handler, then enable it in THIS core's NVIC only. The
     * vector table is shared by both cores; the enable bit is per core. */
    dint.intatr = TA_HLNG;
    dint.inthdr = (FP) crs_dv_handler;
    er          = tk_def_int(rmii_hw_irq_number(), &dint);
    if (er != E_OK || !rmii_hw_rx_start())
    {
        tm_printf((UB *) "capture: receiver start failed er=%d\n", (INT) er);
        (void) tk_slp_tsk(TMO_FEVR);
    }
    EnableInt(rmii_hw_irq_number(), IS18_CRS_DV_INT_LEVEL);
#if TK_SUPPORT_SMP
    tm_printf((UB *) "capture: running on processor %d, PHY at %d\n",
              (INT) tk_get_prc(), (INT) phy_addr);
#endif

    for (;;)
    {
        /* Woken by the ISR, or after IS18_CAPTURE_IDLE_MS to poll the PHY
         * and keep the heartbeat moving when there is no traffic. */
        (void) tk_slp_tsk(IS18_CAPTURE_IDLE_MS);
        ++g_rmii_capture_stats.heartbeat;
        while (rmii_hw_next_capture(&capture))
        {
            handle_capture(&capture);
            rmii_hw_release_capture(capture.buffer);
        }
        /* Time based, so the link is polled even under constant traffic.
         * MDIO is bit banged (about 0.3 ms); the ISR can still preempt it. */
        if (rmii_hw_time_us() >= next_poll)
        {
            next_poll = rmii_hw_time_us() + LINK_POLL_US;
            g_rmii_capture_stats.link_up = rmii_hw_link_up() ? 1u : 0u;
        }
        g_rmii_capture_stats.isr_count  = rmii_hw_isr_count();
        g_rmii_capture_stats.rx_overrun = rmii_hw_overrun_count();
        publish();
    }
}

ID
rmii_capture_task_create (ID frame_pool_id, ID frame_mailbox_id)
{
    T_CTSK ctsk = {0};

    g_pool_id    = frame_pool_id;
    g_mailbox_id = frame_mailbox_id;
    ctsk.tskatr  = TA_HLNG | TA_RNG0 | TA_ASSPRC;
    ctsk.assprc  = TP_PRC2; /* core 1, alone */
    ctsk.task    = (FP) capture_task;
    ctsk.itskpri = IS18_PRI_CAPTURE;
    ctsk.stksz   = IS18_STACK_CAPTURE;
    g_task_id    = tk_cre_tsk(&ctsk);
    return g_task_id;
}
