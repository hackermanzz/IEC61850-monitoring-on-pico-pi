/** @file task_producer.c
 *
 * @brief Capture producer task: turns finished RMII captures into checked
 * capture frames for the analysis module, and publishes capture health.
 *
 * @par
 * Each capture is decoded and FCS-checked. Only GOOSE and SV frames are
 * kept; each is numbered, copied into a pool frame and handed over to the
 * analysis module. Capture statistics go to the health monitor.
 *
 * @par
 * With MONITOR_SYNTHETIC the task sends small artificial frames instead, to
 * test frame storage and ownership without Ethernet hardware.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../analysis/analysis.h"
#include "../health/health.h"
#include "../monitor_config.h"
#include "../monitor_stacks.h"
#include "../monitor_time.h"
#include "capture.h"
#include "capture_frame.h"
#include "rmii_frame.h"
#include "task_producer.h"

#if !MONITOR_SYNTHETIC
#include "rmii_capture_hw.h"
#endif

// Status reporting. The source number identifies the capture module to the
// health monitor and to the stack report.
//
#define STATUS_SOURCE_CAPTURE (2u)
#define STATUS_PERIOD_US      (100000u)
#define LINK_POLL_PERIOD_US   (100000u)
#define PHY_DIAG_PERIOD_US    (2000000u)
#define TASK_SLEEP_MS         (10)
#define SYNTHETIC_PERIOD_MS   (300)
#define CRS_DV_IRQ_PRIORITY   (1)

// Ethernet framing used to recognize IEC 61850 GOOSE and SV frames.
//
#define ETHERNET_HEADER_BYTES (14u)
#define ETHERTYPE_OFFSET      (12u)
#define ETHERTYPE_BYTES       (2u)
#define VLAN_TAG_BYTES        (4u)
#define MAX_VLAN_TAGS         (2u)
#define BITS_PER_BYTE         (8u)
#define ETHERTYPE_GOOSE       (0x88B8u)
#define ETHERTYPE_SV          (0x88BAu)
#define ETHERTYPE_VLAN        (0x8100u)
#define ETHERTYPE_QINQ        (0x88A8u)
#define ETHERTYPE_QINQ_LEGACY (0x9100u)

static monitor_capture_stats_t g_stats           = {0};
static monitor_capture_stats_t g_published_stats = {0};
static uint32_t                g_sequence_number = 0u;
static uint64_t                g_last_report_us  = 0u;

// Guards g_published_stats; created once by task_producer_init().
//
static ID gh_stats_lock = 0;

#if !MONITOR_SYNTHETIC
static uint8_t  g_scratch[CAPTURE_FRAME_CAPACITY + RMII_FRAME_FCS_BYTES];
static uint64_t g_last_link_poll_us     = 0u;
static uint64_t g_last_phy_diag_us      = 0u;
static uint64_t g_last_start_attempt_us = 0u;

// Read by the CRS_DV ISR to wake the task.
//
static ID volatile gh_capture_task = 0;
#endif

static void              producer_task(INT start_code, void * p_exinf);
static void              publish_status(void);
static capture_frame_t * acquire_frame(void);
static void              release_frame(capture_frame_t * p_frame);
static void              send_frame(capture_frame_t * p_frame);
static bool              send_copy(uint8_t const * p_data, uint16_t length,
                                   uint64_t timestamp_us);
#if MONITOR_SYNTHETIC
static void synthetic_loop(void);
#else
static void     capture_loop(void);
static void     drain_captures(rmii_capture_hw_capture_t * p_capture);
static void     handle_capture(rmii_capture_hw_capture_t const * p_capture);
static size_t   decode_capture(rmii_capture_hw_capture_t const * p_capture);
static bool     is_iec61850_frame(uint8_t const * p_data, size_t length);
static bool     is_vlan_tag(uint32_t ether_type);
static void     service_capture_status(void);
static void     start_capture_hardware(void);
static uint32_t start_receiver(void);
static bool     is_retryable_fault(uint32_t fault);
static void     crs_dv_isr(UINT interrupt_number);
#endif

/*!
 * @brief Create the statistics lock.
 *
 * @return E_OK, or the kernel error code.
 */
ER
task_producer_init (void)
{
    T_CMTX lock   = {0};
    ER     result = E_OK;

    lock.mtxatr   = TA_INHERIT;
    gh_stats_lock = tk_cre_mtx(&lock);

    if (gh_stats_lock < E_OK)
    {
        result = gh_stats_lock;
    }

    return (result);
}

/*!
 * @brief Create and start the capture producer task.
 *
 * @return The task ID, or a negative kernel error code.
 */
ID
task_producer_start (void)
{
    return (app_start_task_ex(producer_task, MONITOR_CAPTURE_PRIORITY, TP_PRC2,
                              MONITOR_CAPTURE_STACK));
}

/*!
 * @brief Copy the statistics the task last published.
 *
 * @param[out] p_stats Receives the statistics.
 *
 * @return E_OK, or the kernel error code.
 */
ER
task_producer_read_stats (monitor_capture_stats_t * p_stats)
{
    ER result = E_PAR;

    if (NULL != p_stats)
    {
        result = tk_loc_mtx(gh_stats_lock, TMO_FEVR);

        if (E_OK == result)
        {
            *p_stats = g_published_stats;
            result   = tk_unl_mtx(gh_stats_lock);
        }
    }

    return (result);
}

/*!
 * @brief The capture producer task.
 *
 * @param[in] start_code The kernel start code (unused).
 * @param[in] p_exinf    The kernel extended information (unused).
 */
static void
producer_task (INT start_code, void * p_exinf)
{
    // The casts mark parameters the kernel task signature requires but this
    // task does not use.
    (void) start_code;
    (void) p_exinf;

#if MONITOR_SYNTHETIC
    synthetic_loop();
#else
    capture_loop();
#endif
}

/*!
 * @brief Publish the capture statistics to readers and the health monitor.
 */
static void
publish_status (void)
{
    monitor_status_message_t message = {0};

    g_stats.heartbeat++;

    // Never block the capture task: if a reader holds the lock, the copy is
    // simply updated at the next report.
    if (E_OK == tk_loc_mtx(gh_stats_lock, TMO_POL))
    {
        g_published_stats = g_stats;

        // Unlocking a mutex this task holds cannot fail.
        (void) tk_unl_mtx(gh_stats_lock);
    }
    message.source       = STATUS_SOURCE_CAPTURE;
    message.generated_us = monitor_time_us();
    message.data.capture = g_stats;

    // A full status queue only delays the next report, so the result is not
    // needed.
    (void) health_publish(&message);

    g_last_report_us = monitor_time_us();
    MONITOR_STACK_REPORT(STATUS_SOURCE_CAPTURE);
}

/*!
 * @brief Take a free frame from the pool, counting failures.
 *
 * @return The frame, or NULL if none is free.
 */
static capture_frame_t *
acquire_frame (void)
{
    bool                    b_cleanup_failed = false;
    capture_frame_t * const p_frame = capture_frame_acquire(&b_cleanup_failed);

    if (b_cleanup_failed)
    {
        g_stats.cleanup_failed++;
    }

    if (NULL == p_frame)
    {
        g_stats.pool_empty++;
    }

    return (p_frame);
}

/*!
 * @brief Give a frame back to the pool, counting failures.
 *
 * @param[in] p_frame The frame.
 */
static void
release_frame (capture_frame_t * p_frame)
{
    if (E_OK != capture_frame_release(p_frame))
    {
        g_stats.cleanup_failed++;
    }
}

/*!
 * @brief Hand a filled frame over to the analysis module.
 *
 * @par
 * A successful hand-over transfers ownership of the frame to the analysis
 * task, so the frame must not be touched afterwards.
 *
 * @param[in] p_frame The frame.
 */
static void
send_frame (capture_frame_t * p_frame)
{
    if (E_OK != analysis_submit_frame(p_frame))
    {
        g_stats.send_failed++;
        release_frame(p_frame);
    }
}

/*!
 * @brief Copy bytes into a pool frame with the current sequence number and
 *        send it.
 *
 * @param[in] p_data       The frame bytes.
 * @param[in] length       The number of bytes, at most
 *                         CAPTURE_FRAME_CAPACITY.
 * @param[in] timestamp_us The frame end time.
 *
 * @return True if a pool frame was available.
 */
static bool
send_copy (uint8_t const * p_data, uint16_t length, uint64_t timestamp_us)
{
    capture_frame_t * const p_frame = acquire_frame();

    if (NULL != p_frame)
    {
        p_frame->sequence_number  = g_sequence_number;
        p_frame->timestamp_us     = timestamp_us;
        p_frame->valid_byte_count = length;
        memcpy(p_frame->frame_data, p_data, length);
        send_frame(p_frame);
    }

    return (NULL != p_frame);
}

#if MONITOR_SYNTHETIC

/*!
 * @brief Send one artificial frame per period, for ever.
 */
static void
synthetic_loop (void)
{
    // NOTE: Deliberately artificial frames. They test frame storage and
    // ownership, not Ethernet.
    static uint8_t const synthetic_frame[] = {0xDEu, 0xADu, 0xBEu, 0xEFu};

    for (;;)
    {
        g_sequence_number++;
        g_stats.last_seq = g_sequence_number;

        // The cast is safe: the array holds four bytes.
        if (send_copy(synthetic_frame, (uint16_t) sizeof(synthetic_frame),
                      monitor_time_us()))
        {
            g_stats.rx_frames++;
        }

        publish_status();
        (void) tk_dly_tsk(SYNTHETIC_PERIOD_MS);
    }
}

#else /* !MONITOR_SYNTHETIC */

/*!
 * @brief Start the capture hardware and process captures, for ever.
 */
static void
capture_loop (void)
{
    rmii_capture_hw_capture_t capture = {0};

    gh_capture_task = tk_get_tid();
    start_capture_hardware();

    for (;;)
    {
        // A missing PHY or a temporary resource failure need not require a
        // reboot. Keep reporting health between bounded start-up retries.
        // A placeholder pin map never attempts hardware access.
        if (is_retryable_fault(g_stats.fault)
            && ((monitor_time_us() - g_last_start_attempt_us)
                >= MONITOR_CAPTURE_RETRY_US))
        {
            start_capture_hardware();
        }

        if (CAPTURE_FAULT_NONE == g_stats.fault)
        {
            drain_captures(&capture);
        }
        else if ((monitor_time_us() - g_last_report_us) >= STATUS_PERIOD_US)
        {
            publish_status();
        }
        else
        {
            // Not yet time to report the fault again.
        }

        // The wake-up from the ISR or the time-out both simply continue the
        // loop, so the result is not needed.
        (void) tk_slp_tsk(TASK_SLEEP_MS);
    }
}

/*!
 * @brief Process every finished capture, then service status.
 *
 * @param[out] p_capture Working storage for one capture.
 */
static void
drain_captures (rmii_capture_hw_capture_t * p_capture)
{
    while (rmii_capture_hw_next_capture(p_capture))
    {
        handle_capture(p_capture);
        rmii_capture_hw_release(p_capture->buffer);
        service_capture_status();
    }

    service_capture_status();
}

/*!
 * @brief Decode one capture and send it on if it is a valid GOOSE or SV
 *        frame.
 *
 * @param[in] p_capture The finished capture.
 */
static void
handle_capture (rmii_capture_hw_capture_t const * p_capture)
{
    size_t const length = decode_capture(p_capture);

    if ((length < ETHERNET_HEADER_BYTES) || (length > CAPTURE_FRAME_CAPACITY))
    {
        g_stats.bad_crc++;
    }
    else
    {
        g_stats.rx_frames++;

        if (!is_iec61850_frame(g_scratch, length))
        {
            g_stats.non_iec_dropped++;
        }
        else
        {
            g_sequence_number++;
            g_stats.last_seq = g_sequence_number;

            // The cast is safe: length is at most CAPTURE_FRAME_CAPACITY,
            // which fits in 16 bits. A missing pool frame is already counted.
            (void) send_copy(g_scratch, (uint16_t) length,
                             p_capture->timestamp_us);
        }
    }
}

/*!
 * @brief Decode a capture into g_scratch and find the frame length.
 *
 * @param[in] p_capture The finished capture.
 *
 * @return The frame length without the FCS, or 0 if no FCS matched.
 */
static size_t
decode_capture (rmii_capture_hw_capture_t const * p_capture)
{
    uint64_t const start_us = monitor_time_us();
    size_t const   decoded =
        rmii_frame_decode_samples(p_capture->p_samples, p_capture->word_count,
                                  g_scratch, sizeof(g_scratch));

    // The casts keep 16 bits for the statistics. A capture holds at most
    // 3900 words and g_scratch 1522 bytes, so no bits are lost.
    g_stats.sample_words_last  = (uint16_t) p_capture->word_count;
    g_stats.decoded_bytes_last = (uint16_t) decoded;

    if (0u == p_capture->word_count)
    {
        g_stats.short_captures++;
    }

    size_t const length = rmii_frame_find_length(g_scratch, decoded);

    // The cast is safe: decoding one capture takes far less than 2^32 us.
    uint32_t const elapsed_us = (uint32_t) (monitor_time_us() - start_us);

    g_stats.decode_last_us = elapsed_us;

    if (elapsed_us > g_stats.decode_max_us)
    {
        g_stats.decode_max_us = elapsed_us;
    }

    return (length);
}

/*!
 * @brief Check for a GOOSE or SV EtherType, after at most two VLAN tags.
 *
 * @param[in] p_data The frame bytes.
 * @param[in] length The frame length.
 *
 * @return True for a GOOSE or SV frame.
 */
static bool
is_iec61850_frame (uint8_t const * p_data, size_t length)
{
    bool     b_is_iec61850 = false;
    bool     b_is_done     = false;
    size_t   offset        = ETHERTYPE_OFFSET;
    uint32_t tags          = 0u;

    while (!b_is_done && ((offset + ETHERTYPE_BYTES) <= length))
    {
        // The cast widens the byte before shifting; no bits are lost.
        uint32_t const ether_type =
            (((uint32_t) p_data[offset]) << BITS_PER_BYTE)
            | p_data[offset + 1u];

        if ((ETHERTYPE_GOOSE == ether_type) || (ETHERTYPE_SV == ether_type))
        {
            b_is_iec61850 = true;
            b_is_done     = true;
        }
        else if ((MAX_VLAN_TAGS == tags) || !is_vlan_tag(ether_type))
        {
            b_is_done = true;
        }
        else
        {
            offset += VLAN_TAG_BYTES;
            tags++;
        }
    }

    return (b_is_iec61850);
}

/*!
 * @brief Check whether an EtherType is a VLAN tag.
 *
 * @param[in] ether_type The EtherType.
 *
 * @return True for an 802.1Q, 802.1ad or legacy QinQ tag.
 */
static bool
is_vlan_tag (uint32_t ether_type)
{
    return ((ETHERTYPE_VLAN == ether_type) || (ETHERTYPE_QINQ == ether_type)
            || (ETHERTYPE_QINQ_LEGACY == ether_type));
}

/*!
 * @brief Poll the link, read PHY diagnostics and publish status when each
 *        is due.
 */
static void
service_capture_status (void)
{
    uint64_t const now_us = monitor_time_us();

    // NOTE: Separate deadlines keep status publication from postponing link
    // polling indefinitely while the ready-buffer loop stays busy.
    if ((now_us - g_last_link_poll_us) >= LINK_POLL_PERIOD_US)
    {
        g_stats.link_up     = rmii_capture_hw_is_link_up();
        g_last_link_poll_us = monitor_time_us();
    }

    if ((now_us - g_last_phy_diag_us) >= PHY_DIAG_PERIOD_US)
    {
        rmii_capture_hw_read_phy_diag(&g_stats.phy);
        g_last_phy_diag_us = monitor_time_us();
    }

    if ((now_us - g_last_report_us) >= STATUS_PERIOD_US)
    {
        g_stats.isr_count  = rmii_capture_hw_isr_count();
        g_stats.rx_overrun = rmii_capture_hw_overrun_count();
        g_stats.dma_full   = rmii_capture_hw_dma_full_count();
        publish_status();
    }
}

/*!
 * @brief Find the PHY and start the receiver, recording any fault.
 */
static void
start_capture_hardware (void)
{
    bool const b_is_recovering = (CAPTURE_FAULT_NONE != g_stats.fault);
    uint32_t   phy_address     = 0u;

    g_stats.start_attempts++;

    if (0 == MONITOR_PINS_CONFIGURED)
    {
        g_stats.fault = CAPTURE_FAULT_NO_PINS;
    }
    else if (!rmii_capture_hw_phy_init(&phy_address))
    {
        g_stats.phy_found = 0u;
        g_stats.link_up   = 0u;
        g_stats.fault     = CAPTURE_FAULT_NO_PHY;
    }
    else
    {
        g_stats.phy_found   = 1u;
        g_stats.phy_address = phy_address;
        g_stats.fault       = start_receiver();

        if ((CAPTURE_FAULT_NONE == g_stats.fault) && b_is_recovering)
        {
            g_stats.recoveries++;
        }
    }

    g_last_start_attempt_us = monitor_time_us();
}

/*!
 * @brief Install the CRS_DV interrupt handler and start the receiver.
 *
 * @return CAPTURE_FAULT_NONE, or CAPTURE_FAULT_START on failure.
 */
static uint32_t
start_receiver (void)
{
    T_DINT   irq_definition = {0};
    uint32_t fault          = CAPTURE_FAULT_START;

    irq_definition.intatr = TA_HLNG;

    // The cast converts the ISR to the kernel's generic handler type, as
    // tk_def_int() requires.
    irq_definition.inthdr = (FP) crs_dv_isr;

    if ((E_OK == tk_def_int(rmii_capture_hw_irq_number(), &irq_definition))
        && rmii_capture_hw_rx_start())
    {
        fault = CAPTURE_FAULT_NONE;
        EnableInt(rmii_capture_hw_irq_number(), CRS_DV_IRQ_PRIORITY);
    }

    return (fault);
}

/*!
 * @brief Report whether a start-up fault is worth retrying.
 *
 * @param[in] fault The fault code.
 *
 * @return True for a missing PHY or a resource failure.
 */
static bool
is_retryable_fault (uint32_t fault)
{
    return ((CAPTURE_FAULT_NO_PHY == fault) || (CAPTURE_FAULT_START == fault));
}

/*!
 * @brief CRS_DV interrupt: finish the capture and wake the task.
 *
 * @par
 * NOTE: Installed with TA_HLNG, so the kernel's interrupt entry calls this
 * as an ordinary C function; no compiler ISR keyword is needed (rule 6.5.a).
 *
 * @param[in] interrupt_number The interrupt number (unused).
 */
static void
crs_dv_isr (UINT interrupt_number)
{
    // The cast marks a parameter the handler signature requires but this
    // handler does not use.
    (void) interrupt_number;

    if (rmii_capture_hw_isr())
    {
        // A failed wake-up only delays decoding until the task's next timed
        // wake-up, so the result is not needed.
        (void) tk_wup_tsk(gh_capture_task);
    }
}

#endif /* !MONITOR_SYNTHETIC */

/*** end of file ***/
