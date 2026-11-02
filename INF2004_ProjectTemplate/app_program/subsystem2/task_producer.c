#include "subsystem2.h"
#include "../monitor_stacks.h"
#include "capture_frame.h"
#include "rmii_frame.h"
#include "../subsystem3/subsystem3.h"
#include "../subsystem4/subsystem4.h"
#include "../monitor_time.h"
#include <string.h>
#if !MONITOR_SYNTHETIC
#include "rmii_capture_hw.h"
#endif

static monitor_capture_stats_t stats;
static uint32_t sequence;
static uint64_t last_report;
#if !MONITOR_SYNTHETIC
static uint8_t scratch[CAPTURE_FRAME_CAPACITY + RMII_FRAME_FCS_BYTES];
#endif

static void publish_status(void)
{
    monitor_status_message_t message = {0};
    stats.heartbeat++;
    message.source = 2;
    message.generated_us = monitor_time_us();
    message.data.capture = stats;
    (void)subsystem4_publish(&message);
    last_report = monitor_time_us();
    MONITOR_STACK_REPORT(2);
}

static capture_frame_t *acquire_frame(void)
{
    // Initializes the struct to NULL
    capture_frame_t *frame = NULL;
    ER er = tk_wai_sem(sem_slots, 1, TMO_POL);
    if (er != E_OK) return NULL;
    
    er = tk_get_mpf(mpf_samples, (void **)&frame, TMO_POL);
    if (er != E_OK) {
        if (tk_sig_sem(sem_slots, 1) != E_OK) stats.cleanup_failed++;
        return NULL;
    }
    return frame;
}

static void release_frame(capture_frame_t *frame)
{
    if (tk_rel_mpf(mpf_samples, frame) != E_OK) stats.cleanup_failed++;
    else if (tk_sig_sem(sem_slots, 1) != E_OK) stats.cleanup_failed++;
}

static void send_frame(capture_frame_t *frame)
{
    if (tk_snd_mbx(mbx_samples, &frame->header) != E_OK) {
        stats.send_failed++;
        release_frame(frame);
    }
    /* Successful send transfers ownership; never touch frame afterward. */
}

#if !MONITOR_SYNTHETIC
static ID capture_task_id;
static uint64_t last_link_poll;
static uint64_t last_phy_diag;
static uint64_t last_start_attempt;
static void capture_irq(UINT intno)
{
    (void)intno;
    if (rmii_capture_hw_isr()) (void)tk_wup_tsk(capture_task_id);
}

static bool is_iec(const uint8_t *data, size_t length)
{
    size_t off = 12;
    for (unsigned tags = 0; off + 2 <= length; tags++) {
        uint16_t type = (uint16_t)((uint16_t)data[off] << 8 | data[off + 1]);
        if (type == 0x88b8 || type == 0x88ba) return true;
        if (tags == 2 || (type != 0x8100 && type != 0x88a8 && type != 0x9100))
            return false;
        off += 4;
    }
    return false;
}

static void handle_capture(const rmii_capture_hw_capture_t *capture)
{
    capture_frame_t *frame;
    uint64_t start = monitor_time_us();
    size_t decoded = rmii_frame_decode_samples(capture->p_samples,
                         capture->word_count, scratch, sizeof(scratch));
    stats.sample_words_last = (uint16_t)capture->word_count;
    stats.decoded_bytes_last = (uint16_t)decoded;
    if (capture->word_count == 0) stats.short_captures++;
    size_t length = rmii_frame_find_length(scratch, decoded);
    uint32_t elapsed = (uint32_t)(monitor_time_us() - start);
    stats.decode_last_us = elapsed;
    if (elapsed > stats.decode_max_us) stats.decode_max_us = elapsed;
    if (length < 14 || length > CAPTURE_FRAME_CAPACITY) {
        stats.bad_crc++;
        return;
    }
    stats.rx_frames++;
    if (!is_iec(scratch, length)) { stats.non_iec_dropped++; return; }
    stats.last_seq = ++sequence;
    frame = acquire_frame();
    if (frame == NULL) { stats.pool_empty++; return; }
    frame->seqNum = sequence;
    frame->timestamp_us = capture->timestamp_us;
    frame->valid_byte_count = (uint16_t)length;
    memcpy(frame->frame_data, scratch, length);
    send_frame(frame);
}

static void service_capture_status(void)
{
    uint64_t now = monitor_time_us();
    /* Separate deadlines: status publication must not indefinitely postpone
     * link polling while the ready-buffer loop remains busy. */
    if (now - last_link_poll >= 100000) {
        stats.link_up = rmii_capture_hw_is_link_up();
        last_link_poll = monitor_time_us();
    }
    if (now - last_phy_diag >= 2000000) {
        rmii_capture_hw_read_phy_diag(&stats.phy);
        last_phy_diag = monitor_time_us();
    }
    if (now - last_report >= 100000) {
        stats.isr_count = rmii_capture_hw_isr_count();
        stats.rx_overrun = rmii_capture_hw_overrun_count();
        stats.dma_full = rmii_capture_hw_dma_full_count();
        publish_status();
    }
}

static void start_capture_hardware(void)
{
    T_DINT dint = {0};
    uint32_t phy;
    bool recovering = stats.fault != 0;
    stats.start_attempts++;
    if (!MONITOR_PINS_CONFIGURED) stats.fault = 3;
    else if (!rmii_capture_hw_phy_init(&phy)) {
        stats.phy_found = 0;
        stats.link_up = 0;
        stats.fault = 1;
    } else {
        stats.phy_found = 1;
        stats.phy_address = phy;
        dint.intatr = TA_HLNG;
        dint.inthdr = (FP)capture_irq;
        ER er = tk_def_int(rmii_capture_hw_irq_number(), &dint);
        if (er != E_OK || !rmii_capture_hw_rx_start()) stats.fault = 2;
        else {
            stats.fault = 0;
            if (recovering) stats.recoveries++;
            EnableInt(rmii_capture_hw_irq_number(), 1);
        }
    }
    last_start_attempt = monitor_time_us();
}
#endif

EXPORT void producer_task(INT stacd, void *exinf)
{
    (void)stacd;
    (void)exinf;
#if MONITOR_SYNTHETIC
    /* Deliberately artificial: tests storage/ownership, not Ethernet. */
    for (;;) {
        capture_frame_t *frame = acquire_frame();
        stats.last_seq = ++sequence;
        if (frame != NULL) {
            frame->seqNum = sequence;
            frame->timestamp_us = monitor_time_us();
            frame->valid_byte_count = 4;
            memcpy(frame->frame_data, "\xde\xad\xbe\xef", 4);
            stats.rx_frames++;
            send_frame(frame);
        } else stats.pool_empty++;
        publish_status();
        tk_dly_tsk(S2_PERIOD_MS);
    }
#else
    rmii_capture_hw_capture_t capture;
    capture_task_id = tk_get_tid();
    start_capture_hardware();
    for (;;) {
        /* A missing PHY or a temporary resource failure need not require a
         * reboot. Keep reporting health between bounded startup retries.
         * A placeholder pin map deliberately never attempts hardware access. */
        if ((stats.fault == 1 || stats.fault == 2) &&
            monitor_time_us() - last_start_attempt >= MONITOR_CAPTURE_RETRY_US)
            start_capture_hardware();
        if (!stats.fault) {
            while (rmii_capture_hw_next_capture(&capture)) {
                handle_capture(&capture);
                rmii_capture_hw_release(capture.buffer);
                service_capture_status();
            }
            service_capture_status();
        } else if (monitor_time_us() - last_report >= 100000) publish_status();
        tk_slp_tsk(10);
    }
#endif
}
