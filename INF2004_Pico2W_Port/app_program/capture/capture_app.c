/** @file capture_app.c
 * @brief Two-core capture bring-up with one console/MDIO owner on Core 0.
 */
#include "capture_app.h"

#if PORT_CAPTURE
#include <inttypes.h>  /* Portable diagnostic formats. */
#include <stdatomic.h> /* Publish worker status and raw diagnostic snapshot. */
#include <stdio.h>     /* Only the Core 0 task prints. */
#include "hardware/clocks.h" /* Record system clock for timing diagnosis. */
#include "hardware/sync.h"   /* WFE waits for ISR's SEV notification. */
#include "pico/time.h"       /* Monotonic report intervals. */
#include "capture_decode.h"
#include "capture_hw.h"
#include "capture_pipe.h"
#include "capture_phy.h"
#if !PORT_STORAGE
#include "capture_test.h" /* Core 0-only marked UDP batch accounting. */
#endif
#if PORT_STORAGE
#include "../storage/storage.h"
#endif
#include "mdio_phy.h"
#if PORT_DETECTION
#include "../health/detection.h"
#include "../health/console.h"
#include "hardware/watchdog.h"
#endif
#if PORT_ANALYSIS
#include "../analysis/analysis_port.h"
#include "kernel_port.h"
#include "../analysis/iec_rules.h"
#endif

static uint32_t    g_worker_stack[1024] __attribute__((aligned(8)));
static atomic_int  g_worker_status;
static atomic_uint g_decode_counts[CAPTURE_DECODE_INVALID + 1u];
static atomic_uint g_prefix_ready;
#if PORT_ANALYSIS
static atomic_uint g_decode_max_us;
#endif
static uint32_t             g_prefix[16];
static uint32_t             g_prefix_count;
static uint32_t             g_prefix_words;
static uint32_t             g_tail[16];
static uint32_t             g_tail_count;
static uint32_t             g_crs_high_samples;
static uint32_t             g_rxd_set_bits;
static capture_raw_t        g_first_meta;
static capture_signal_run_t g_signal_runs[CAPTURE_TRACE_MAX_RUNS];
static size_t               g_signal_run_count;
#if !PORT_STORAGE
static capture_test_tracker_t g_test_tracker;
#endif

static void capture_app_worker(INT code, void * p_exinf);
static bool capture_app_phy(uint8_t * p_address);
static bool capture_app_link(uint8_t address, uint16_t * p_bmsr,
                             uint16_t * p_special);
static void capture_app_process(const capture_raw_t * p_raw);
static void capture_app_report(uint32_t delivered);
#if !PORT_STORAGE
static void capture_app_report_tests(void);

/** @brief Report only marked batches; background traffic cannot inflate them.
 */
static void
capture_app_report_tests (void)
{
    uint32_t                   index = 0u;
    const capture_test_run_t * p_run = NULL;

    for (index = 0u; CAPTURE_TEST_RUNS > index; index++)
    {
        p_run = &g_test_tracker.runs[index];
        if (p_run->b_used)
        {
            printf("TEST run=%" PRIu32 " src=%u.%u.%u.%u unique=%" PRIu32
                   " expected=%" PRIu32 " missing=%" PRIu32 "\n",
                   p_run->run_id, p_run->source_ip[0], p_run->source_ip[1],
                   p_run->source_ip[2], p_run->source_ip[3], p_run->unique,
                   p_run->expected, p_run->expected - p_run->unique);
            printf(
                "TEST run=%" PRIu32 " duplicates=%" PRIu32 " reordered=%" PRIu32
                " conflicts=%" PRIu32 " complete=%u\n",
                p_run->run_id, p_run->duplicates, p_run->reordered,
                p_run->conflicts,
                ((p_run->unique == p_run->expected) && (0u == p_run->conflicts))
                    ? 1u
                    : 0u);
        }
    }
    printf("TEST rejected=%" PRIu32 " run_capacity_drops=%" PRIu32 "\n",
           g_test_tracker.rejected, g_test_tracker.run_capacity_drops);
}

#endif /* !PORT_STORAGE */

/** @brief Advertise only 10BASE-T after checking the actual PHY identity. */
static bool
capture_app_phy (uint8_t * p_address)
{
    uint32_t             address      = 0u;
    uint32_t             attempt      = 0u;
    uint32_t             responses    = 0u;
    mdio_phy_id_t        identity     = {0};
    capture_phy_result_t result       = {0};
    bool                 b_configured = false;

    mdio_phy_init();
    /* A one-shot discovery failure must not hide startup readiness. These
     * bounded retries only read IDs; never configure an unidentified device.
     */
    for (attempt = 1u; 5u >= attempt; attempt++)
    {
        responses = 0u;
        for (address = 0u; 32u > address; address++)
        {
            if (mdio_phy_identify((uint8_t) address, &identity))
            {
                responses++;
                printf("PHY scan addr=%" PRIu32
                       " id1=%04x id2=%04x LAN8720=%u\n",
                       address, identity.id1, identity.id2,
                       identity.b_is_lan8720 ? 1u : 0u);
                if (identity.b_is_lan8720)
                {
                    *p_address = (uint8_t) address;
                    printf("PHY addr=%" PRIu32 " id1=%04x id2=%04x\n", address,
                           identity.id1, identity.id2);
                    b_configured = capture_phy_configure(*p_address, &result);
                    printf(
                        "PHY ANAR before_ack=%u before=%04x write_half_us=10\n",
                        result.b_anar_before_read ? 1u : 0u,
                        result.anar_before);
                    printf("PHY config stage=%s ANAR_ack=%u ANAR=%04x "
                           "BMCR_ack=%u BMCR=%04x\n",
                           result.p_stage, result.b_anar_read ? 1u : 0u,
                           result.anar, result.b_bmcr_read ? 1u : 0u,
                           result.bmcr);
                    if (b_configured)
                    {
                        printf("PHY 10 Mbps advertisement verified.\n");
                    }
                    return b_configured;
                }
            }
        }
        printf("PHY discovery attempt=%" PRIu32 "/5 complete_id_reads=%" PRIu32
               " matching=0\n",
               attempt, responses);
        if (5u > attempt)
        {
            (void) tk_dly_tsk(250u);
        }
    }
    printf("PHY discovery failed: no LAN8720 identity; configuration not "
           "attempted.\n");
    return false;
}

static bool
capture_app_link (uint8_t address, uint16_t * p_bmsr, uint16_t * p_special)
{
    uint16_t discard = 0u;
    uint32_t speed   = 0u;
    bool     b_read  = mdio_phy_read(address, 1u, &discard)
                    && mdio_phy_read(address, 1u, p_bmsr)
                    && mdio_phy_read(address, 31u, p_special);

    /* BMSR link is latch-low: the second read is the current state. */
    speed = (*p_special >> 2u) & 7u;
    return b_read && (0x24u == (*p_bmsr & 0x24u))
        && ((1u == speed) || (5u == speed));
}

static void
capture_app_process (const capture_raw_t * p_raw)
{
    capture_frame_t *       p_frame = NULL;
    capture_decode_result_t result  = CAPTURE_DECODE_INVALID;
    uint32_t                index   = 0u;

    if (0u == atomic_load_explicit(&g_prefix_ready, memory_order_relaxed))
    {
        g_prefix_count =
            (16u < p_raw->word_count) ? 16u : (uint32_t) p_raw->word_count;
        g_prefix_words = (uint32_t) p_raw->word_count;
        for (index = 0u; g_prefix_count > index; index++)
        {
            g_prefix[index] = p_raw->p_words[index];
        }
        g_first_meta = *p_raw;
        g_first_meta.p_words =
            NULL; /* Metadata copy never retains raw storage. */
        g_tail_count = g_prefix_count;
        g_signal_run_count =
            capture_decode_trace(p_raw->p_words, p_raw->word_count,
                                 g_signal_runs, CAPTURE_TRACE_MAX_RUNS);
        for (index = 0u; g_tail_count > index; index++)
        {
            g_tail[index] =
                p_raw->p_words[p_raw->word_count - g_tail_count + index];
        }
        for (index = 0u; p_raw->word_count > index; index++)
        {
            g_crs_high_samples += (uint32_t) __builtin_popcount(
                p_raw->p_words[index] & 0x24924924u);
            g_rxd_set_bits += (uint32_t) __builtin_popcount(
                p_raw->p_words[index] & 0xdb6db6d8u);
        }
        /* The release/acquire pair makes the non-atomic copied prefix safe. */
        atomic_store_explicit(&g_prefix_ready, 1u, memory_order_release);
    }
    if (p_raw->b_damaged)
    {
        capture_pipe_loss();
        return;
    }
    p_frame = capture_pipe_reserve();
    if (NULL == p_frame)
    {
        return;
    }
#if PORT_ANALYSIS
    uint64_t decode_started = time_us_64();
#endif
    result = capture_decode(p_raw->p_words, p_raw->word_count, p_frame);
#if PORT_ANALYSIS
    uint64_t decode_elapsed = time_us_64() - decode_started;
    uint32_t decode_us =
        (UINT32_MAX < decode_elapsed) ? UINT32_MAX : (uint32_t) decode_elapsed;
    if (decode_us > atomic_load(&g_decode_max_us))
    {
        atomic_store(&g_decode_max_us, decode_us);
    }
#endif
    atomic_fetch_add(&g_decode_counts[result], 1u);
    if (CAPTURE_DECODE_OK == result)
    {
        p_frame->timestamp_us = p_raw->timestamp_us;
        p_frame->sequence     = p_raw->sequence;
        if (!capture_pipe_offer(p_frame))
        {
            (void) capture_pipe_cancel(p_frame);
        }
    }
    else
    {
        capture_pipe_loss();
        (void) capture_pipe_cancel(p_frame);
    }
}

static void
capture_app_worker (INT code, void * p_exinf)
{
    capture_raw_t      raw             = {0};
    capture_hw_stats_t stats           = {0};
    uint32_t           previous_pauses = 0u;
    uint32_t           previous_high   = 0u;

    (void) code;
    (void) p_exinf;
    if (!capture_hw_init())
    {
        atomic_store(&g_worker_status, -1);
        tk_ext_tsk();
    }
    atomic_store(&g_worker_status, 1);
    for (;;)
    {
#if PORT_DETECTION
        detection_heartbeat(SUPERVISION_WORKER);
#endif
        if (capture_hw_take(&raw))
        {
            capture_hw_stats(&stats);
            if ((previous_pauses != stats.pauses)
                || (previous_high != stats.armed_while_high))
            {
                capture_pipe_loss();
                previous_pauses = stats.pauses;
                previous_high   = stats.armed_while_high;
            }
            capture_app_process(&raw);
            capture_hw_release(raw.slot);
        }
        else
        {
            /* SEV in completion ISR latches an event even just before WFE.
             * No 10 ms task sleep is inserted into the frame service path.
             */
            __wfe();
        }
    }
}

static void
capture_app_report (uint32_t delivered)
{
    capture_hw_stats_t   hw   = {0};
    capture_pipe_stats_t pipe = {0};

    capture_hw_stats(&hw);
    capture_pipe_stats(&pipe);
    printf("PIO selftest=%" PRIu32 " expected=15 word=%08" PRIx32
           " end_pc=%" PRIu32 " irq=%08" PRIx32 " eof_irqs=%" PRIu32 "\n",
           hw.self_test_flags, hw.self_test_word, hw.self_test_end_pc,
           hw.self_test_irq, hw.eof_interrupts);
    printf("DMA disabled_stops=%" PRIu32 "\n", hw.dma_disabled_stops);
    printf("CAP raw=%" PRIu32 " crc_ok=%u delivered=%" PRIu32
           " no_sfd=%u short=%u bad_crc=%u large=%u invalid=%u\n",
           hw.completed, atomic_load(&g_decode_counts[CAPTURE_DECODE_OK]),
           delivered, atomic_load(&g_decode_counts[CAPTURE_DECODE_NO_SFD]),
           atomic_load(&g_decode_counts[CAPTURE_DECODE_SHORT]),
           atomic_load(&g_decode_counts[CAPTURE_DECODE_BAD_CRC]),
           atomic_load(&g_decode_counts[CAPTURE_DECODE_TOO_LARGE]),
           atomic_load(&g_decode_counts[CAPTURE_DECODE_INVALID]));
    printf("CAP full=%" PRIu32 " stall=%" PRIu32 " pauses=%" PRIu32
           " high_arm=%" PRIu32 " max_rearm_us=%" PRIu32
           "\nCAP pool_drop=%" PRIu32 " queue_drop=%" PRIu32
           " owner_error=%" PRIu32 " loss_gen=%" PRIu32 "\n",
           hw.dma_full, hw.fifo_stall, hw.pauses, hw.armed_while_high,
           hw.max_rearm_us, pipe.pool_drops, pipe.queue_drops,
           pipe.ownership_errors, pipe.loss_generation);
#if !PORT_STORAGE
    capture_app_report_tests();
#endif
#if PORT_ANALYSIS
    analysis_port_stats_t analysis = {0};
    iec_rules_stats_t     rules    = {0};
    printf("ANA stack_used=%" PRIu32 " stack_size=4096 bytes\n",
           kernel_port_initial_stack_used());
    analysis_port_stats(&analysis);
    static uint64_t previous_time        = 0u;
    static uint64_t previous_analysis_us = 0u;
    static uint32_t previous_raw         = 0u;
    static uint32_t previous_delivered   = 0u;
    static uint32_t previous_accepted    = 0u;
    uint64_t        now                  = time_us_64();
    if (0u != previous_time)
    {
        uint64_t duration = now - previous_time;
        uint32_t frames   = delivered - previous_delivered;
        if (0u != duration)
        {
            printf(
                "PERF interval_us=%" PRIu64 " raw_fps=%" PRIu32
                " delivered_fps=%" PRIu32 " iec_fps=%" PRIu32
                " avg_analysis_us=%" PRIu32 "\n",
                duration,
                (uint32_t) ((uint64_t) (hw.completed - previous_raw) * 1000000u
                            / duration),
                (uint32_t) ((uint64_t) frames * 1000000u / duration),
                (uint32_t) ((uint64_t) (analysis.accepted - previous_accepted)
                            * 1000000u / duration),
                (0u < frames)
                    ? (uint32_t) ((analysis.total_us - previous_analysis_us)
                                  / frames)
                    : 0u);
        }
    }
    previous_time        = now;
    previous_analysis_us = analysis.total_us;
    previous_raw         = hw.completed;
    previous_delivered   = delivered;
    previous_accepted    = analysis.accepted;
    printf("PERF max_decode_us=%u max_window_us=%" PRIu32
           " frame_age_us=%" PRIu32 " max_frame_age_us=%" PRIu32 "\n",
           atomic_load(&g_decode_max_us), analysis.max_window_us,
           analysis.last_frame_age_us, analysis.max_frame_age_us);
    iec_rules_stats(&rules);
    printf("ANA received=%" PRIu32 " accepted=%" PRIu32 " rejected=%" PRIu32
           " windows=%" PRIu32 " goose=%" PRIu32 " sv=%" PRIu32
           " positive=%" PRIu32 "\n",
           analysis.received, analysis.accepted, analysis.rejected,
           analysis.windows, analysis.goose_windows, analysis.sv_windows,
           analysis.positive_windows);
    printf("ANA background=%" PRIu32 " goose_seen=%" PRIu32 " sv_seen=%" PRIu32
           " iec_rejected=%" PRIu32 " oversize=%" PRIu32 "\n",
           analysis.background, analysis.goose_seen, analysis.sv_seen,
           analysis.iec_rejected, analysis.oversize);
    printf("ANA gaps=%" PRIu32 " restarts=%" PRIu32 " stream_resets=%" PRIu32
           " last_us=%" PRIu32 " max_us=%" PRIu32 " protocol=%" PRIu32
           " label=%" PRIu32 " probability_ppm=%" PRIu32 "\n",
           analysis.gaps, analysis.restarts, analysis.stream_resets,
           analysis.last_us, analysis.max_us, analysis.last_protocol,
           analysis.last_label, analysis.last_probability_ppm);
    printf("RULE shadow=1 profiles=0 frames=%" PRIu32 " flagged=%" PRIu32
           " run=%" PRIu32 " skipped=%" PRIu32 " parse_errors=%" PRIu32
           " reasons=%08" PRIx32 "\n",
           rules.frames, rules.flagged, rules.model_run, rules.model_skipped,
           rules.parse_errors, rules.seen_reasons);
#endif
#if PORT_DETECTION
    detection_report();
    console_report();
#if PORT_STORAGE
    storage_report();
#endif
#endif
}

void
capture_app_task (INT start_code, void * p_exinf)
{
    T_CTSK            worker           = {0};
    ID                task             = 0;
    uint8_t           address          = 0u;
    uint16_t          bmsr             = 0u;
    uint16_t          special          = 0u;
    uint32_t          delivered        = 0u;
    uint32_t          index            = 0u;
    uint64_t          report_at        = 0u;
    capture_frame_t * p_frame          = NULL;
    bool              b_prefix_printed = false;
    bool              b_link           = false;
#if PORT_ANALYSIS
    uint64_t analysis_check_started = 0u;
#endif

    (void) start_code;
    (void) p_exinf;
#if PORT_DETECTION
    if (!console_start())
    {
        printf("Detection console task startup failed.\n");
        tk_ext_tsk();
    }
#endif
#if PORT_ANALYSIS
#if PORT_DETECTION
#if PORT_STORAGE
    printf("Pico 2 W micro T-Kernel v%s storage. watchdog_reboot=%u\n",
           PICO_PROGRAM_VERSION_STRING, watchdog_caused_reboot() ? 1u : 0u);
#else
    printf("Pico 2 W micro T-Kernel v0.7-dev2 detection. watchdog_reboot=%u\n",
           watchdog_caused_reboot() ? 1u : 0u);
#endif
#else
    printf("Pico 2 W micro T-Kernel v0.6-dev3 analysis.\n");
#endif
    printf("Analysis initialization: begin\n");
    analysis_check_started = time_us_64();
    analysis_port_init();
    printf("Analysis initialization: OK; reference self-check: begin\n");
    if (!analysis_port_self_check())
    {
        printf("CHECK analysis synthetic GOOSE/SV rules/RF: FAIL\n");
        tk_ext_tsk();
    }
    printf("CHECK analysis synthetic GOOSE/SV rules/RF: PASS time=%" PRIu64
           " us\n",
           time_us_64() - analysis_check_started);
    printf("Analysis: Pico 1 rules/RF; shadow mode; no trusted profiles; "
           "software float.\n");
#if PORT_DETECTION
    if (!detection_init())
    {
        printf("CHECK detection copied alarm queue/exhaustion: FAIL\n");
        tk_ext_tsk();
    }
    printf("CHECK detection copied alarm queue/exhaustion: PASS\n");
#endif
#else
    printf("Pico 2 W micro T-Kernel v0.5-dev7-r1 capture.\n");
#endif
#if PORT_STORAGE
    if (!storage_init())
    {
        printf("Storage queue initialization failed.\n");
        tk_ext_tsk();
    }
#else
    capture_test_init(&g_test_tracker);
#endif
    printf("Core 1: GP4/5/6 PIO+DMA RX; Core 0: MDIO/USB/consumer.\n");
    printf("10 Mbps only, clk_sys=%" PRIu32 " Hz; no traffic transmitted.\n",
           clock_get_hz(clk_sys));
    if ((!capture_pipe_init()) || (!capture_pipe_self_check()))
    {
        printf("CHECK capture pool/queue ownership: FAIL\n");
        tk_ext_tsk();
    }
    printf("CHECK capture pool/queue exhaustion and ownership: PASS\n");
    if (!capture_app_phy(&address))
    {
        printf(
            "Capture stopped: PHY identity/configuration readback failed.\n");
        tk_ext_tsk();
    }
    while (!b_link)
    {
        b_link = capture_app_link(address, &bmsr, &special);
        printf("PHY waiting for negotiated 10 Mbps: BMSR=%04x SCSR=%04x "
               "ready=%u\n",
               bmsr, special, b_link ? 1u : 0u);
        if (!b_link)
        {
            (void) tk_dly_tsk(1000u);
        }
    }
    worker.tskatr  = TA_HLNG | TA_USERBUF | TA_ASSPRC;
    worker.task    = (FP) capture_app_worker;
    worker.itskpri = 6;
    worker.stksz   = sizeof(g_worker_stack);
    worker.bufptr  = g_worker_stack;
    worker.assprc  = TP_PRC2;
    task           = tk_cre_tsk(&worker);
    if ((0 >= task) || (E_OK != tk_sta_tsk(task, 0)))
    {
        printf("Capture stopped: Core 1 task start failed.\n");
        tk_ext_tsk();
    }
    report_at = time_us_64();
#if PORT_DETECTION
    if (!detection_start())
    {
        printf("Detection stopped: alarm/supervisor task startup failed.\n");
        tk_ext_tsk();
    }
#endif
#if PORT_STORAGE
    if (!storage_start())
    {
        printf("Storage task startup failed.\n");
        tk_ext_tsk();
    }
#endif
    for (;;)
    {
#if PORT_DETECTION
        detection_heartbeat(SUPERVISION_CONSUMER);
#endif
        p_frame = capture_pipe_receive(100u);
        if (NULL != p_frame)
        {
            delivered++;
#if PORT_ANALYSIS
            analysis_port_observe(p_frame);
#endif
            /* Observe while this consumer owns the FCS-verified frame. */
#if !PORT_STORAGE
            (void) capture_test_observe(&g_test_tracker, p_frame->data,
                                        p_frame->length);
#endif
            if (1u == delivered)
            {
                printf("FIRST frame seq=%" PRIu32
                       " len=%u wire=%u end_us=%" PRIu64 " loss_gen=%" PRIu32
                       " bytes=",
                       p_frame->sequence, p_frame->length, p_frame->wire_length,
                       p_frame->timestamp_us, p_frame->loss_generation);
                for (index = 0u; 32u > index; index++)
                {
                    printf("%02x", p_frame->data[index]);
                }
                printf("\n");
            }
            (void) capture_pipe_release(p_frame);
        }
#if PORT_ANALYSIS
        analysis_port_poll(time_us_64());
#endif
#if PORT_STORAGE
        storage_poll();
#endif
        if ((!b_prefix_printed)
            && (1u
                == atomic_load_explicit(&g_prefix_ready, memory_order_acquire)))
        {
            printf("RAW first block words=%" PRIu32 " prefix=", g_prefix_words);
            for (index = 0u; g_prefix_count > index; index++)
            {
                printf("%08" PRIx32 " ", g_prefix[index]);
                if (3u == (index % 4u))
                {
                    printf("\n");
                }
            }
            printf("\n");
            printf("RAW tail=");
            for (index = 0u; g_tail_count > index; index++)
            {
                printf("%08" PRIx32 " ", g_tail[index]);
                if (3u == (index % 4u))
                {
                    printf("\n");
                }
            }
            printf("\nRAW samples=%" PRIu32 " crs_high=%" PRIu32
                   " rxd_set_bits=%" PRIu32 "\nRAW end_pc=%" PRIu32
                   " irq=%08" PRIx32 " inte=%08" PRIx32 " ints=%08" PRIx32
                   " pins=%" PRIu32 " damaged=%u\n",
                   g_prefix_words * 10u, g_crs_high_samples, g_rxd_set_bits,
                   g_first_meta.end_pc, g_first_meta.pio_irq,
                   g_first_meta.irq_enable, g_first_meta.irq_status,
                   g_first_meta.pin_levels, g_first_meta.b_damaged ? 1u : 0u);
            b_prefix_printed = true;
            printf("RAW RXD runs (value:samples, 10 samples per dibit):\n");
            for (index = 0u; g_signal_run_count > index; index++)
            {
                printf("%" PRIu32 ":%" PRIu32 " ", g_signal_runs[index].value,
                       g_signal_runs[index].samples);
                if (7u == (index % 8u))
                {
                    printf("\n");
                }
            }
            printf("\n");
            printf("RAW stop=%" PRIu32 " dma_remaining=%" PRIu32
                   " dma_words=%" PRIu32 " (stop: 0=PIO 1=DMA)\n",
                   g_first_meta.stop_reason, g_first_meta.dma_remaining,
                   g_first_meta.dma_words);
        }
        if (time_us_64() >= report_at)
        {
            if (0 > atomic_load(&g_worker_status))
            {
                capture_app_report(delivered);
                printf("Capture stopped: Core 1 PIO/DMA init or self-test "
                       "failed.\n");
                tk_ext_tsk();
            }
            printf("capture worker_status=%d time=%" PRIu64 " us\n",
                   atomic_load(&g_worker_status), time_us_64());
            capture_app_report(delivered);
            report_at = time_us_64() + 1000000u;
        }
    }
}
#endif /* PORT_CAPTURE */

/*** end of file ***/
