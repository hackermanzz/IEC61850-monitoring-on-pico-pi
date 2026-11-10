# v0.6: Pico 2 W analysis, rules and random forest

The v0.6 analysis port integrates the existing Pico 1 analysis into the
real micro T-Kernel SMP capture pipeline. Local review, compilation and offline
checks pass. **The v0.6 functional analysis-parity milestone is complete for the
tested lab schema:** startup, individual GOOSE/SV and mixed analysis have board
evidence. Higher-rate capture shortfalls, broader publisher schemas, bursts,
large frames, soak, accuracy and worst-case resource qualification remain open.
The working v0.5 capture image and its board-tested snapshots remain available.
No alarm, incident lifecycle, SD, radio or watchdog service is enabled here.

## What happens to a packet

Think of capture as a delivery worker and analysis as an inspector. A fixed
buffer is the tray holding one packet. Core 1 fills a tray; the kernel queue
passes its address to Core 0. The inspector borrows it, reads the packet and
returns that tray exactly once. The queue never waits for analysis to catch up;
if all trays are busy, loss counters record the overload.

    LAN8720 -> Core 1 PIO/DMA -> decode + Ethernet CRC
            -> existing fixed pool/queue -> Core 0 analyzer
            -> rules -> features -> four-frame RF window
            -> diagnostic counters -> return capture buffer

A **parser** reads encoded fields while checking boundaries. **GOOSE** carries
state/event messages; **SV** carries sampled measurements. **BER/TLV** is the
nested tag/length/value format those parsers read. A **stream** is one publisher
identity whose history must be kept separate from other publishers.

Actual excerpt, capture_app.c / capture_app_task (not a standalone program):

```c
            delivered++;
#if PORT_ANALYSIS
            analysis_port_observe(p_frame);
#endif
            /* Observe while this consumer owns the FCS-verified frame. */
            (void) capture_test_observe(&g_test_tracker, p_frame->data,
                                        p_frame->length);
```

Later in that same consumer branch, the implemented release is:

```c
            (void) capture_pipe_release(p_frame);
```

The analysis adapter does not queue or retain that pointer. The reference
analyzer copies the raw bytes it needs into its own bounded history. All four
frames of a scored window remain available through analyzer_copy_batch_frame;
the next analysis input may replace that snapshot. Future asynchronous evidence
consumers must copy it before the next input, rather than retain borrowed pointers.

## What was reused and what was adapted

| Files | Role |
| --- | --- |
| analyzer.c/.h | Existing bounded parsing, per-stream histories and feature calculations. |
| iec_rules.c/.h | Existing rule engine and optional model-gating logic. |
| rule_profiles.c/.h | Existing explicitly configured trusted-publisher tables. |
| generated_batch_models.c/.h | Existing generated RF trees and feature names; not retrained or edited. |
| batch_model_manifest.json | Existing model/schema settings and provenance. |
| reference_hashes.json | SHA256 fingerprints of those nine unchanged reference files. |
| analysis_port.c/.h | New Core 0 adapter: ownership, loss/restart handling, timing and counters. |
| analysis_fixture.h | Eight local synthetic frames; none are transmitted. |
| analysis_expected.h | Reference-derived expected features/scores for the startup self-check. |

The original files are in INF2004_ProjectTemplate/app_program/analysis. The host
parity test checks both copies against the saved fingerprints. The wrapper from
the old task_consumer.c is not copied: it expects missing application headers,
an incident store and a different mailbox/frame layout. The new adapter uses
the already-tested v0.5 fixed-pool/message-buffer ownership instead.

No new task or kernel queue is added. Analysis runs in the existing Core 0
consumer, at priority5, with its existing4096-byte static stack. Core 1 remains
the dedicated receive worker. Only Core 0 uses console/libc/math. The build uses
software floating point; hardware FPU task context is still unsupported.

## Features, windows and the RF model

A **feature** is a number calculated from packet fields or history: for example,
a timing interval or counter change. A **window** is four frames from one stream.
A **stride of two** means windows1-4,3-6,5-8: each new result needs two more frames
after the initial four. The history and window sizes are unchanged:

- Four GOOSE streams and one SV stream.
- Thirteen per-frame GOOSE metrics and eighteen per-frame SV metrics.
- Each metric produces mean, maximum, last value and standard deviation across
  the four-frame window:13x4=52 GOOSE inputs;18x4=72 SV inputs.
- SV waveform history retains128 samples, with up to14 ASDUs per frame. An
  **ASDU** is one encoded sample group inside the SV packet.
- The supplied SV model expects six big-endian float32 values at byte offsets
  0,4,8,12,16,20 within the sample data. A publisher using integer/quality pairs
  needs a schema check; it is not automatically compatible.

An **RF (random forest)** is a collection of decision trees. The existing model
has100 trees for each protocol. It combines their outputs into a score, then
uses the existing protocol-specific threshold to produce label0 or1. A score
is not a guaranteed real-world probability, and a positive window is not yet
an integrated incident/alarm. No model or threshold was changed in this port.

Actual excerpt, analyzer.c / predict_batch:

```c
        aggregate_batch(p_batch, feature_count, output);
        probability = p_predict(output);
        label       = (probability >= threshold) ? 1u : 0u;
        memcpy(g_last_batch_features, output, output_count * sizeof(float));
        g_last_batch_feature_count    = output_count;
        g_last_batch_protocol         = p_result->protocol;
        p_result->prediction_ready    = true;
        p_result->primary_probability = probability;
        p_result->primary_label       = label;
        p_result->label_changed =
            (!*pb_has_prediction) || (label != *p_previous_label);
```

## Rule checks and shadow mode

A **rule** checks a specific condition, such as structure, publisher identity,
configuration, counters or timing. A **trusted profile** supplies the approved
identity and expected limits. It must come from trusted configuration, not be
learned automatically from whatever arrives on the wire.

This image builds with IEC_RULE_GATE_ENABLED=0 and MONITOR_LAB_PROFILES=0.
There are zero trusted profiles. Structural/unsupported/unconfigured findings
are available, but publisher-specific identity/rate checks have no deployed
baseline yet. Offline tests exercise those checks with explicit test profiles.

**Shadow mode** means findings are diagnostic. **Gating** would skip selected
model runs to save CPU; it is disabled. Every complete supported window still
runs its RF model. A skipped window would be unclassified, not benign.

| Reason bit | Meaning |
| --- | --- |
| 0x001 | Encoded structure problem. |
| 0x002 | No trusted profile for this stream; expected in the current image. |
| 0x004 | Source identity mismatch against a configured profile. |
| 0x008 | Configuration mismatch. |
| 0x010 | Test/simulation flag. |
| 0x020 | Needs commissioning. |
| 0x040 | Counter anomaly. |
| 0x080 | Data changed without the expected state change. |
| 0x100 | Timing finding. |
| 0x200 | Capture gap affecting a configured rule baseline. |
| 0x400 | Unsupported encoding/feature. |

The reason word combines bits; it is not an attack label. With no profiles,
not every possible gap produces a rule bit; ANA gaps remains the adapter's
separate capture-discontinuity counter.

## Gaps, restarts and ownership fixes

A **discontinuity** means history may be incomplete. The adapter checks both the
capture sequence and loss_generation. That generation is a changing marker,
not the number of lost packets. A generation change can reveal a pause even
when successfully recorded frame sequence numbers are consecutive.

Ordinary gaps call the reference analyzer_note_capture_gap. It marks streams
suspect; each stream's next counter decides whether to keep its window or reset
that stream. This preserves the reference policy rather than resetting every
stream for an unrelated background-frame loss. Backwards timestamps, duplicate
capture IDs or backwards sequence jumps reset all analysis state. A normal
32-bit sequence wrap by one is allowed. Rejected frames larger than the reference
1518-byte limit now flag uncertain history rather than being silently skipped.
No frame is truncated to fit the model's evidence buffers.

Actual excerpt, analysis_port.c / analysis_port_observe:

```c
            delta = p_frame->sequence - g_sequence;
            /* Unsigned wrap by one is normal. Duplicate/backwards IDs or
             * a backwards clock invalidate all histories, not just a vote.
             */
            b_restart = (0u == delta) || (UINT32_MAX / 2u < delta)
                     || (p_frame->timestamp_us < g_timestamp);
            b_gap = (1u != delta) || (p_frame->loss_generation != g_generation);
```

## Reading the console

| Output | Meaning |
| --- | --- |
| ANA received | Verified capture frames offered to analysis. |
| ANA accepted/rejected | Parsed supported IEC frames versus everything else, including ordinary UDP/background traffic. Rejected does not by itself mean corruption or attack. |
| ANA windows/goose/sv | Scored windows in total and by protocol. |
| ANA positive | Windows above the unchanged model threshold; not incident count. |
| ANA gaps/restarts/stream_resets | Adapter discontinuities, full resets, and reference per-stream resets. |
| ANA last_us/max_us | Consumer analysis elapsed time, including any preemption; excludes wire capture/queue wait. This is not arrival-to-alarm latency. |
| ANA protocol/label/probability_ppm | Last scored window: protocol0=GOOSE,1=SV; label0/1; score scaled by1000000. Meaningful only after windows>0. |
| ANA stack_used/stack_size | Initial Core 0 task's stack watermark estimate in bytes, out of4096. Includes startup and analysis paths exercised so far; not overflow protection or a guarantee of worst-case use. |
| RULE frames/flagged/run/skipped | Rule observations, flagged observations, model decisions and skipped model decisions. skipped must remain0. |
| RULE reasons | Cumulative reason bits since reset; resets clear the rule counters. |
| CAP / TEST | Existing raw receive and marked UDP-batch diagnostics remain available. |

A **stack watermark** fills unused stack storage with a known pattern before the
task starts, then estimates how much has been overwritten. It does not measure
all stacks/MSP exceptions and cannot detect every possible overflow. Watch for
shrinking headroom under real SV load. Compiler .su reports describe individual
function frames, not the full nested call chain.

## Build and local verification

From the repository root:

```powershell
.\INF2004_Pico2W_Port\run_these.ps1 -Profile analysis
.\INF2004_Pico2W_Port\testing\host\run_tests.ps1
```

The image is build/analysis/pico2w_analysis_v06.uf2. Capture-only remains available
through -Profile capture. All original profiles remain separate; analysis source
files are excluded from the other four builds.

Latest offline replay:843 cases,408 accepted frames,199 scored windows. Separate
reference/port executables produce bit-identical feature vectors and model scores
for those fixtures. All four raw evidence snapshots are checked byte-for-byte.
Cases include all supported stream slots,14/15-ASDU bounds, GOOSE/SV truncation,
malformed lengths, rule source/config/test/gap flags, capture generation changes,
sequence/time restarts and normal32-bit wrap. These checks prove preservation for
the fixtures; they do not prove attack accuracy or physical Ethernet performance.

The startup self-check feeds four GOOSE and four SV frames through the real
parser/rules/models. It checks both model paths,52/72 features against reference
expected values (NaN-aware absolute1e-6 plus relative1e-5 tolerance), valid scores,
two full windows and zero skipped decisions. It then clears synthetic histories
and counters before live capture. A tolerance permits math-library rounding;
it is not an allowance to change feature definitions.

## Board acceptance: next user action

1. For optional dev3 diagnostics, manually flash the newly built analysis UF2
   and save startup. Keep the preserved dev2 image for mixed-test comparisons. Require:

```text
Pico 2 W micro T-Kernel v0.6-dev3 analysis.
CHECK analysis synthetic GOOSE/SV rules/RF: PASS time=... us
CHECK capture pool/queue exhaustion and ownership: PASS
PHY config stage=OK ...
... ready=1
PIO selftest=15 expected=15 ...
```

2. Save several ANA/RULE/CAP summaries. If self-check fails, capture stops; save
   the output and restore the preserved v0.5 fallback rather than treating it as
   a passing analysis board test.
3. Re-run the existing100-packet/10fps UDP batch and match its fresh run ID. This
   tests capture/handoff while the analysis consumer is integrated. Ordinary
   P2RXTEST UDP is not GOOSE/SV: it should increase ANA rejected, not model windows.
4. With a verified publisher using the documented schema, test GOOSE alone,
   SV alone and mixed traffic. Require increasing appropriate window counters,
   skipped0, stable stack headroom and no ownership errors. Save publisher settings,
   offered counts, CAP gaps/drops and processing maxima. Repeat with bursts and
   larger SV frames; the startup self-check is not a substitute for this wire test.
5. Keep the complete system under the user-approved479232-byte peak RAM ceiling
   (90% of Pico 2 W SRAM; supersedes216064bytes). Static BSS
   size alone does not qualify runtime peak, all stacks or later service budgets.

Board self-check now passes; alternating mixed traffic, worst-case target timing/stack
peaks and combined load remain pending. Do not claim >=99% capture,100ms arrival-to-alarm performance,
RF accuracy or complete publisher compatibility from a successful build/replay.
Four-frame cold-start collection alone takes three inter-arrival intervals;
that waiting time must be included in any later end-to-end deadline.

## Dev2 correction: disabled math is different from software math

The first dev1 board log panicked immediately after the analysis banner. Source
and link-map inspection found an erroneous SDK selection: `none` installs
panic stubs for float/double arithmetic, rather than providing software math.
The host replay used the PC's math library and therefore could not catch this.
A target disassembly without VFP was insufficient: panic stubs contain no VFP
either. The original failed image and user log are retained for regression.

Actual corrected selection in platform/kernel.cmake (analysis branch):

```cmake
pico_set_float_implementation(${PORT_IMAGE} compiler)
pico_set_double_implementation(${PORT_IMAGE} compiler)
```

Together with `-mfloat-abi=soft`, this selects integer-instruction compiler/libgcc
arithmetic and libm instead of disabled SDK wrappers. Hardware FPU context remains
disabled. Capture/kernel profiles retain their previous `none` selection because
they do not perform floating-point analysis. Model/feature files are unchanged.

The analysis build now runs testing/host/verify_analysis_image.py against the
actual ELF before reporting it ready. It rejects disabled-math wrapper symbols,
requires real arithmetic/sqrtf helpers, and rejects VFP instructions. It correctly
rejects the original dev1 ELF and accepts dev2. Python is required for this check.
Dev2 adds initialization/selfcheck stage markers. Board recovery now passes in the supplied log;
the linkage correction now has positive board self-check evidence.

## Earlier dev2 baseline: sequential GOOSE and SV pass

User corrected sender selection: successful reports use interface26, whereas
prior reports used12 (only an example index). Without the interface listing,
the exact device mapping is not established; do not infer it from index alone.
The earlier no-IEC log is retained, not treated as a passing test.

New complete board log v06_dev2_goose_sv_sequential_pass.txt shows:
- Startup synthetic selfcheck PASS5036us,PHY/link/PIO15 pass.
- First GOOSE batch reaches accepted100,goose49,sv0,windows49.
- Subsequent SV batch reaches accepted200,goose49,sv49,windows98.
- Matching candidate reports:interface26,GOOSE100 and SV100 submitted/completed,
  each~9.98sec at10fps. UTC starts04:06:45.149079 and04:07:01.797785 Nov9
  (~13:06/13:07 JST). This was sequential protocols on ONE boot, not alternating
  mixed traffic. No unique per-run receiver IDs in raw IEC; counts/windows are
  consistent with both100-frame batches, not a general loss/accuracy proof.
- Final45.260791s raw437,crc_ok/delivered430,accepted200,rejected230,windows98,
  GOOSE49,SV49,positive98;RULEframes200,flagged200,run98,skipped0,reasons0x2.
  0x2 means no trusted profile (expected profiles0), NOT an attack label.
  All98model windows cross current thresholds on synthetic data; that does NOT
  establish real attacks, accuracy or why these waveforms receive positive scores.
- Stack watermark2124/4096,max analysis elapsed2377us (includes preemption,
  parsing/features/model where applicable; not wire-to-alarm deadline).
- full/stall/DMA-disabled/pool/queue/owner0. Pauses46,high_arm13,max_rearm1111us,
  no_sfd5,short1,bad_crc1,loss_gen63,ANA gaps55. These rose during GOOSE/background
  overlap then stayed unchanged throughout SV. Do not claim all errors preceded
  both tests, or derive capture percentage from430/437.

Next: fresh-boot mixed Scapy case (--protocol mixed --iface26,100each,total200,
10total fps/~20sec), then longer/rate/size tests and worst-case stack/peak RAM.
Keep dev2 for comparisons. Functional live parsing/rules/RF for each protocol is
now proven; concurrent mixed/load qualification remains. No v0.7 work resumed.

## Optional dev3 diagnostics

The default analysis build now produces0.6-dev3, adding separate background,
GOOSE/SV-seen and rejected-IEC counters plus rule parse_errors. Its build/host
checks pass; no dev3 board result is claimed. The successful log above is dev2.
No reflash is needed for the next mixed test. The preserved dev2 board image is
build/analysis/known-working-v06-dev2-live-iec.uf2 (relative to the port root).
The generic build/analysis/pico2w_analysis_v06.uf2 currently contains dev3.

## Throughput measurement candidate

Dev3 now also reports PERF interval raw/delivered/IEC fps,mean analysis elapsed,
max raw-decode/window-call elapsed and end-service-to-analysis frame age. This
adds fixed counters only; the existing stop/rearm algorithm and buffer counts
are unchanged. Dev3 telemetry now has board evidence at96.45fps; higher-rate qualification is pending. Read the
[limit-test procedure](../../testing/throughput/README.md) before raising load.
The user reports the low-rate mixed case passed; no new mixed serial/report was
provided. This does not establish production capacity. Models remain unchanged.

## Latest throughput result: one SV unobserved near139.96 submitted frames/s

Saved full dev3 serial v06_dev3_mixed_150_requested_one_missing.txt and matching
v06_dev3_mixed_150_sender.json in testing/analysis/logs. Sender:interface26,
150requested,139.9646achieved,21.4275sec,1500GOOSE+1500SV submitted/completed.
Receiver:2999accepted,GOOSE1500/SV1499,IEC rejected0,background224. One submitted
SV not observed. Ratio2999/3000=99.9667%againstOSsubmissions,NOT formal wire99%
qualification/unique-packet guarantee. Counts settled through101.38s,so the final
one-frame deficit is not just the supplied excerpt ending mid-send/drain.

Expected749windows perprotocol/1498total;actualGOOSE749,SV747,total1496. One stream
history reset occurred by32.600275s at1364accepted,well inside the batch,not a
kernelrestart(restarts0). An incomplete sliding history can lose multiple window
outputs from one frame gap;this is why windows are not a packet-loss counter.

Pre-test22.520793s->completion44.710795s:pauses63->70,high_arm13->14,short3->4,
no_sfd5andbad_crc1unchanged,ANAgaps72->81,maxrearm2132->2554us. full/stall/
DMA-disabled/pool/queue/owner all0. Final stack2124/4096,max scored-call3186us,
max decode3998us(preexisting),max age6879us(from6219pre),last ages~sub-ms without
sustained growth. Background191pre->203completion->224final; no completely quiet
wire. Added short recording is consistent with a reception issue but cannot be
identified as the missing SV from these counters alone. Raw acquisition remains
the stronger lead than decoded-queue pressure,not proven root cause/DMA ceiling.

Comparison of short small-frame/1ASDU mixed runs:
- Requested100,achieved96.4462:2000accepted/2000submitted,998windows,0streamresets.
- Requested150,achieved139.9646:2999/3000,1496/1498windows,1streamreset.
- Requested200,achieved187.7854:3989/4000,1978/1998windows,11streamresets.
Do not assume a fixed threshold between them: different background bursts,
host/NIC delivery and short duration confound attribution. Highest clean count
match is one~96fps run,not a guaranteed production rate. Keep its fallback.

Next: repeat same150requested case once with freshboot and~10seconds quiet after
ready,collectbaseline+sender+PERF/CAP/ANA. Do not jump500 yet. If recurring gaps,
isolate acquisition from analysis load and profile raw stop/rearm/decoding before
increasing buffers or calling this hardware bandwidth exhaustion. This review
changes evidence/docs only; no code/build/tests/assistanttraffic/flashing/Git.
