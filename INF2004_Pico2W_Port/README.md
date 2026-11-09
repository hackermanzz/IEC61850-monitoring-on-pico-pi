# Pico 2 W port

Six build profiles target Pico 2 W / RP2350 Arm Secure: SDK diagnostic,
single-core micro T-Kernel v0.3-r1, dual-core v0.4-dev2 acceptance,
**v0.5-dev7-r1 capture**, **v0.6-dev3 analysis/rules/RF**, and
**v0.7-dev2 detection/alarm/supervision**.

v0.7 has a separate `detection` profile with single-protocol incidents,
two full-window evidence slots, copied alarm events and task-progress
supervision. Dev1 board logs show independent GOOSE/SV incidents and mixed
incidents/evidence; the user confirms the physical mixed alarm LED. Full board
acceptance remains open. Dev2 fixes truncated USB diagnostics with a bounded
complete-line queue. GPIO output and watchdog reset default off; see the
[v0.7 walkthrough and board procedure](app_program/health/README.md).

The supplied board logs pass the v0.3 single-core checks and the v0.4 SMP
functional suite, including cross-core mailbox/alarm, mutex priority inheritance,
shared counters and scheduler audits. LAN8720 identifies as 0007/c0f1 at address 1.
**Dev6 now has functional board capture evidence:343 CRC-valid frames delivered
from Core1 to Core0**, with zero full/stall/DMA-disabled or ownership faults.
Three start-marker rejections,one CRC rejection and72 raw-buffer pauses remain
in the supplied run. Dev7 adds per-run unique test-packet counting; its first100/100 board batch now passes; two repeats remain.
Capture percentage/capacity remain unqualified.
Known-working v0.3 and v0.4 UF2/ELF fallbacks are preserved under build/kernel
and build/smp. Longer stress, repeated boots and fault injection remain pending.

The [analysis walkthrough](app_program/analysis/README.md) describes the new v0.6
consumer and its acceptance steps. The [capture walkthrough](app_program/capture/README.md) explains the new
implementation using actual source excerpts, plain definitions and ownership
examples. The [board procedure](testing/README.md#v05-capture-board-procedure)
describes its next acceptance checks.

For the direct Windows PC Ethernet connection, the
[traffic test guide](testing/traffic/README.md) provides a finite UDP broadcast
sender. Start with dev4 PIO self-tests, then a low-rate known batch. GOOSE/SV
publishers are not required to establish initial frame acquisition.

```text
INF2004_Pico2W_Port/
  app_program/
    app_main.c           SDK main, console/time and PHY scan
    capture/             MDIO, PIO/DMA RX, decoder and frame pipe
    analysis/            implemented parser/features/models and shadow rules
    storage/             future S1 SD
    health/              S4 bounded evidence, supervision and v0.7 runtime
    alarm/               S5 local alarm; future notifications
  config/config.h        static-buffer kernel profiles
  platform/              RP2350 context, interrupts, tick and faults
  third_party/mtkernel/  recovered course kernel, license and provenance
  testing/host/          real MDIO driver with electrical trace stubs
  testing/kernel/        explicitly linked board acceptance suite
  testing/capture/       capture acceptance and board evidence
  build/                 generated outputs, ignored
```

## Build

From this directory in PowerShell:

```powershell
.\run_these.ps1 -Profile diagnostic
.\run_these.ps1 -Profile kernel
.\run_these.ps1 -Profile smp
.\run_these.ps1 -Profile capture
.\run_these.ps1 -Profile analysis
.\run_these.ps1 -Profile detection
```

The default profile is `diagnostic`. Outputs are separate:

| Profile | UF2 | Behavior |
| --- | --- | --- |
| diagnostic | `build/diagnostic/pico2w_diagnostic.uf2` | Read-only PHY address scan, then clock/time output. |
| kernel | `build/kernel/pico2w_kernel_v03.uf2` | Single-core scheduler/IPC checks, PHY scan and heartbeat. |
| capture | `build/capture/pico2w_capture_v05.uf2` | SMP receive pipeline: verified 10 Mbps negotiation, GP4/5/6 PIO/DMA, CRC, bounded frame handoff and counters. |
| analysis | `build/analysis/pico2w_analysis_v06.uf2` | Capture plus existing GOOSE/SV parsing, shadow rules, RF models, reference-derived startup self-check and analysis/stack counters. |
| detection | `build/detection/pico2w_detection_v07.uf2` | v0.6 pipeline plus latched incidents, two evidence records, copied alarm events and a supervisor; GPIO/reset disabled by default. |
| smp | `build/smp/pico2w_kernel_smp_v04.uf2` | Original checks plus Core 1 affinity, delayed mailbox replies, shared counter and remote alarm/audits. |

The script works from any working directory and uses installed SDK 2.3.1,
CMake 4.3.4, Ninja 1.13.2, Arm GCC 15.2.1 and picotool 2.3.1. It accepts
`-SdkPath`, checks tool/native-command failures and restores PATH/SDK environment
on exit. New profiles must explicitly reconcile their SDK/library dependencies.
No SDK copy is required. Flashing is a separate board operation.

Diagnostic/kernel/smp profiles only read PHY management pins GP2/GP3.
The **capture, analysis and detection profiles write and verify LAN8720 10 Mbps negotiation settings**,
then samples confirmed GP4 CRS_DV / GP5 RXD0 / GP6 RXD1. REFCLK/nINT remain
unconnected. No packet transmission, notifications or assistant flashing.
Startup waits up to 15 seconds for USB CDC. Open the console promptly.

The [SMP implementation walkthrough](platform/smp/README.md) explains how the
two cores share a kernel, how context switches work, and when to use atomics,
spinlocks, mutexes, semaphores and mailboxes. v0.4-dev2 adds a cross-core
priority-inheritance mutex test and a plain counter protected by that mutex.

## Verification and implementation notes

On November 9, all five profiles build. MDIO read/write,2640 decoder fixtures,
PHY/PIO, frame ownership and sender tests pass. The analysis reference/port
comparison passes843 cases and199 scored windows, including byte-checked
four-frame evidence. BARR/format passes67 first-party C/header files.
The analysis ELF links software math and contains no VFP instructions; current
dev3 static BSS is176096 bytes, which is not a runtime peak RAM measurement.
Sequential GOOSE/SV and a mixed 2000-frame count match have board evidence;
load/resource qualification remains open. Existing prebuilt newlib GNU-stack-note warning
remains; application compiler checks use -Wall -Wextra -Werror.

See [verification commands and board acceptance](testing/README.md),
[the RP2350 adapter and its limits](platform/README.md), and
[kernel source provenance](third_party/mtkernel/README.md).
The kernel uses the actual course common scheduler and IPC sources. The SDK
supplies RP2350 boot/reset/linker metadata and USB; the old RP2040 BSP is not
linked. Only the diagnostic owner uses libc, with SDK global thread-local state.
FPU task context and per-task libc state remain unsupported in this bring-up.

## Adding code

- C, C++ and preprocessed assembly anywhere under `app_program/` are discovered
  on the next build. Headers belong beside their module or in `config/`.
- PIO sources under `app_program/` generate their headers in the build directory.
  Use distinct PIO basenames; do not copy generated headers into the source.
- Keep one SDK `main()` entry in `app_main.c`. New source discovery does not
  automatically call new functions or supply external libraries.
- Tests remain outside automatic application discovery. The kernel profile
  explicitly links its acceptance suite; host tests never enter the firmware.
- Platform and kernel source selection is explicit in `platform/kernel.cmake`.
  Do not automatically compile the recovered RP2040 or unrelated board sources.

## Progress and version roadmap

Reviewed 2026-11-09. Target: **Pico 2 W / RP2350 Arm Cortex-M33 with
micro T-Kernel 3 SMP**. Single-core and SMP functional board checks pass;
capture and analysis have functional board evidence; performance and resource
qualification remain incomplete.
The versions below are proposed engineering milestones, not existing releases,
Git tags, or kernel version numbers. There are no completion-date estimates yet;
the kernel port and PHY timing need measured evidence first.

### Current position

| Area | Progress | Remaining acceptance |
| --- | --- | --- |
| v0.1 build | Six profiles generate RP2350 UF2s | Reproduce tool setup on a fresh checkout. |
| v0.2 PHY | Raw LAN8720 IDs board-confirmed; host reads/writes pass | Capture configuration/link readbacks on board. |
| v0.3 kernel | Nine functional checks board-pass | Repeat boots, soak and fault injection. |
| v0.4 SMP | Complete supplied functional suite passes, failures=0 | Longer stress, stack peaks, migration/reclaim and combined load. |
| v0.5 capture | Functional board capture and Core1-to-Core0 delivery pass:343 CRC-valid frames | Dev7-r1 first100/100 batch passes; two baseline repeats pending; burst/overload/gap and independent offered-frame loss measurements follow. |
| v0.6 analysis | Functional analysis-parity milestone complete for tested lab schema:843 offline cases/199 windows match reference; board self-check, individual IEC and mixed2000-frame counts pass | Broader rate/burst/large-frame/soak, accuracy and worst-case resource qualification remain. Higher-rate capture shortfalls remain open. |
| v0.7 services | Dev1 board logs show independent GOOSE/SV incidents and mixed retained evidence/software alarm; mixed physical LED user-confirmed. Dev2 adds readable bounded console output | Dev2 board regression, single-protocol physical LEDs, watchdog/stall, full/slow sinks, long attacks, service-load timing/stacks remain. SD/network are later milestones. |

These versions are engineering milestones, not released/tagged software.
There is no meaningful overall completion percentage yet.

`../INF2004_ProjectTemplate/app_program/` contains capture and analysis source
for reuse, including fixed frame ownership and four-frame model windows. Its
storage, health and alarm modules are TODO skeletons; shared application headers,
kernel and build foundation are absent in the current checkout. It cannot serve
as a complete buildable kernel template as it stands. Earlier integrated
firmware measurements do not qualify this port.

### Milestones and acceptance checks

| Proposed version | Changes and subsystem features | Required evidence before completion |
| --- | --- | --- |
| **v0.1 — SDK diagnostic baseline** | Application layout, automatic C/C++/assembly/PIO discovery, installed SDK build, USB console, clock and microsecond time diagnostic. | Previously recorded configure/build and RP2350 UF2 inspection exist. Retain exact tool versions; add a board output log to qualify execution. |
| **v0.2 — PHY identification** | Capture: finish MDIO clock timing, most-significant-bit-first fields, bounded bit counts, released turnaround, ACK handling and read-register API. Scan addresses 0–31; read LAN8720 ID registers. Keep initial exercise read-only. | Build current learner code; log repeatable raw IDs and ACK/no-device behavior. Verify actual module, power and clock arrangement before selecting a receive configuration. No shifted-ID workaround. |
| **v0.3 — RP2350 single-core kernel** | Recover the exact course RP2040 foundation as reference without restructuring Git history. Add the RP2350 Arm platform/build configuration, startup/vector table, linker and boot metadata, exception/context switching, interrupt priorities/masking, tick timer, monotonic time and fault reporting. Reconcile SDK runtime ownership. | Boot on one core; demonstrate two preempting tasks, delay/wakeup, timeout, semaphore/mailbox operations and ISR-to-task wakeup. Check register/stack preservation and fault output. Use software floating point until FPU context preservation is qualified. |
| **v0.4 — micro T-Kernel SMP** | Bring up Core 1 and its stack/vectors; implement inter-core reschedule signalling, kernel locks/memory ordering, core affinity and interrupt ownership. Audit SIO FIFO/spinlock use, SDK coexistence and heap synchronization. | Board logs demonstrate simultaneous tasks on both cores, cross-core wakeups, priority/preemption and sustained contention without lost messages, deadlocks or corrupted state. Qualify floating-point context if enabled. Dual LED loops alone are insufficient. |
| **v0.5 — Capture acquisition and handoff** | S2 implemented in its own SMP profile: 10 Mbps PHY configuration/readback, three-pin PIO sampling and qualified low-tail detector, DMA double raw buffers, bounded decoder/FCS, kernel frame pool and non-waiting pointer queue, timestamps and loss generation. | Host tests and real-kernel pool/queue board checks pass;343 CRC-valid frames delivered. Compare real bytes/FCS and raw timing; test DMA overrun and exhaustion, then measure sustained/burst capture against independent offered-frame counts. |
| **v0.6 — Analysis parity** | S3: port parsing, per-stream state, features, generated RF models and shadow rules. Preserve four-frame windows/stride two, 128-sample SV history, 52 GOOSE/72 SV inputs, four GOOSE/one SV streams and all four raw evidence frames. Reconcile shared headers/APIs. | Host replay matches reference features/model outputs; malformed frames and loss/restart paths are checked. Target build and timed board replay establish inference cost and stack/RAM use. Confirm actual SV payload schema before claiming publisher compatibility. |
| **v0.7 — Detection, alarm and supervision** | S3 owns incident state; S4 provides bounded evidence storage and one watchdog supervisor; S5 drives the alarm. Either GOOSE or SV alone can create an incident. Add copied output queues, progress telemetry, evidence exhaustion policy and arrival-to-alarm timestamps. | GOOSE-only, SV-only and mixed cases activate the LED. Full/slow output sinks and long attacks do not stop detection. Inject a software task stall and distinguish healthy idle. Measure complete latency including window collection. |
| **v0.8 — SD incident records with DMA** | S1: SD writer and SPI/FatFs baseline, then DMA-backed SPI block transfers; bounded record queue, incident/evidence serialization and durable ACK matched to slot and incident ID. User reserves GP10–GP15 for SD; verify exact signal mapping and bus mode before enabling I/O. | Prove safe filesystem writes, DMA ownership/completion/timeout handling, then concurrent capture/analysis/alarm with slow/full/removed card and ACK mismatches. Recheck RAM, capture loss and alarm latency. FAT16/32 only; exclusive new files under `IECLOG`, preserving existing NOOBS files. No formatting or overwrites. |
| **v0.9 — Wi-Fi and Telegram** | S5: adapt existing HTTPS/parser fixes to the qualified RP2350 runtime. Preserve one radio/lwIP owner, bounded notification queues/retries, independent alarm path and peak TLS allocation telemetry. Investigate driver/runtime feasibility during v0.3–v0.4. | Board tests cover successful delivery, disconnect, timeout, TLS failure and alert backlog with capture/analysis active. Record CPU, stack and heap peaks. Keep credentials outside source/export artifacts. |
| **v1.0 — Qualified combined system** | Integrate all required subsystems; fix versions/configuration and document workload, wiring, model/publisher schema, stream admission and evidence policies. | Demonstrate >=99% capture for the agreed sustained/burst workload, agreed arrival-to-LED latency, held-out accuracy and <=216064 bytes total peak RAM with required services enabled. Include startup, long attacks, queue exhaustion, SD/network faults and soak testing. Publish limits and reproducible results. |
| **v1.1 — Optional optimization** | Evaluate inference gating, stream expiry/admission improvements, model retraining or feature changes, and optional buzzer after the baseline is qualified. | Compare missed attacks, false alarms, latency, CPU and RAM against v1.0. Feature/history changes require retraining/re-export and replay. Enable gating only after explicit policy selection and evidence. |

### Subsystem responsibilities

| Subsystem | Folder | Planned responsibility |
| --- | --- | --- |
| Platform | `platform/` | Implemented RP2350 boot adapter, scheduling, SMP, interrupts, time and synchronization; further stress/resource qualification pending. |
| S1 | `app_program/storage/` | SD queue/writer, SPI/FatFs, DMA-backed block transfers and durable completion acknowledgements. |
| S2 | `app_program/capture/` | PHY management, PIO/DMA acquisition, decoding/FCS, frame pool, nonblocking delivery and loss telemetry. |
| S3 | `app_program/analysis/` | Parsing, stream histories, rules/features/models and sole ownership of incident decisions/state. |
| S4 | `app_program/health/` | Bounded evidence storage services, resource/progress reporting and the single watchdog supervisor. It does not make independent incident decisions. |
| S5 | `app_program/alarm/` | Local alarm and queued notifications through the radio-owning task. |

Provisional scheduling follows the course template's constraints: lower numeric
priority is higher, priorities 1–4 are reserved for system services, USB/radio
ownership remains on Core 0, and the v0.5 capture task is pinned to Core 1 at priority 6.
The consumer is Core 0 priority 5. This profile uses two application tasks,
one fixed pool and one message buffer; acceptance-suite objects are excluded.
Recalculate priorities/resources when integrating later services.

### v0.8 SD/DMA sequence

DMA-backed SD storage belongs in **v0.8**, after v0.7 incident/evidence ownership
and alarm/supervisor acceptance. DMA (direct memory access) moves bytes between
a RAM buffer and the SD interface with less CPU copying. The SD driver and
filesystem still manage commands, card readiness, file contents and failures.
It does not remove the need for bounded queues or make a slow card instantaneous.

| Step | Work | Exit check |
| --- | --- | --- |
| v0.8a — Safe SD baseline | Reserve user-specified GP10–GP15; verify carrier and exact signal mapping. Establish a bounded S1 writer, FAT16/32 mount and exclusive new incident files, initially using a simple SPI block driver. Budget filesystem state, sector buffers, queue and stack before adding them. | Known records read back correctly; existing card files untouched; missing/full/removed card returns controlled errors without blocking detection. |
| v0.8b — DMA block transfers | Add SPI-paced DMA beneath the same filesystem/writer API. Claim separate available DMA resources and review interrupt ownership against Core1 capture's exclusive DMA_IRQ_1. Keep transfer buffers owned and unchanged until DMA completion; handle card busy, timeout, abort and cleanup separately. | Repeated block/readback checks, delayed/failed completions and removal tests show no buffer reuse or channel/IRQ conflict. Compare CPU time and transfer timing with the baseline. |
| v0.8c — Durable evidence handoff and combined qualification | Copy bounded incident records to S1; keep S3 the sole incident owner. Return completion ACKs containing both slot and incident ID only after the driver's card-completion and filesystem sync policy succeeds. Define safe evidence-slot release/reuse at this milestone. | Reject stale/mismatched ACKs; full/slow sinks and long attacks do not stop detection. Measure capture loss, alarm latency, stack/total RAM and soak with SD DMA active. |

The intended path is `incident/evidence -> bounded S1 record queue -> FatFs ->
SD block driver -> SPI + DMA -> card`. Capture's raw DMA buffers stay owned by
capture; the writer uses its own bounded buffers. DMA completion alone is not
permission to release evidence as durably stored: FatFs distinguishes buffered
writes and completion/sync requests. See the
[official SPI DMA example](https://github.com/raspberrypi/pico-examples/blob/master/spi/spi_dma/spi_dma.c)
and [FatFs write-completion contract](https://elm-chan.org/fsw/ff/doc/dwrite.html).

**GP10–GP15 is the reserved SD range, not yet an implemented signal map.**
The baseline roadmap remains SPI plus DMA; using all six pins for a native
four-bit SD interface would be a separate transport choice to confirm before
implementation. Do not assign the reserved pins to capture or alarm outputs.

Current v0.7-dev2 GP19 candidate reserves214976/216064bytes, leaving1088bytes.
SD buffers, filesystem
state and its task must fit a reviewed total budget; DMA is not a RAM saving
assumption. Keep the model/history capacities and agreed ceiling unchanged.
This addition changes the roadmap only; no SD/DMA storage code or wiring has
been enabled, and the existing NOOBS card contents remain protected.

### Dependencies and decisions still needed

The main dependency is **single-core kernel -> SMP -> kernel-integrated capture
-> analysis -> incidents/alarm -> combined qualification**. Read-only PHY work,
diagnostic PIO/DMA acquisition and host analysis replay can prepare inputs before
kernel integration. SD and notification integration follow stable incident APIs;
they must each be checked with the combined system.

- Confirm the LAN8720 module and clock source, receive timing and carrier pin
  compatibility. Current confirmed wires: MDIO GP2, MDC GP3, CRS_DV GP4,
  RXD0 GP5 and RXD1 GP6; REFCLK/nINT is not connected.
- Define the offered workload: packet sizes/rates, bursts, stream identities,
  monitoring topology and publisher SV encoding. Sequence gaps alone cannot
  measure all capture losses.
- Resolve the 100 ms latency target against model collection time. Four frames
  require three inter-arrival intervals from a cold start: 100 ms spacing alone
  consumes 300 ms before inference. Define warmup and attack scenarios or explicitly
  agree a model/requirement change; a 100 ms status tick is not this deadline.
- Agree evidence quotas, incident boundaries, retention, repeat alerts and stream
  expiry/admission. Exhausted evidence storage must allow continued detection.
- Retain the **216064-byte total RAM ceiling**, including static buffers,
  stacks, kernel objects, network buffers and peak TLS heap. Extra RP2350 RAM
  does not automatically change the agreed application budget.
- Keep rules in shadow mode and inference gating off. Skipped windows are
  unclassified; never automatically learn trust from live traffic. MMS support
  remains outside the current GOOSE/SV scope.

### Current next task

Build and qualify `-Profile detection` following the
[v0.7 procedure](app_program/health/README.md). This first candidate latches one
incident per stream/boot and retains the first two complete evidence windows;
exhaustion does not block detection. Alarm and supervisor preempt analysis on
Core0; a lower-priority Core0 task drains complete diagnostic lines without
formatting or making capture wait for USB. No additional Core1 service is
introduced. The build checks reserved RAM
against216064bytes, including a bounded libc heap and exception-stack
reservations. Actual stack peaks and physical arrival-to-LED latency still need
board evidence. GPIO output requires explicitly verified wiring; default is off.

The separate v0.6 analysis image/fallbacks remain available. Its board evidence
includes sequential GOOSE/SV and2000/2000 submitted mixed frames at96.45 achieved
submission fps. At139.96fps one of3000 submitted frames was unobserved; at187.79fps
eleven of4000 were unobserved. Submission rates/counts are not independent wire
measurements. Repeat the150-requested-fps case with a quiet baseline and isolate
acquisition if gaps recur; see the [throughput procedure](testing/throughput/README.md).
Do not attribute v0.6 results to the new service-loaded v0.7 image.

Latest v0.7-dev1 mixed1500-per-protocol test reaches GOOSE1500/SV1499,
2999accepted and1496windows, with one stream reset. It establishes two incidents,
two saved evidence windows and software alarm mask3; physical mixed LED is
user-confirmed. GOOSE default shows49positive windows/one incident/alarm mask1;
SV default shows100accepted/49windows/one incident/one saved record. USB output
is truncated, so unavailable fields are not reconstructed as passing evidence.
No independent sender completion/wire count or single-protocol physical LED
confirmation was supplied. Dev2 changes logging only; the missing SV is not
declared fixed. Preserve the original board logs and repeat with readable output.

### Capture regression procedure

Run `build/capture/pico2w_capture_v05.uf2` manually and require the v0.5-dev7-r1
banner. Follow the [100-packet baseline procedure](testing/traffic/README.md#4-baseline-verify100-unique-packets-before-testing-limits).
Match the sender's fresh run ID to TEST output: unique=100, expected=100,
missing=0 and complete=1, with no duplicates, conflicts or rejected candidates.
Repeat three batches before increasing rate or payload size. This establishes
baseline delivery, not maximum capacity or a general >=99% capture claim.
Preserve the dev6 functional fallback in `build/capture/`.

Kernel, adapter and test sources are currently local/ignored by this checkout's
Git configuration. Their presence here does not mean they are committed or
available in a fresh clone; no force-adding, staging or commits were performed.

Dev7-r1 adds bounded PHY discovery retries and diagnostics after the first dev7
board boot failed before identifying a PHY. The earlier discovery root cause remains unknown; see the traffic procedure for the next steps.

## Dev7-r1 first marked batch result

Dev7-r1 marked baseline batch1 PASS: run3829278217, source169.254.193.73,
100 unique/100 expected, missing/duplicates/reordered/conflicts/rejected/capacity0,
complete1. Matching sender JSON:100 planned/submitted,completed,64-byte UDP payload,
10fps limit,9.9582549s. UTC2026-11-08T15:40:46.728937 (=Nov9 JST).
Receiver completion at82.845632s, persists83.945632s and84.965632s.
During marked batch pauses64/high_arm3/no_sfd3/loss_gen67 unchanged; after completion
pauses66/loss_gen69. Final raw361,crc_ok/delivered358,bad_crc0,full/stall/DMA-disabled/
pool/queue/owner0,max_rearm1734us. This is one successful low-rate batch, not maximum
capacity/general capture percentage. Need two more fresh-ID100/100 batches at10fps
before rate/size stress. Logs saved testing/capture/logs/v05_dev7_r1_batch1_100_pass.txt
and matching v05_dev7_r1_batch1_sender.json. No source changes required by this result.

Dev2 corrects disabled-math SDK linkage discovered after the dev1 board panic.
The analysis build now verifies real software math helpers as well as absence
of VFP instructions. Dev2 board startup/self-check now passes; on-wire IEC/load acceptance remains pending.

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

The [throughput/limit-test guide](testing/throughput/README.md) describes the
current DMA gap risks,dev3 PERF counters and controlled rate/burst/size tests.
Low-rate functional success does not qualify production throughput.

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
