# Pico 2 W port

Four build profiles target Pico 2 W / RP2350 Arm Secure: SDK diagnostic,
single-core micro T-Kernel v0.3-r1, dual-core v0.4-dev2 acceptance, and
**v0.5-dev7-r1 packet capture/test accounting**.

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

The [capture walkthrough](app_program/capture/README.md) explains the new
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
    analysis/            future parser/features/models
    storage/             future S1 SD
    health/              future S4 evidence/supervision
    alarm/               future S5 alarm/notifications
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
```

The default profile is `diagnostic`. Outputs are separate:

| Profile | UF2 | Behavior |
| --- | --- | --- |
| diagnostic | `build/diagnostic/pico2w_diagnostic.uf2` | Read-only PHY address scan, then clock/time output. |
| kernel | `build/kernel/pico2w_kernel_v03.uf2` | Single-core scheduler/IPC checks, PHY scan and heartbeat. |
| capture | `build/capture/pico2w_capture_v05.uf2` | SMP receive pipeline: verified 10 Mbps negotiation, GP4/5/6 PIO/DMA, CRC, bounded frame handoff and counters. |
| smp | `build/smp/pico2w_kernel_smp_v04.uf2` | Original checks plus Core 1 affinity, delayed mailbox replies, shared counter and remote alarm/audits. |

The script works from any working directory and uses installed SDK 2.3.1,
CMake 4.3.4, Ninja 1.13.2, Arm GCC 15.2.1 and picotool 2.3.1. It accepts
`-SdkPath`, checks tool/native-command failures and restores PATH/SDK environment
on exit. New profiles must explicitly reconcile their SDK/library dependencies.
No SDK copy is required. Flashing is a separate board operation.

Diagnostic/kernel/smp profiles only read PHY management pins GP2/GP3.
The **capture profile writes and verifies LAN8720 10 Mbps negotiation settings**,
then samples confirmed GP4 CRS_DV / GP5 RXD0 / GP6 RXD1. REFCLK/nINT remain
unconnected. No packet transmission, notifications or assistant flashing.
Startup waits up to 15 seconds for USB CDC. Open the console promptly.

The [SMP implementation walkthrough](platform/smp/README.md) explains how the
two cores share a kernel, how context switches work, and when to use atomics,
spinlocks, mutexes, semaphores and mailboxes. v0.4-dev2 adds a cross-core
priority-inheritance mutex test and a plain counter protected by that mutex.

## Verification and implementation notes

On November 8, all four profiles built. MDIO read/write trace, generated
decoder and ownership/interleaving host tests pass. Automated BARR/format
checks pass 51 first-party C/header files. Third-party style is preserved.
See the capture walkthrough for hardware and performance limits.

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

Reviewed 2026-11-08. Target: **Pico 2 W / RP2350 Arm Cortex-M33 with
micro T-Kernel 3 SMP**. Single-core and SMP functional board checks pass;
capture is implemented and awaits hardware acceptance.
The versions below are proposed engineering milestones, not existing releases,
Git tags, or kernel version numbers. There are no completion-date estimates yet;
the kernel port and PHY timing need measured evidence first.

### Current position

| Area | Progress | Remaining acceptance |
| --- | --- | --- |
| v0.1 build | Four profiles generate RP2350 UF2s | Reproduce tool setup on a fresh checkout. |
| v0.2 PHY | Raw LAN8720 IDs board-confirmed; host reads/writes pass | Capture configuration/link readbacks on board. |
| v0.3 kernel | Nine functional checks board-pass | Repeat boots, soak and fault injection. |
| v0.4 SMP | Complete supplied functional suite passes, failures=0 | Longer stress, stack peaks, migration/reclaim and combined load. |
| v0.5 capture | Functional board capture and Core1-to-Core0 delivery pass:343 CRC-valid frames | Dev7-r1 first100/100 batch passes; two baseline repeats pending; burst/overload/gap and independent offered-frame loss measurements follow. |
| v0.6+ application | Analysis/storage/health/alarm remain placeholders | Integrate and qualify against the roadmap below. |

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
| **v0.8 — SD incident records** | S1: SPI/FatFs, bounded record queue, incident/evidence serialization, durable ACK matched to slot and incident ID, card-removal/full/error handling. Confirm Pico 2 W/carrier pins before enabling I/O. | Bench tests cover slow/full/removed card and ACK mismatches while detection runs. Accept FAT16/32 only; create exclusive new files under `IECLOG`, preserving all existing NOOBS files. No formatting or overwriting existing files. |
| **v0.9 — Wi-Fi and Telegram** | S5: adapt existing HTTPS/parser fixes to the qualified RP2350 runtime. Preserve one radio/lwIP owner, bounded notification queues/retries, independent alarm path and peak TLS allocation telemetry. Investigate driver/runtime feasibility during v0.3–v0.4. | Board tests cover successful delivery, disconnect, timeout, TLS failure and alert backlog with capture/analysis active. Record CPU, stack and heap peaks. Keep credentials outside source/export artifacts. |
| **v1.0 — Qualified combined system** | Integrate all required subsystems; fix versions/configuration and document workload, wiring, model/publisher schema, stream admission and evidence policies. | Demonstrate >=99% capture for the agreed sustained/burst workload, agreed arrival-to-LED latency, held-out accuracy and <=216064 bytes total peak RAM with required services enabled. Include startup, long attacks, queue exhaustion, SD/network faults and soak testing. Publish limits and reproducible results. |
| **v1.1 — Optional optimization** | Evaluate inference gating, stream expiry/admission improvements, model retraining or feature changes, and optional buzzer after the baseline is qualified. | Compare missed attacks, false alarms, latency, CPU and RAM against v1.0. Feature/history changes require retraining/re-export and replay. Enable gating only after explicit policy selection and evidence. |

### Subsystem responsibilities

| Subsystem | Folder | Planned responsibility |
| --- | --- | --- |
| Platform | `platform/` | Implemented RP2350 boot adapter, scheduling, SMP, interrupts, time and synchronization; further stress/resource qualification pending. |
| S1 | `app_program/storage/` | SD queue/writer, SPI/FatFs and durable completion acknowledgements. |
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

### Immediate next task

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
