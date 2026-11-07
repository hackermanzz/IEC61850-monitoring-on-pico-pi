# Pico 2 W port

This folder now has two build profiles: a standalone SDK clock/time/PHY-ID
image (v0.1-v0.2) and a micro T-Kernel **single-core** verification image
(v0.3). Both target Pico 2 W / RP2350 Arm Secure. They build successfully;
board execution and PHY identity remain unqualified. Dual-core SMP is v0.4.

The first board log reached kernel startup and passed the semaphore timeout
check, then panicked. Kernel revision `0.3-r1` is rebuilt with a PRIMASK
synchronization fix, 64 semaphore handoffs and persistent error reporting.
The user reports heartbeat/time output on the rerun, confirming progress past
the original panic. Full CHECK results, revision and PHY IDs remain to be
collected; the remaining board gates stay open.

```text
INF2004_Pico2W_Port/
  app_program/
    app_main.c           SDK main, console/time and PHY scan
    capture/mdio_phy.*   read-only Clause 22 management
    analysis/            future parser/features/models
    storage/             future S1 SD
    health/              future S4 evidence/supervision
    alarm/               future S5 alarm/notifications
  config/config.h        single-core static-buffer kernel profile
  platform/              RP2350 context, interrupts, tick and faults
  third_party/mtkernel/  recovered course kernel, license and provenance
  testing/host/          real MDIO driver with electrical trace stubs
  testing/kernel/        explicitly linked board acceptance suite
  testing/capture/logs/  future board PHY evidence
  build/                 generated outputs, ignored
```

## Build

From this directory in PowerShell:

```powershell
.\run_these.ps1 -Profile diagnostic
.\run_these.ps1 -Profile kernel
```

The default profile is `diagnostic`. Outputs are separate:

| Profile | UF2 | Behavior |
| --- | --- | --- |
| diagnostic | `build/diagnostic/pico2w_diagnostic.uf2` | Read-only PHY address scan, then clock/time output. |
| kernel | `build/kernel/pico2w_kernel_v03.uf2` | Real kernel scheduler/IPC checks, PHY scan, then kernel-delayed heartbeat. Core 1 remains parked. |

The script works from any working directory and uses installed SDK 2.3.1,
CMake 4.3.4, Ninja 1.13.2, Arm GCC 15.2.1 and picotool 2.3.1. It accepts
`-SdkPath`, checks tool/native-command failures and restores PATH/SDK environment
on exit. New profiles must explicitly reconcile their SDK/library dependencies.
No SDK copy is required. Flashing is a separate board operation.

The images initialize only confirmed management pins GP2 MDIO / GP3 MDC.
They do not reset/reconfigure the PHY, start Ethernet capture, change wiring or
send notifications. Startup waits up to 15 seconds for a USB CDC connection.
A successful build does not establish electrical compatibility or board execution.

## Verification and implementation notes

On November 7, both profiles built and generated RP2350 Arm Secure UF2s.
The MDIO host trace suite and the BARR-C/format checks passed for the 28 new
C/header files. Recovered third-party code retains its original style.

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

Reviewed 2026-11-07. Target: **Pico 2 W / RP2350 Arm Cortex-M33 with
micro T-Kernel 3 SMP**. The current kernel profile implements the single-core
bring-up stage; hardware acceptance remains pending.
The versions below are proposed engineering milestones, not existing releases,
Git tags, or kernel version numbers. There are no completion-date estimates yet;
the kernel port and PHY timing need measured evidence first.

### Current position

| Area | Active Pico 2 W port | Evidence and remaining work |
| --- | --- | --- |
| Build and board diagnostic | Implemented and rebuilt | Both profiles build with SDK 2.3.1 / Arm GCC 15.2.1 and generate UF2s. Board console/time evidence is pending. |
| PHY management | Implemented; host-tested | Complete read transactions, ACK handling, exact raw IDs and address scan. Host wire/timing/error tests pass; LAN8720 board IDs are pending. |
| Real packet capture | Not ported | No active PIO/DMA receiver, decoder or frame handoff in this folder. |
| micro T-Kernel platform | Single-core adapter and acceptance image build | Real course kernel common sources plus RP2350 PSP context, interrupts, tick and fault record. Runtime acceptance and SMP remain pending. |
| Analysis | Folder placeholder | Reusable parser, rules, features and generated models exist in the reference folder, not this executable. |
| Incidents, health, SD, alarm, notifications | Folder placeholders | End-to-end application behavior remains to be implemented. |
| Hardware qualification | Pending | Prior diagnostic success was user-reported without a supplied board log. No documented PHY-ID, packet capture, kernel/SMP, latency or full-system RAM proof. |

**v0.1-v0.3 software is implemented and buildable; their board acceptance gates
remain open.** v0.2 has host transaction tests; v0.3 has compiled on-board
acceptance tests. Neither result substitutes for running those images on RP2350.
It is too early for a meaningful overall completion percentage.

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
| **v0.5 — Capture acquisition and handoff** | S2: first PIO sample and DMA raw dump in the diagnostic harness, then integrate with qualified kernel tasks/ISRs. Port RMII decoding/FCS, separate sample buffers and bounded frame pool, nonblocking queue handoff, timestamps and drop counters. Resolve CRS_DV end-of-frame behavior and publish a loss-generation signal for losses before decoding. | Compare decoded bytes/FCS with known frames and raw timing. Inject DMA overrun, pool exhaustion and queue-full conditions; prove each frame block is released exactly once and loss is visible downstream. Then measure sustained/burst capture against independent offered-frame counts. |
| **v0.6 — Analysis parity** | S3: port parsing, per-stream state, features, generated RF models and shadow rules. Preserve four-frame windows/stride two, 128-sample SV history, 52 GOOSE/72 SV inputs, four GOOSE/one SV streams and all four raw evidence frames. Reconcile shared headers/APIs. | Host replay matches reference features/model outputs; malformed frames and loss/restart paths are checked. Target build and timed board replay establish inference cost and stack/RAM use. Confirm actual SV payload schema before claiming publisher compatibility. |
| **v0.7 — Detection, alarm and supervision** | S3 owns incident state; S4 provides bounded evidence storage and one watchdog supervisor; S5 drives the alarm. Either GOOSE or SV alone can create an incident. Add copied output queues, progress telemetry, evidence exhaustion policy and arrival-to-alarm timestamps. | GOOSE-only, SV-only and mixed cases activate the LED. Full/slow output sinks and long attacks do not stop detection. Inject a software task stall and distinguish healthy idle. Measure complete latency including window collection. |
| **v0.8 — SD incident records** | S1: SPI/FatFs, bounded record queue, incident/evidence serialization, durable ACK matched to slot and incident ID, card-removal/full/error handling. Confirm Pico 2 W/carrier pins before enabling I/O. | Bench tests cover slow/full/removed card and ACK mismatches while detection runs. Accept FAT16/32 only; create exclusive new files under `IECLOG`, preserving all existing NOOBS files. No formatting or overwriting existing files. |
| **v0.9 — Wi-Fi and Telegram** | S5: adapt existing HTTPS/parser fixes to the qualified RP2350 runtime. Preserve one radio/lwIP owner, bounded notification queues/retries, independent alarm path and peak TLS allocation telemetry. Investigate driver/runtime feasibility during v0.3–v0.4. | Board tests cover successful delivery, disconnect, timeout, TLS failure and alert backlog with capture/analysis active. Record CPU, stack and heap peaks. Keep credentials outside source/export artifacts. |
| **v1.0 — Qualified combined system** | Integrate all required subsystems; fix versions/configuration and document workload, wiring, model/publisher schema, stream admission and evidence policies. | Demonstrate >=99% capture for the agreed sustained/burst workload, agreed arrival-to-LED latency, held-out accuracy and <=216064 bytes total peak RAM with required services enabled. Include startup, long attacks, queue exhaustion, SD/network faults and soak testing. Publish limits and reproducible results. |
| **v1.1 — Optional optimization** | Evaluate inference gating, stream expiry/admission improvements, model retraining or feature changes, and optional buzzer after the baseline is qualified. | Compare missed attacks, false alarms, latency, CPU and RAM against v1.0. Feature/history changes require retraining/re-export and replay. Enable gating only after explicit policy selection and evidence. |

### Subsystem responsibilities

| Subsystem | Folder | Planned responsibility |
| --- | --- | --- |
| Platform | Future kernel/platform configuration | Boot, scheduling, SMP, interrupts, time, synchronization, memory and board services. Exact source layout follows inspection of the recovered course foundation. |
| S1 | `app_program/storage/` | SD queue/writer, SPI/FatFs and durable completion acknowledgements. |
| S2 | `app_program/capture/` | PHY management, PIO/DMA acquisition, decoding/FCS, frame pool, nonblocking delivery and loss telemetry. |
| S3 | `app_program/analysis/` | Parsing, stream histories, rules/features/models and sole ownership of incident decisions/state. |
| S4 | `app_program/health/` | Bounded evidence storage services, resource/progress reporting and the single watchdog supervisor. It does not make independent incident decisions. |
| S5 | `app_program/alarm/` | Local alarm and queued notifications through the radio-owning task. |

Provisional scheduling follows the course template's constraints: lower numeric
priority is higher, priorities 1–4 are reserved for system services, USB/radio
ownership remains on Core 0, and capture is a candidate for Core 1. Recalculate
task/object counts, priorities, stack sizes and IRQ ownership after recovering
the foundation; these are not yet implemented assignments for RP2350.

### Dependencies and decisions still needed

The main dependency is **single-core kernel -> SMP -> kernel-integrated capture
-> analysis -> incidents/alarm -> combined qualification**. Read-only PHY work,
diagnostic PIO/DMA acquisition and host analysis replay can prepare inputs before
kernel integration. SD and notification integration follow stable incident APIs;
they must each be checked with the combined system.

- Obtain/inspect the course kernel foundation and record its exact revision,
  license and RP2350 changes. A compiler CPU-flag change is only one part of the port.
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

Run the documented board checks in order: diagnostic clock/time and repeatable
PHY IDs, then the single-core kernel acceptance suite and heartbeat. Capture the
raw output and debugger fault evidence; correct any observed failures before
claiming v0.1-v0.3 qualified or enabling SMP. Direct implementation of v0.1-v0.3
is now user-authorized; continue supplying ample explanatory comments and
BARR-C-style code. This does not authorize Git releases, wiring changes, live
notifications or automatic resumption of the earlier cleared hardware goal.
