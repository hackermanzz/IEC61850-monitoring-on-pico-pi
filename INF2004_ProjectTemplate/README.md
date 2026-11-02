# IEC 61850 monitor: shared foundation and interfaces

This integrator checkpoint establishes the micro T-Kernel 3 SMP runtime and
contracts for five contributors. **All application subsystems are disabled.**
Startup prints that state and reports real kernel RAM statistics once per second.
It creates no capture, analysis, watchdog, SD, alarm or notification owners.
The USB console is enabled by default; the optional Pico W radio service remains available with WIFI=cyw43.
No network clients are enabled. The optional radio driver retains the template diagnostic scan behavior; leave WIFI=none to keep the radio off.

## Contributor boundaries

| Subsystem | Responsibility | Integration contract |
|---|---|---|
| S1 | SD incident-value export | Copied bounded records from S3; durable slot + full incident ID ACKs back to S3 |
| S2 | LAN8720 capture | Owned fixed-pool frames to S3, including valid length, sequence and microsecond uptime |
| S3 | GOOSE/SV analysis and rules | Sole analyzer/incident owner; copied notices to S5, records to S1 and statuses to S4 |
| S4 | Health, watchdog and evidence support | Copied status snapshots; only eventual watchdog owner; evidence implementation called only by S3 |
| S5 | Alarm and Telegram | Independent high-priority latched alarm; bounded notice submission; networking stays on radio service owner |

Each contributor branches from this checkpoint and supplies real implementation
and validation in subsequent commits. The interface headers are declarations and
data formats, not working subsystem implementations. The old sample subsystem C
files have been removed from this checkpoint. No success-returning replacement
implementations are used. `build_make/mtkernel_3/app_program/subdir.mk` explicitly
links only shared runtime sources, so unrelated local module files are not built.

## Shared contracts

- Every subsystem declares `subsystemN_init()` and `subsystemN_start()`. During
  later integration, initialize all shared objects before starting any owners.
  The foundation does not call those unimplemented entry points.
- Task creation uses `app_start_task_ex()` with explicit priority, stack bytes
  and processor affinity. Lower numbers mean higher scheduling priority.
- Planned owners: S1 SD Core0/priority18; S2 capture Core1/8; S3 analysis Core0/10;
  S4 health Core0/7; S5 alarm Core0/6. Radio remains its existing Core0 owner.
- A successful mailbox send transfers ownership of one frame block. Failed
  sends retain sender ownership. The receiver releases a block exactly once.
  Capture acquisition and copied notice/storage submissions must be nonblocking.
- Frame capacity is 1518 bytes. Sequence is 32-bit; timestamps are 64-bit
  microseconds since boot, not UTC. Use copied status messages across owners.
- Four-frame analyzer windows use stride two. The API reserves four GOOSE and
  one SV stream, preserving the existing model's feature/history requirements.
  Models, rule algorithms and frame retention implementations are not included.
- Incident ACKs match both evidence slot and full 64-bit incident ID. A durable
  export may mark an active episode, but release waits until its closure.
- No application task takes over the radio service's lwIP ownership. Future
  HTTPS requires private credentials, trusted CA and UTC; none is enabled here.

The interface headers under `app_program/subsystem1` through `subsystem5` and
`monitor_status.h` define the exact types. Change shared contracts through the
integrator rather than independently changing a consumer's assumptions.

## Build and verify

Use WSL/Linux, GNU make, a host C++ compiler, Arm GNU GCC and Pico SDK **2.2.0**
with its TinyUSB/CYW43 submodules. The kernel-only UART profile needs no SDK.
Run from `INF2004_ProjectTemplate`:

```sh
export PICO_SDK_PATH=/path/to/pico-sdk-2.2.0
python3 tools/build_monitor.py PICO_SDK_PATH="$PICO_SDK_PATH"
python3 tools/build_monitor.py CONSOLE=uart WIFI=none SMP=0 STACK_DIAG=1 TEST=1
python3 testing/host/run.py
```

The wrapper writes build logs under `testing/build_logs/` and converts the ELF
to UF2. Images have a `_foundation_stk0` or `_foundation_stk1` suffix. Nothing
flashes the board. Build profiles share one object tree; run them sequentially.
Profile invalidation includes SDK path and build-rule fingerprints.

`INTEGRATION_STAGE=foundation`, `CAPTURE=disabled`, `NET=none`, `STORAGE=0`,
`TELEGRAM=0`, `WATCHDOG=0` and `PINS_CONFIGURED=0` are enforced. Attempts to enable
unfinished application features fail during makefile parsing. `TEST=1` does not
claim that unimplemented subsystems have passed tests. `STACK_DIAG=1` paints task
stacks and queries the real initial task; painted usage is a lower bound on bytes
written, not an exact worst-case stack requirement. Service report hooks are weak
until the future S4 collector is introduced.

Host tests exercise production kernel allocation, coalescing, overflow/OOM,
reallocation, allocation-peak accounting and stack painting/query failure paths
under ASan/UBSan. Target compiler checks validate the shared frame/record layouts
and cross-subsystem headers. Native pointer widths and mocked CPU contexts are
test substitutes, not hardware timing or general SMP allocator qualification.

## Configuration and limits

`monitor_config.h` holds planned pins, priorities, stack budgets and the agreed
216064-byte total RAM ceiling. Those are contracts/reservations, not allocated
application resources in this checkpoint. `foundation_ram` reports actual kernel
allocations plus fixed reservations; it is not a worst-case runtime qualification.
Kernel object tables reserve headroom for later integration. Heap clients must
remain on Core0 unless a separate SMP synchronization change is reviewed.

Planned PHY connections are MDIO GP2, MDC GP3, CRS_DV GP4, RXD0 GP5/RXD1 GP6.
Reserve GP10-15 for the Maker Pi Pico SD socket and GP23/24/25/29 for the radio.
GP19 is the unverified planned alarm assignment. The foundation accesses none of
these external application pins. Future capture still needs PHY clock and actual
loss/latency qualification; the 99% capture and 100 ms alarm targets are unproven.

Only example configuration headers are shared. Real Wi-Fi/Telegram headers,
binaries, Git exports, working notes and non-README Markdown stay ignored. Source
and build entry points must remain independent of legacy `rmii/` and `FreeRTOS/`.

The micro T-Kernel BSP retains T-License 2.2. Imported interface headers preserve
their existing notices, including BSD-3-Clause/Sandeep Mistry where applicable.
The Pico SDK remains an external dependency with its own source licenses.
