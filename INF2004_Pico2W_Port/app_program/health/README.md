# v0.7 detection, evidence, alarm and supervision

The `detection` profile builds **0.7-dev2** on the v0.6 parser/rules/RF pipeline.
Dev2 now has board evidence for independent GOOSE/SV incidents,retained evidence,
software alarm and user-confirmed physical LEDs. Mixed also retains two records
and applies mask3, but records four SV frames fewer than the1500-each plan.
**Complete v0.7 acceptance remains pending.** Dev2's complete-line logging works
through these runs;2–3 pre-test diagnostic line drops remain explicit. Existing
capture-rate shortfalls and watchdog/stall acceptance remain open.
The separate `analysis` profile retains v0.6 behavior and its own output directory.

The console replacement now forwards USB input to the original SDK backend.
This fixes the dev1 Wi-Fi UTC command, which could not receive typed characters
through an output-only replacement driver. Queued output ownership is unchanged;
Wi-Fi dev2 normally obtains its clock automatically and needs no typed command.

Think of capture as a conveyor, the analyzer as a collector that examines four
items together, and evidence storage as two trays beside the conveyor. When the
model reports a positive result, S3 records an incident and S5 latches the alarm.
If both trays are occupied, the conveyor and collector continue working.

## First-version policy

- Either GOOSE **or** SV alone can trigger; there is no cross-protocol agreement
  requirement. The generated model's positive label is used unchanged. A model
  positive is a detection decision, not proof that a real attack occurred.
- Rules remain shadow-only, gating off, no trusted profiles. Missing profiles,
  gaps, malformed frames and skipped/unknown results do not independently alarm.
- There is at most one incident per full stream identity per boot, with five
  ledger entries. Identity includes protocol, APPID, both MAC addresses and the
  complete stream ID. The ledger does not rely only on a hash.
- Incidents and the alarm latch until reboot. Benign results or capture resets
  do not clear them. Repeated positive windows increment counters; they do not
  allocate more records or flood the output queue. Automatic clearing, episode
  expiry and repeat alerts are deliberately deferred policy choices.
- Two evidence slots retain the first two incidents until reboot. No overwrite,
  eviction, filesystem writes or durable-storage claim. A full slot set prevents
  additional evidence copies, never detection or the alarm request. If the
  five-entry ledger fills, additional identities are counted as untracked positive
  windows; the already-latched global alarm remains on.

## What the code does

These are actual excerpts, not standalone files to paste together.

In `analysis/incident.c`, `incident_observe` creates an event even when evidence
cannot be saved:

```c
    p_event->incident_id     = g_stats.incidents;
    p_event->protocol        = (uint32_t) p_result->protocol;
    p_event->window_start_us = p_result->batch_packets[0].timestamp_us;
    p_event->newest_end_us   = p_identity->timestamp_us;
    p_event->decision_us     = decision_us;
    p_event->evidence_saved  = evidence_save(p_event->incident_id, p_result);
    return true;
```

S3 calls this synchronously inside `analysis_port_observe`, before the next
analyzer call can reuse the window. S4's `evidence_save` copies all four raw
frames (without Ethernet FCS), their metadata and parsed values, and all 52 GOOSE
or 72 SV model inputs. A failed/incomplete copy is counted and never published.
The stored bytes do not point back into the capture pool or analyzer history.
Only the analysis owner can read the record API in this version; no cross-task
borrowed evidence pointers are passed to future sinks.

In `alarm/alarm.c`, `alarm_submit` publishes the persistent request before trying
the four-message copied queue:

```c
    atomic_fetch_or_explicit(&g_requested, mask, memory_order_release);
    if (E_OK != tk_snd_mbf(g_queue, p_event, sizeof(*p_event), TMO_POL))
    {
        atomic_fetch_add(&g_drops, 1u);
    }
```

`TMO_POL` means return immediately if the queue is full. A dropped event loses
its detailed timing telemetry; it cannot cancel the independent alarm request.
The alarm task applies that request before draining at most four events per
cycle, then sleeps for 10 ms. It checks again after receiving each event so a
producer running between the initial request read and receive is handled too.

## Scheduling and memory

Lower priority numbers run first. Detection uses five application tasks:

| Owner | Core | Priority | Static task stack |
| --- | --- | --- | --- |
| S3 capture consumer/analysis/incident owner and sole formatter/libc-state owner | 0 | 7 | 4096 bytes |
| S5 local alarm | 0 | 5 | 2048 bytes |
| S4 supervisor | 0 | 6 | 2048 bytes |
| Diagnostic USB backend drain (no printf) | 0 | 8 | 1536 bytes |
| S2 raw capture/decode worker | 1 | 6 | 4096 bytes |

Alarm and supervisor can preempt a continuously runnable consumer. Core1 still
uses the dedicated runnable WFE worker; no additional Core1 service was added.
The supervisor sends SEV every 50 ms to wake its healthy idle loop. Capture IRQs
remain free of kernel calls. Service tasks do not print or use radio/lwIP/libc
state. USB diagnostic write/stdio-lock timeouts remain zero. Dev1 SDK writes
could discard suffixes when its 64-byte FIFO filled. Dev2 queues
complete lines before reaching that backend, then a priority8 task checks free
space and submits at most64bytes per1ms-requested wake (kernel tick10ms). It
retains the rest of the line until later. The SDK remains responsible for its
USB mutex/TinyUSB work; only this task writes the original backend. The analysis
owner still does all printf formatting, so the drain task needs no per-task libc
state. No capture IRQ or Core1 task writes this queue or USB.

The static2048-byte queue assembles lines up to254text bytes plusCRLF. Full or
long lines are discarded as whole records and counted in LOG dropped_lines;
partial printf calls are joined before publication. Logs remain best effort,
not lossless evidence or a physical USB-disconnection framing guarantee. The
queue adds no waiting to analysis. The output task yields after every chunk and
is intentionally not a watchdog-critical owner. Host slow-sink/preemption/full/
overlong/ring-wrap tests pass. These board runs report a452/1536-byte console
watermark and readable steady logs, with diagnostic drop counts unchanged
during traffic. Target worst-case timing/stack qualification remains open.
This does not establish capture latency under USB service load. There are two message
buffers (capture pointers and copied alarm events)
and one fixed capture pool; existing kernel object limits remain unchanged.

The preserved builds verified reserved RAM against the former **216064-byte**
limit. The user-approved Pico 2 W ceiling is now **479232 bytes**, 90% of520KiB,
with52KiB reserved. The restored local checker reads config/ram_budget.h and
now enforces the new limit. Its report is
`build/detection/ram-verification.json`. It counts main RAM from the vector table
through all RAM code/data/BSS/padding, a bounded 2048-byte libc heap, both SDK
exception-stack reservations and any scratch sections. Static task stacks,
kernel buffers, capture buffers, analyzer histories and evidence slots are
already inside that main-RAM span; they are not added twice.

The strong `_sbrk` replacement actually enforces the libc bound and refuses
Core1 allocations. Merely declaring a small `.heap` section would not do this:
the SDK's weak implementation can grow towards `__StackLimit`. A rejected
allocation returns failure instead of borrowing the remaining RP2350 RAM.
This reservation check does **not** prove absence of stack overflow. Consumer,
alarm, supervisor and USB drain watermarks remain estimates, requiring board
stress tests. Current GP19 dev2 reserved RAM is214976/216064bytes, leaving1088;
the dev1 baseline was211088bytes. The delta3888bytes includes the queue and
new stack, not any reduction to model/history/evidence capacity.
Future SD/TLS services share the approved479232-byte combined budget; include
their static resources and peak allocation rather than checking services alone.

### Capture-to-analysis SRAM

The current DMA transfer is **PIO receive FIFO to raw samples in SRAM**. Core1
then decodes samples into a frame-pool block. The handoff to Core0 analysis sends
that block's address through the kernel queue; it does not DMA/copy the whole
packet to another analysis input buffer. Both cores can access the same SRAM.

Actual excerpt, `capture/capture_pipe.c`, `capture_pipe_offer` (not standalone):

```c
    if (E_OK != tk_snd_mbf(g_queue, &p_frame, sizeof(p_frame), TMO_POL))
```

`p_frame` is a pointer: a four-byte address on this target. The kernel copies its
value from `&p_frame` into the queue. The frame itself stays in the pool until
Core0 finishes analysis and releases it exactly once. The analyzer makes its
required history/evidence copies before that release; the full pipeline is not
entirely free of copying.

Current target ELF symbol sizes give this selected buffer breakdown:

| Storage | Reserved bytes | Meaning |
| --- | ---: | --- |
| Two raw capture slots | 56112 | 56000 sample bytes plus slot metadata; DMA fills sample arrays. |
| Eight decoded frame blocks | 12544 | Eight1568-byte blocks, shared with the consumer. |
| Four-entry capture message buffer | 32 | Four addresses plus kernel message headers; no packet payload copies here. |
| GOOSE/SV stream-state arrays | 71480 | Analyzer history/state, including per-stream retained raw frames; excludes separate analyzer scratch/completion storage. |
| Two incident evidence records | 14560 | Independent retained window copies; includes metadata, values and features. |

The capture slots, frame pool and handoff queue together reserve68688bytes.
The table is not a full firmware total. All these buffers are already included
in the dev1 reservation211088/216064bytes. Dev2 adds the console queue/task,
bringing the current GP19 candidate to214976bytes, leaving1088bytes. Do not add
the listed capture/analysis/evidence buffers again when budgeting SD. Fixed allocation does not grow with every packet.
Under excess load buffers can fill, causing pauses/drops rather than more SRAM
allocation. DMA throughput and stack peaks still require target measurements.

Adding a memory-to-memory DMA stage between capture and analysis would not
remove the existing raw/decoded/history buffers. The present address handoff
already avoids a separate packet-sized handoff copy. Future SD DMA requires its
own explicitly budgeted transfer-buffer ownership and contention review.

## Supervision

The supervisor monitors task-loop heartbeats, not packet totals. Thus an idle
wire or disconnected cable after startup can be healthy. It samples consumer,
worker and alarm counters every 50 ms. No progress for 1 second latches a stall:
mask bits 1=consumer, 2=worker, 4=alarm. Counter wrap is harmless when the sampled
value changes. A later heartbeat cannot erase the latched failure.

Default mode observes and reports stalls without resetting. With
`-WatchdogReset`, this single supervisor enables the hardware watchdog for
3000 ms and feeds it only while every monitored owner progresses. A stalled
supervisor also stops feeding it. USB startup/PHY/link waiting precedes watchdog
enable, so waiting for the first link does not cause a reset loop.

`-StallTask consumer|worker|alarm` injects a deliberate task-loop stall after
`-StallAfterMs` milliseconds from service startup (default 10000). Interrupts
and kernel scheduling stay enabled. This exercises a software stall, unlike
unplugging the cable. No injected build is a normal operating image.

## Build and board acceptance

From the repository root, build the default candidate:

```powershell
.\INF2004_Pico2W_Port\run_these.ps1 -Profile detection
```

Output: `build/detection/pico2w_detection_v07.uf2`. Default settings are
**GPIO disabled, reset disabled, no injected stall**. `ALARM applied` then means
the software alarm service processed the latch; it does not mean a physical LED
lit. The Pico2W onboard LED is radio-controlled and is not driven by this GPIO
service. GP19 is supported only as an explicitly wired active-high external LED
output, with appropriate resistor and confirmed wiring. No pins are inferred.

The supplied dev1 logs useGP19, and the user confirms its LED lights for mixed
traffic. This command enables that same GP19 assignment:

```powershell
.\INF2004_Pico2W_Port\run_these.ps1 -Profile detection -AlarmGpio 19
```

Flashing and traffic sending are manual user operations. For each acceptance
case, reboot, record the exact image/settings and complete serial log, require
the `0.7-dev2` banner, analysis self-check, copied-queue self-check, PHY/link and
PIO15 checks. Use the existing [IEC sender](../../testing/traffic/README.md),
explicitly selecting the actual wired interface (26 in previous successful
reports; list interfaces again rather than assuming that index is permanent).

1. Healthy idle for at least 60 seconds: all three heartbeat counters and HEALTH
   checks advance; stalled_mask=0. Repeat after disconnecting the cable **after**
   startup. Idle alone must not create an incident.
2. GOOSE-only, then a fresh-boot SV-only case: 100 frames at 10 total fps. Expect
   49 scored windows, one incident, one saved record, requested/applied=1 for
   GOOSE or 2 for SV, no copy errors, and actual LED assertion when GPIO enabled.
   The synthetic publisher is not independent attack ground truth.
3. Fresh-boot mixed: 100 per protocol, 10 total fps. Expect 98 windows, two
   incidents, two saved records and requested/applied=3. Save sender JSON too.
4. Repeat a positive stream for a long run: repeated counts increase, evidence
   stays bounded and capture/analysis continue. To exercise evidence-full on
   board, add a third valid admitted identity using a controlled publisher;
   the supplied sender's fixed identities alone cannot fill a third slot.
   Also stop reading the USB console during traffic, then resume; detection
   must continue, while diagnostic text may be missing by design.
   Host tests already exercise this path and deliberately full/slow alarm sinks;
   a zero queue_drop counter on an ordinary board run does not prove overload.
5. Build with `-StallTask worker` in monitor mode: expect injected_mask=2 and,
   within about 1 second of lost progress, stalled_mask=2. Repeat for alarm
   (mask4). Consumer-stall stops console reporting; use SWD or the reset variant
   to observe it. A subsequent normal image must contain no fault injection.
6. Build an explicitly labelled reset test with `-WatchdogReset -StallTask worker`
   (and optionally the verified GPIO). The watchdog should reboot approximately
   3–4 seconds after lost progress. Require the next banner's watchdog_reboot=1;
   the injected image will repeat the test until replaced. Repeat for the other
   owners, and observe that healthy idle does not reboot. Restore the default
   build settings afterward; the runner always supplies them explicitly.

Physical LED transitions, actual watchdog resets, queue-pressure behavior,
capture/stack effects under service load and soak remain board acceptance work.

## Latest dev2 board results

The three supplied dev2 logs are archived verbatim in `testing/detection/logs/`,
with original hashes and a separate JSON review. The user explicitly confirmed
the physical LED lit for BOTH new single-protocol tests. No new sender JSON or
independent physical timing/wire count was supplied. Mixed is compared with the
previously stated1500-per-protocol plan.

| Case | Accepted / model windows | Incident / evidence / software alarm |
| --- | --- | --- |
| GOOSE | 100 /49GOOSE | 1incident,1record,requested/applied1,physicalLED confirmed |
| SV | 100 /49SV | 1incident,1record,requested/applied2,physicalLED confirmed |
| Mixed | 2996:GOOSE1500/SV1496;1491windows:749/742 | 2incidents,2records,requested/applied3;prior dev1 mixed physicalLED confirmed |

All cases show zero evidence copy errors,alarm event queue drops,capture
pool/queue drops and ownership errors. These are functional protocol/evidence/
alarm passes; a zero counter does not prove gap-free acquisition. Mixed has
four history resets and seven fewer score windows than the1498 expected for
complete1500each. Model windows are not a packet-loss counter.

Mixed last pre-IEC report16.694441s -> final complete40.080897s: raw pauses29->49,
high_arm10->18,no_sfd7->12,short2->4,bad_crc0unchanged,loss_gen48->83 andANA
gaps38->64. Capture full/stall/DMA-disabled and decoded pool/queue drops remain0.
Background103->147; reception faults cannot be assigned to individual missing
SV packets from these counters. This remains an acquisition lead,not proof that
the DMA engine saturated or the analyzer's output queue overflowed.

GOOSE/SV/mixed request->apply intervals are4935/13764/17241us. Oldest-frame-end
to alarm-service spans308180/316652/60818us; newest-frame-end spans7203/15667/
19455us. The single-protocol cold windows demonstrate the~300ms collection cost
at10fps. These exclude first-bit/pre-ISR latency and are not physical attack
arrival-to-LED measurements. Do not claim a100ms deadline from inference time.

LOG dropped_lines is2(GOOSE),3(SV),2(mixed),already present before IEC traffic
and unchanged during each batch. Whole-line logging is usable;startup output is
not lossless. The SV paste ends mid-line,so use its preceding complete reports.
Observed watermarks:consumer2124/4096,alarm188/2048,supervisor220/2048,console
452/1536. HEALTH stalled_mask/injected_mask/reset remain0; these logs do not
exercise deliberate stalls,hardware reset,full/slow sinks or long soak.

The verified local dev2 UF2/ELF is retained as
`build/detection/known-working-v07-dev2-functional.*`. Local hashes match the
previously verified candidate;no independent device hash was read. No rebuild,
new firmware changes,assistant flashing or additional commit was needed to
record this evidence. Next run the worker-stall monitor/reset procedure above
and continue controlled acquisition characterization with matching sender JSON.

## Worker-stall monitor test: board PASS

The supplied dev2 worker-stall monitor log shows healthy progress before the
fault,then `injected_mask=2` at report16.225705s and `stalled_mask=2` at
17.325704s. The worker heartbeat freezes at14415375; consumer/alarm counters,
HEALTH checks and console reports continue through67.925704s. The failure stays
latched for at least50.6seconds after its first visible detection. There is one
boot banner and `reset=0` throughout,matching the monitor-only test.

These report times are sampled about one second apart; their difference does
not measure exact injection-to-detection latency. The original log and review
are preserved under `testing/detection/logs/v07_dev2_worker_stall_monitor_*`.
No publisher was needed; zero IEC windows/incidents/alarm is expected here.
No firmware change is indicated. This verifies worker-stall detection and
continued operation,not hardware-watchdog reset or the other stalled owners.

The worker reset variant used after this monitor pass was:

```powershell
.\INF2004_Pico2W_Port\run_these.ps1 -Profile detection -AlarmGpio 19 -WatchdogReset -StallTask worker
```

Manually flash it,keep Ethernet connected and capture serial output. Around
10seconds after service startup the worker stalls; expect a hardware reset
about3–4seconds after lost progress and `watchdog_reboot=1` in the next banner.
Capture that next boot too. This injected image repeats the test after every
boot until replaced. Restore normal operation by building/flashing without
`-WatchdogReset` and without `-StallTask worker`. No traffic sender is needed.

USB serial can disconnect when the Pico resets. PuTTY may remain inactive;
after the COM port returns,use its title-bar menu **Restart Session**,or open a
new serial session. Keep USB power connected while doing this: a separate power
cycle would change the reset-cause test. Firmware waits up to15seconds for USB
CDC connection at boot. A terminal disconnect alone is not proof of watchdog
reset; require the new startup banner's `watchdog_reboot=1` and restarted time
counter. See [PuTTY's session controls](https://www.puttyssh.org/0.83/htmldoc/Chapter3.html#using-newsession).

## Remaining supervision sequence

The latest watchdog-enabled idle log now covers83.779985seconds of advancing
tasks/checks withreset1,injected/stalled0,no incident andno reboot. The user
confirms Ethernet was unplugged,but not its timing. This is an observed
functional pass,not proof of60seconds in each cable state orlongsoak.

**Current priority is feature development.** The user explicitly deferred extra
qualification rounds as excessive. Do not require repeat idle/stall ornew
evidence-exhaustion test batches before implementing the next feature. Keep
the following procedures as optional future qualification references andcarry
forward known capture/latency/RAM limits;the system is not fully qualified.

The consumer-reset test now supplies its post-reboot log: banner
`watchdog_reboot=1`,analysis selfcheck4633us,queue/pool/PHY/link/PIO checks pass.
New runtime reports13.032281->15.189385s andHEALTHchecks20->38 show restarted
tasks progressing,withreset1 and injected/stalled0 before the next fault.
This accepts the prepared consumer test's recovery evidence;the excerpt begins
after reset and does not measure the fault-to-reset interval. It is not a
healthy-idle test because the injected image would stall the consumer again.
The exact log/review is preserved under
`testing/detection/logs/v07_dev2_consumer_watchdog_*`.

The alarm-monitor candidate now also passes on board: `injected_mask=4` first
appears at27.465809s and `stalled_mask=4` at28.485810s. Alarm heartbeat stays501,
while consumer/capture/check counters and console continue through60.855814s,
at least32.370004seconds after detection,withreset0 andonebootbanner. Sampled
report spacing is not exact fault-detection latency. LOGdrops2remainconstant;
console watermark464/1536. The original log/review is archived as
`testing/detection/logs/v07_dev2_alarm_stall_monitor_*`. This verifies the alarm
owner's stall detection,not physical actuation during a failed alarm task.

After the monitor log passed,the user confirmed the worker watchdog-reset test
works correctly following PuTTY reconnection. This is recorded as a user-reported
functional pass; no additional reset-cycle log or exact timing measurement was
supplied. Continue with these separately named dev2 qualification images under
`build/detection/` (UF2 and matching ELF/settings/hash records):

| Image | Watchdog / fault | What to record |
| --- | --- | --- |
| `v07-dev2-alarm-stall-monitor.uf2` | Reset OFF; alarm task stalls after10seconds | Board PASS:mask4,alarm beat501 frozen;otherowners continue32.37seconds after detection. |
| `v07-dev2-consumer-watchdog-reset.uf2` | Reset ON; consumer stalls after10seconds | Post-reset board log PASS:watchdog_reboot1,successful startup and advancing task counters. Exact pre-fault/reset timing not supplied. |
| `v07-dev2-watchdog-idle.uf2` | Reset ON; no injected fault | At least60seconds quiet after link ready,withreset1 but injected/stalled0 and heartbeats/checks advancing;no false reset or incident. Repeat with Ethernet unplugged AFTER startup. |
| `v07-dev2-normal-gp19.uf2` | Reset OFF; no injected fault | Normal functional fallback withGP19. Use after qualification tests. |

All four useGP19 and unchanged v0.7-dev2 source. They are built candidates,not
additional board passes. No publisher is required. Flash ONE test at a time,
save its entire log,then proceed to the next. Fault-injection reset builds
repeat their failure after each reboot until replaced. The generic
`pico2w_detection_v07.uf2` is restored to normalGP19/resetOFF/no-fault settings
after preparation;use the explicitly named watchdog-idle image for the next
test. Five application tasks and all model/evidence capacities remain unchanged.

For the idle check,replace the injected image with `v07-dev2-watchdog-idle.uf2`,
keep Ethernet connected until link/startup completes,and capture60seconds with
no publisher. Then unplug onlyEthernet and capture another60seconds while USB
power stays connected. `HEALTH reset=1` means watchdog reset is ENABLED,not that
a reset occurred. Require injected/stalled0,advancing task/check counters,no new
boot banner andno incident. Reconnection/reset evidence from injected tests does
not substitute for this healthy-idle false-alarm check.

The idle test covers healthy inactivity with watchdog feeding;unplugging a cable
is not another software-stall injection. Full/slow evidence/output sinks,long
attacks,soak,capture shortfalls and complete physical alarm latency still need
qualification. S1 SD/DMA remains the later v0.8 roadmap work.

## Earlier dev1 board evidence

Original pasted logs are preserved byte-for-byte locally under
`testing/detection/logs/`, with hashes and a loss-aware JSON review. User confirms
GOOSE/SV default100frames/10requested fps, mixedcount1500PERprotocol and the
physical mixed LED. No matching sender completion/rate reports were supplied.

| Case | Readable evidence | Limit |
| --- | --- | --- |
| GOOSE | selfcheck4744us;49positive windows;one incident;software requested/applied1;one alarm event | Final accepted/evidence fields truncated. Physical GOOSE-only LED not separately confirmed. |
| SV | selfcheck4761us;100accepted;49windows;one incident;one saved evidence record;zero copy errors;nonzero first_apply timestamp | Post-incident alarm-mask field truncated. Physical SV-only LED not separately confirmed. |
| Mixed | selfcheck4732us;GOOSE1500/SV1499,2999accepted,1496windows;two incidents;two evidence records;requested/applied3;events2;zero readable alarm/capture queue/pool/ownership drops;physical LED confirmed | One SV unobserved against3000planned,one stream reset;not independent wire-loss proof;readable HEALTH mask0 is not a long-soak/stall test. |

First request->apply intervals are7342us(GOOSE),16943us(SV),5355us(mixed).
Mixed window-to-service max61817us,newest-to-service20482us are software intervals,
not physical arrival-to-LED measurements. Existing gaps/pauses and the one SV
shortfall are not fixed by the logging change. Do not reconstruct missing fields
as zeros or label synthetic model positives as validated real attacks.

These truncated dev1 records are superseded for single-protocol acceptance by
the readable dev2 results above. Watchdog/stall,full evidence ledger/sinks,long
attacks and worst-case service-load remain open. Save sender JSON and check LOG
dropped_lines before treating a serial excerpt as complete.

## Reading timing and counters

`first_request_us` is the first persistent alarm request time; `first_apply_us`
is sampled immediately after the software service applies it (after gpio_put
when enabled). Their difference excludes inference and window collection.
`window_to_service_max_us` measures oldest frame end-ISR-service to event
processing; `newest_to_service_max_us` starts from the newest frame instead.
These are conservative software service intervals, not independent physical
arrival-to-LED measurements. The frame timestamps exclude first-bit arrival
and pre-ISR latency, and event drops make timing samples incomplete.

The four-frame model requires three inter-arrival intervals from a cold start.
At 10 frames/s for one protocol, that alone is about 300 ms; inference plus a
10 ms alarm loop cannot establish a 100 ms full-system deadline. Measure attack
arrival/window positions and the physical output independently, then resolve
the target without silently changing model history or excluding warmup.

Zero copy_errors means attempted copies succeeded; it does not mean every
incident has evidence (check full and saved). Zero queue_drop means attempted
event sends fit; it does not prove capture was lossless. Existing PERF/CAP/ANA
counters retain their v0.6 meanings and limits.
