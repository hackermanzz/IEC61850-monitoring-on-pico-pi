# Understanding the v0.5 capture implementation

v0.4-dev2 now has a supplied passing board log: all listed kernel/SMP checks
PASS, failures=0, worker_core=1, counter=10000, mutex_counter=2000 and
wrong_core_ticks=0. This is functional board evidence, not a long stress test.

v0.5-dev6 adds the capture subsystem. It builds and its host tests pass, but
real CRC-valid packet reception now has board evidence; capture percentage
still needs independent measurement.
The code blocks below are **excerpts of the implemented source**, not separate
files to paste together. Each names its source and function.

## 1. Two workers, one delivery line

A **core** is a physical processor. A **task** is a scheduled program with its
own saved registers and stack. A **peripheral** is hardware that performs a
specialized job, such as sampling pins or moving data.

```text
LAN8720 Ethernet PHY (the chip that turns cable signals into digital data)
          |
          | GP4 CRS_DV, GP5 RXD0, GP6 RXD1
          v
PIO sampler + PIO end detector     Hardware runs independently of tasks
          |
          v
DMA -> raw buffer A or B           2 x 7000 words; never overwrite an owner
          |
          v
Core 1 capture task                Decode samples, verify checksum
          |
          v
8 frame blocks -> queue of 4 pointers
          |
          v
Core 0 consumer                    Count/release frames; USB diagnostics
```

Core 0 also owns MDIO, the separate interface for reading and configuring the
PHY. MDIO does not carry packets. The current consumer counts frames; protocol
analysis, incidents, SD and notifications belong to later milestones.

## 2. Pin a task to its hardware owner

**Affinity** means restricting a task to a selected processor. In
`capture_app.c`, `capture_app_task` creates the worker using this real code:

```c
    worker.tskatr  = TA_HLNG | TA_USERBUF | TA_ASSPRC;
    worker.task    = (FP) capture_app_worker;
    worker.itskpri = 6;
    worker.stksz   = sizeof(g_worker_stack);
    worker.bufptr  = g_worker_stack;
    worker.assprc  = TP_PRC2;
    task           = tk_cre_tsk(&worker);
```

`TA_ASSPRC` enables processor assignment. The kernel numbers processor bits
from one: `TP_PRC2` means physical Core 1, while `TP_PRC1` means Core 0.
Priority 6 is the capture task's scheduling priority; a lower number means
higher priority. `TA_USERBUF` supplies its preallocated 4096-byte stack instead
of asking a heap allocator for memory. A **stack** stores function-call state
and local variables. It is separate from packet storage.

The coordinator has priority 5 on Core 0. That does not stop the Core 1 task
running at the same time. Both use the same SMP kernel; this is not a pair of
independent operating systems.

## 3. Why this first receiver uses 10 Mbps

**RMII** is the PHY's Reduced Media Independent Interface. RXD0/RXD1 carry
two bits at once, called a **dibit**. At 10 million bits per second, one dibit
lasts 200 ns. Sampling at 50 million samples per second produces approximately
ten samples of each dibit. The software uses that repetition to recover bytes.

REFCLK is not connected in the confirmed wiring, so this is an asynchronous
oversampling receiver, not a conventional clocked Ethernet MAC. 100 Mbps is
unsupported by this decoder. The receive path uses only the confirmed pins.

In `capture_app.c`, `capture_app_phy` first checks the raw LAN8720 identity,
then calls capture_phy_configure in capture_phy.c, which writes advertisement register 4 = `0x0061` (10 Mbps half/full duplex) and
control register 0 = `0x1200` (enable and restart automatic negotiation). It
reads back both settings. Writes have no PHY acknowledgement bit; returning
true from the wire write alone is not configuration verification.

`capture_app_link` then uses this actual condition:

```c
    /* BMSR link is latch-low: the second read is the current state. */
    speed = (*p_special >> 2u) & 7u;
    return b_read && (0x24u == (*p_bmsr & 0x24u))
        && ((1u == speed) || (5u == speed));
```

**Negotiation** is the two cable peers agreeing a common speed and duplex.
**Duplex** describes whether sending and receiving can occur simultaneously.
BMSR is the basic status register. Its link bit is **latch-low**: it remembers
a previous disconnection until read, so the function reads it twice. SCSR is
the special control/status register; speed codes 1/5 indicate 10 Mbps.

The Core 0 task waits one second between link checks; it does not spin with
interrupts disabled. Capture starts only after negotiation confirms 10 Mbps.
An unplugged cable can leave it waiting indefinitely, with a status line each
second. Diagnostic/kernel/SMP acceptance profiles still do management reads only.

## 4. PIO is a tiny dedicated pin-processing machine

**PIO** means Programmable I/O. Its state machines execute small programs
without asking the CPU to inspect every pin transition. A **state machine**
here is a small hardware instruction engine, not a kernel task.

The first program in `capture_rx.pio` is:

```pio
.program capture_samples
wait 1 pin 0
.wrap_target
in pins, 3
.wrap
```

`pin 0` is relative to the configured input base, GP4. It waits for CRS_DV
high, then repeatedly samples GP4/5/6 with one instruction per sample.
**CRS_DV** combines carrier sense and receive-data-valid information.

The real configuration in `capture_hw.c`, `capture_hw_init`, includes:

```c
    sm_config_set_in_pins(&sample_config, CAPTURE_PIN_BASE);
    sm_config_set_in_shift(&sample_config, true, true, 30u);
    sm_config_set_fifo_join(&sample_config, PIO_FIFO_JOIN_RX);
```

The shift register collects three bits at a time. **Autopush** transfers it
to the receive FIFO automatically after 30 bits: ten samples per 32-bit word.
With right shifting, chronological samples occupy bits 2..4, 5..7, ... 29..31.
The low two bits are unused. **FIFO** means first in, first out: a small
hardware waiting area. Joining it for receive provides eight words of space.

Clock division uses integer arithmetic, preserving the kernel's integer-only
context rule. At the normal 150 MHz system clock, divider 3 gives 50 MHz.
No floating-point divide is hidden in the PIO initialization.

## 5. A falling CRS_DV edge is not necessarily the end

LAN8720 can toggle CRS_DV while draining the final packet data. At 10 Mbps
the tail toggle rate is 2.5 MHz. Stopping on the first low edge can truncate
the frame. The second program in `capture_rx.pio` qualifies the low interval:

```pio
.program capture_end
wait 1 pin 0
high:
set x, 15
low:
jmp pin high
jmp x-- low
irq 0
halt:
jmp halt
```

While CRS_DV is high, `jmp pin high` reloads the counter. While it stays low,
two instructions repeat sixteen times: about 640 ns at 50 MHz. A shorter
low tail pulse resets the counter. `irq 0` raises a PIO interrupt flag only
after the sustained low interval. Both machines then wait for CPU rearming.
This addresses the first-edge design problem; real timing still needs board
measurement. It is not an independently proven packet-boundary guarantee.

The PHY speed and tail behavior come from the
[Microchip LAN8720A datasheet, sections 3.4.1.1 and 4.2.14](https://ww1.microchip.com/downloads/aemDocuments/documents/UNG/ProductDocuments/DataSheets/LAN8720A-LAN8720Ai-Data-Sheet-DS00002165.pdf).

## 6. DMA is the worker that carries the samples

**DMA** means Direct Memory Access. It copies the PIO FIFO into RAM without
the CPU executing a load/store loop for every sample. **DREQ** is the hardware
request signal: PIO asks DMA for a transfer only when a word is available.

`capture_hw.c`, `capture_hw_init`, configures:

```c
    channel_config_set_transfer_data_size(&dma_config, DMA_SIZE_32);
    channel_config_set_read_increment(&dma_config, false);
    channel_config_set_write_increment(&dma_config, true);
```

The source address stays at the same PIO FIFO register. The destination
address advances through the raw buffer. Each transfer is 32 bits (four bytes).
The channel and both PIO state machines are claimed through SDK allocation APIs;
they are not assumed to be free based on a hard-coded channel number.

Two raw buffers use 56,000 sample bytes, approximately 1.4 ms of recording per
buffer. At frame end, the interrupt handler disables both state machines,
clears DMA enable before aborting it for RP2350 erratum E5, waits for the abort,
and drains completed FIFO words. It marks a full DMA buffer or a FIFO stall
as damaged. Damaged recordings never become valid published frames.

A **stall** means PIO could not push because its FIFO was full; sample timing
was lost. A longer frame or a delayed interrupt can fill the raw buffer.
See the SDK's [DMA API and abort erratum notes](https://github.com/raspberrypi/pico-sdk/blob/master/src/rp2_common/hardware_dma/include/hardware/dma.h).

## 7. Buffer ownership prevents two writers using the same memory

**Ownership** means permission to access or change a particular buffer. Raw
buffers follow these states, defined in `capture_hw.c`:

```text
FREE -> FILLING -> READY -> READING -> FREE
        DMA       ISR      task
```

`FILLING` belongs to DMA. Only after DMA has stopped may the ISR publish
`READY`. The task takes it as `READING` and returns it after decoding. The ISR
arms only a `FREE` buffer. If neither is free, acquisition pauses and increments
`pauses`; it never overwrites a decoder's input.

An **ISR** is an Interrupt Service Routine, a function run when hardware needs
attention. It should finish quickly. This ISR does no printing, allocation,
decoding or kernel service calls. PIO/DMA interrupts are installed only on
Core 1, with hardware interrupt priority `0x40`.

The ISR/task metadata is protected by temporarily disabling interrupts on
Core 1. That works because both writers are on that same core. It would not
protect against a Core 0 writer. Cross-core counters instead use C11 atomics.
The source asserts these integer atomics are lock-free on the target, so the
ISR never takes a hidden software lock for a counter.

## 8. Wake the service task without delaying a whole kernel tick

`capture_hw_finish` ends with this real code:

```c
    __dmb(); /* DMA/FIFO writes precede publication to the local task. */
    p_slot->state = RAW_READY;
    g_active      = -1;
    pio_interrupt_clear(gp_pio, 0u);
    dma_hw->ints1 = 1u << (uint32_t) g_dma;
    capture_hw_arm();
    __sev(); /* Wake the raw-buffer service task without a kernel ISR call. */
```

**DMB**, a data memory barrier, orders memory operations before publishing
the buffer. **SEV**, send event, sets a processor event notification. The task
uses **WFE**, wait for event, when no raw buffer is ready. The notification is
latched even if the interrupt occurs just before WFE, avoiding a missed wakeup.

WFE is a CPU instruction, not a kernel-blocking call. The task remains runnable
and dedicates Core 1 to servicing capture in this bring-up profile. Higher
priority tasks can still preempt it. Future Core 1 services require a deliberate
scheduling redesign; this is not a general replacement for kernel waits.
The Core 0 consumer uses a real kernel message-buffer wait.

## 9. Turn repeated pin readings into bytes

`capture_decode.c` is portable C, with no SDK/kernel calls. It first finds
the last high CRS_DV sample and permits one final low-tail dibit. It ignores
the long undefined idle RXD region left while the interrupt was being serviced.

It groups repeated RXD values into **runs**. A run is consecutive identical
samples. The actual run-to-dibit conversion in `capture_decode` is:

```c
        value = capture_sample(p_words, position);
        run   = capture_run(p_words, position, end, value);
        position += run;
        repeats = (run + 5u) / 10u;
```

A run of 10 samples represents one dibit; 20 represents two. Adding five
before integer division rounds to the closest dibit and tolerates the initial
sampling phase. Matching packed groups are skipped ten samples at a time to
reduce CPU work. This is a timing assumption, not a recovery method for
arbitrary clock drift or 100 Mbps traffic.

The **preamble** is Ethernet's repeating synchronization pattern. The
**SFD**, Start Frame Delimiter, ends it. At10Mbps the PHY suppresses the
preamble; the decoder requires the complete SFD: three `01` dibits followed by
one `11`. Additional preamble is optional. It then packs four dibits into each byte,
least-significant pair first. It bounds every output write.

The original reference receiver's oversampling/run-length approach informed
this port. The legacy RMII implementation credits Sandeep Mistry under BSD-3;
its source and notices remain in the reference tree. This new three-pin decoder
and qualified end detector replace the old two-pin/first-falling-edge path.

## 10. Verify the frame before publishing it

**CRC** means Cyclic Redundancy Check, a mathematical checksum for detecting
corruption. Ethernet's **FCS**, Frame Check Sequence, is the four CRC bytes at
the end of the frame. A matching CRC is evidence of intact bytes, not proof
that traffic is benign or that an attack occurred.

`capture_decode.c`, `capture_crc32`, uses this actual update:

```c
        crc ^= p_data[index];
        crc = (crc >> 4u) ^ g_crc_table[crc & 15u];
        crc = (crc >> 4u) ^ g_crc_table[crc & 15u];
```

The small lookup table handles four bits per step. The decoder checks only
the physical tail and up to two bytes of rounding allowance, not every possible
payload prefix. A valid CRC hidden earlier in a truncated/extended frame is
therefore not generally accepted as the packet end.

`wire_length` includes the FCS. `length` excludes it; the bytes remain stored.
The supported wire length is 64..1536 bytes. The timestamp is the qualified
end-interrupt service time, **not the first-bit arrival time**. That distinction
matters when measuring the future attack-to-alarm deadline.

## 11. A pool is a shelf of reusable frame blocks

A **fixed memory pool** is a known number of equal-size buffers. The real
micro T-Kernel pool supplies eight frame blocks. There is no per-frame heap
allocation, and no unbounded memory growth. A separate message buffer holds
four pointers. The producer obtains a frame with `capture_pipe_reserve`:

```c
    if (E_OK != tk_get_mpf(g_pool, &p_block, TMO_POL))
    {
        atomic_fetch_add(&g_pool_drops, 1u);
        capture_pipe_loss();
        return NULL;
    }
```

`TMO_POL` means poll: return now if no block is available. It does not mean
the entire kernel call costs zero time; SMP kernel lock contention can still
delay it. Exhaustion increments a drop counter and loss generation.

A **pointer** is a memory address. The queue sends that address, not a copy
of all packet bytes. This keeps kernel message copying short. It also makes
correct ownership essential: a queued address must not point to a reused block.

## 12. A successful send transfers ownership immediately

Frame blocks follow `FREE -> PRODUCER -> QUEUED -> CONSUMER -> FREE`.
In `capture_pipe.c`, `capture_pipe_offer` contains:

```c
    p_frame->loss_generation = atomic_load(&g_generation);
    /* State must be QUEUED before send: the remote receiver can run before
     * this call returns. On success, never touch the frame again here.
     */
    if (E_OK != tk_snd_mbf(g_queue, &p_frame, sizeof(p_frame), TMO_POL))
    {
        (void) capture_pipe_transition(p_frame, FRAME_QUEUED, FRAME_PRODUCER);
        atomic_fetch_add(&g_queue_drops, 1u);
        capture_pipe_loss();
        return false;
    }
    return true;
}
```

Before this excerpt, an atomic compare/exchange changes `PRODUCER` to
`QUEUED`. **Compare/exchange** changes a value only if it still matches the
expected old value. It detects double sends and wrong-owner releases.

The state must be queued before the kernel send. Core 0 may receive, release
and even reuse the block before Core 1 returns from sending. On successful
send, the producer does not read or write that frame again.

On failed send, ownership returns to the producer. The producer must cancel
the frame to return it to the pool. On receive, the consumer owns it until
its final read, then releases it once. Wrong-owner and immediate duplicate
releases are rejected before calling the kernel. These state checks cannot
identify a stale pointer after that address has been allocated again; callers
must respect the lifetime. Kernel pool free-list data may overwrite packet
storage after release, so retaining its pointer for later use is invalid.

The host ownership test deliberately simulates the early receiver/reuse
interleaving. Boot self-checks exercise actual kernel pool exhaustion, queue
exhaustion, FIFO ordering, duplicate-release rejection and full reclamation.
Expected self-test drops are cleared before live acquisition begins.

## 13. Make capture loss visible to future analysis

`capture_pipe.c`, `capture_pipe_loss`, performs:

```c
capture_pipe_loss (void)
{
    atomic_fetch_add(&g_generation, 1u);
}
```

An **atomic** operation is indivisible to competing cores. `loss_generation`
is a changing discontinuity marker, not an exact lost-frame count. Bad CRC,
damaged raw data, pool/queue exhaustion and observed buffer pauses/high rearm
conditions change it. A later valid frame carries the current value, allowing
v0.6 analysis to reset histories rather than join samples across known loss.

`sequence` numbers raw completions, including bad ones. Neither sequence nor
generation can count a packet that arrived entirely while capture was unarmed.
Rearming has a gap, IRQ service can be delayed by kernel interrupt masks, and
software diagnostics cannot measure all unseen traffic. An independent offered
frame reference is required for the >=99% capture claim.

Diagnostic fields:

| Field | Meaning |
| --- | --- |
| raw | Raw buffer completions, not independently offered frames. |
| crc_ok / delivered | Successfully decoded frames / frames received by Core 0. |
| no_sfd / short / bad_crc / large / invalid | Decoder rejection categories. |
| full / stall | Raw capacity reached / PIO FIFO stalled; data rejected. |
| pauses | No free raw buffer at rearm; capture stopped until release. |
| high_arm | CRS_DV already high at arming; possible partial-frame start. |
| max_rearm_us | Maximum observed stop-to-rearm service interval, including pauses; excludes interrupt latency before stopping. |
| pool_drop / queue_drop | Producer could not obtain storage / deliver its pointer. |
| owner_error | Invalid ownership transition; should remain zero in live use. |
| loss_gen | Known or suspected discontinuity marker; wraps at 32 bits. |

Snapshots read counters separately, so simultaneous activity can make one line
temporarily inconsistent. Healthy idle means counters can stay unchanged; it
does not mean the worker has stalled. Only the first raw prefix and first valid
frame bytes are printed, followed by one-second summaries.

## 14. What is tested, and what is still pending

Host tests compile the production MDIO, decoder and pipe implementations.
They check wire read/write fields, timing guards and read ACK; 2640 generated
phase/tail/size cases; known CRC; malformed/oversized/short frames; bounded
ownership/exhaustion and early remote reuse. The pool/queue host model is not
the real kernel, and generated traces are not independent electrical evidence.

All four firmware profiles build. New code uses `-Wall -Wextra -Werror` and
passes the project's automated BARR/format checks. The prebuilt newlib missing
GNU-stack-note linker warning remains. Formatting does not prove all BARR rules.
Image inspection confirms RP2350 Arm Secure, pico2_w and version 0.5-dev4.

The isolated capture build's section sizes and final hashes are recorded in
ignored `build/verification.json`. Those sizes do not establish total peak RAM
or final application compliance with the user-approved479232-byte ceiling
(90% of Pico 2 W SRAM; supersedes the earlier216064-byte budget). Runtime stacks,
SDK heap and later analysis/network/SD resources still need measurements.

The next acceptance step is the manual board procedure in `testing/README.md`.
Do not mark v0.5 qualified until actual traffic is received with matching frame
bytes/checksums and capture losses are measured against an independent sender.

## Dev4 board finding and dev5 correction

Dev4 confirms PIO selftest15, PHY/link10Mbps and live EOF interrupts. First raw
recording322 words is undamaged, but no SFD was decoded. Subsequent recordings
stall; attached log ends raw362/stall361 with no valid frames.

Found source defect in capture_hw.c: stopping clears DMA EN for RP2350-E5;
old rearming triggered a transfer without restoring EN, so later transfers
were ignored. Dev5 capture_hw_arm now includes this real code before its trigger:

```c
    hw_set_bits(&dma_channel_hw_addr((uint32_t) g_dma)->al1_ctrl,
                DMA_CH0_CTRL_TRIG_EN_BITS);
```

EN is the enable bit. AL1_CTRL is the control alias that does not itself start
a transfer. After restoring EN, TRANS_COUNT is written through its trigger
alias. Hardware stop still clears EN before abort. disabled_stops measures an
unexpected disabled channel at stop entry, before that intentional clear.
Expected value is zero. This source correction still needs a board test.

## Dev5 framing result and dev6

Dev5 board removes the old DMA stalls. Its first RXD trace starts0:368,1:30,3:20.
The [LAN8720 datasheet, Table2-1/page8](https://ww1.microchip.com/downloads/en/DeviceDoc/00002165B.pdf)
explains that at10Mbps RXD is held low until SFD. SFD is the eight-bit start
marker D5, sent as01/01/01/11. The old decoder required eight01 dibits; only
three are needed for the complete marker. That explains no_sfd on every record.

In capture_decode.c the implemented requirement is now:

```c
#define CAPTURE_SFD_PREFIX_DIBITS 3u
```

The following11 dibit finishes the marker. If that value repeats into frame
data (3:20), exactly one is consumed as marker; the remaining data is preserved.
Length and CRC checks remain unchanged. A valid host frame with exact observed
start and first byte33 failed before this fix and now passes. Full-preamble and
SFD-only host fixtures total2640; incomplete prefixes and bad CRC still reject.
Dev6 now has a supplied positive board run:343 CRC-valid frames delivered.
Unique test-packet accounting and capture percentage remain pending.

## Reading your console in plain English

Think of the receiver as a parcel line: PIO observes incoming symbols, DMA is
an automatic carrier that puts them in storage, raw buffers are two waiting
trays, the decoder reads the address label, and CRC checks for damaged contents.
The queue passes checked parcels to the other core.

The old DMA bug turned the carrier off after each parcel but did not turn it
back on. Incoming symbols filled its small waiting tray (FIFO) and stalled.
The dev5 log's disabled_stops0/stall0 confirms that pattern is gone in this run.
Now the carrier works, but the label reader expects a longer greeting than the
PHY supplies. Dev6 corrects that expectation; it does not skip the integrity check.

| Console field | Meaning in this run |
| --- | --- |
| PHY ID0007/c0f1 | Management reads identify the expected LAN8720 model/revision. |
| ANAR0061 / ready1 | The10Mbps advertisement was read back; the cable peers agreed a usable10Mbps link. |
| worker_status1 | Capture worker initialization succeeded; rising raw/eof counters demonstrate later progress. |
| time9235750us | Hardware time since boot, about9.24 seconds; not packet latency. |
| PIO selftest15 | All four startup checks passed;15 is a bit mask, not a packet count. |
| wordfffffffc | Known synthetic sample pattern from the startup test; not a memory address or an error. |
| eof_irqs73 | The frame-end detector generated73 serviced interrupts. |
| raw73 |73 recordings were completed; not necessarily73 unique offered Ethernet frames. |
| disabled_stops0 | No completion found DMA unexpectedly switched off. |
| full0 / stall0 | No raw-capacity or PIO FIFO-stall fault observed in these recordings. |
| no_sfd73 | Software rejected every recording at start recognition; this does not prove the sender omitted its marker. |
| crc_ok0 / delivered0 | No frame passed CRC and reached the consumer yet. |
| short/bad_crc/large/invalid0 | No such errors reported; CRC was not reached for no_sfd recordings. Zero bad_crc is not a CRC pass. |
| pauses24 |24 times no free raw tray was available; capture waited for a release. New traffic can be missed during that gap. |
| high_arm5 | Five starts happened while CRS_DV was already high; possible mid-frame starts. |
| max_rearm_us1412 | Longest measured stop-to-restart interval1.412ms, including waiting for storage; excludes latency before the ISR. |
| pool_drop0 / queue_drop0 | No decoded-frame pool/queue exhaustion observed; no valid frames were sent through the queue yet. |
| owner_error0 | No invalid buffer ownership transition detected. |
| loss_gen100 | A changing known/suspected discontinuity marker, not100 proven lost packets. |

Raw storage is signal history, not decoded Ethernet bytes.566 words contain
5660 snapshots of three pins, sampled every20ns (113.2us of recording). crs_high
counts snapshots showing activity; rxd_set_bits counts ones across oversampled
data wires, not packet bits. Prefix24924924 means CRS1/RXD00, expected before
SFD in this PHY mode. Zero tail means idle after the packet.

end_pc5 says the small PIO program reached its end waiting loop. irq/inte/ints
are hexadecimal interrupt-state snapshots for debugging, not error numbers.
stop0 means the frame-end detector stopped acquisition; stop1 means DMA did.
DMAwords566 and remaining6434 describe a7000-word destination. They are sampled
at different stages, so exact equality is not guaranteed in general. damaged0
means no capture-buffer fault detected, not that a packet passed framing/CRC.

The trace is also signal history.0:368 means data00 for368 samples (7.36us).
1:30 means01 for30 samples, or three dibits.3:20 means11 for two dibits; the
first completes SFD and the second begins frame data. These values explain the
software's start-marker mismatch without requiring guesses about wiring.

## Dev6 first functional board capture checkpoint

The latest supplied log ends with347 raw recordings,343 CRC-valid frames and
343 delivered frames. Three recordings lacked a recognized start marker; one
failed CRC. Full/stall/DMA-disabled/ownership/pool/queue errors stay0. Raw-buffer
pauses72 and high-arm9 remain possible capture-gap concerns. The first frame
seq1,len122/wire126 passed CRC before the test batch; background frames can
arrive immediately after the receiver starts.

Starting the sender a few seconds later is fine. The receiver keeps listening;
there is no startup-only receive window. The sender report records100 successful
OS submissions at10fps. Later counters rise at approximately that rate with no
new errors or pauses, consistent with the batch. The present firmware does not
match its unique runID/sequence, so it cannot prove all100 were captured.

This confirms the DMA restart and SFD corrections on real hardware. The earlier
log-reader table describes the failing dev5 run; its zero-CRC/zero-queue-use
statements are historical, not the current dev6 result. CRC-valid delivery now
works. Capture-rate qualification still needs unique test matching and independent
offered-frame evidence, plus investigation of burst-related pauses.
