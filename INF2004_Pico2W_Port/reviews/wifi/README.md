# Pico 1 W notification reuse review

Reviewed 2026-11-10. **Reuse the protocol modules through a selective port; do
not merge the entire branch.** The notification state machine itself has no
direct kernel calls and compiles for RP2350. The radio runtime, allocation,
memory accounting and secure TLS configuration still need integration work.
The user subsequently approved a 90%-of-SRAM Pico 2 W budget; the earlier
216064-byte limit no longer blocks this port.
This report records the source-branch review before integration. The user then
authorized the selective port: v0.9-dev1 now builds and passes host checks; see
the [current implementation and setup](../../app_program/wifi/README.md).
Dependencies and the RAM checker have been restored; the combined image reserves
about394KB under the new479232-byte budget. Board delivery remains untested.
No branch merge or Git history change was made.

## Source and merge scope

Compared current `pico2w_rp2350/analysis_port` at `5f9dd98` with local and cached
remote `MicroTKernel_wifi_notification` at
`7dc251fe1d244fb9f389473f47333a5474ac2cc4`. Remote freshness was not checked.
There is **no common Git ancestor**. A direct tree comparison differs in 909
files (131188 insertions, 29554 deletions); these are tree differences, not a
prediction of merge results. The source branch contains no active Pico 2 port
directory. A wholesale merge would reconcile unrelated project histories.

Both boards use CYW43439, which supports substantial application-code reuse.
See Raspberry Pi's [radio module description](https://www.raspberrypi.com/news/raspberry-pi-radio-module-2-available-now-at-4/).
The installed Pico SDK 2.3.1 supplies RP2350 support; retain its hardware layer.

## What can be reused

| Source under the template | Assessment |
| --- | --- |
| `app_program/subsystem5/telegram_http_parser.c/.h` | Reuse. Bounded HTTP/JSON parsing, including fragmented and chunked responses. Original host tests pass. |
| `app_program/bounded_text.h` | Reuse bounded request-building helpers. |
| `app_program/subsystem5/wifi_notification.c/.h` | Mostly reusable. Nonblocking DNS/TLS/HTTP state machine, partial-write handling and deadlines. Compiles unchanged against RP2350 SDK headers with an adapter header. |
| `notification_port.c` | Adapt current incident/status delivery, time source, configuration and retry ownership. Preserve bounded retries and expiry. |
| `tls_kernel_alloc.c` | Replace allocation backend with an explicitly budgeted bounded arena. Current firmware disables kernel allocation. |
| `lib/libwifi/sysdepend/pico_rp2040/` and old build files | Do not import wholesale. Use current SDK clocks, IRQ/resource claims and RP2350 radio support; adapt only the kernel-facing owner loop. |
| Old subsystem5 alarm/task startup | Preserve the active port's independent GP19 alarm and supervisor. Connect notifications through copied incident information. |

One task must own all radio/lwIP/TLS operations on Core 0. Merely putting two
network callers on the same core does not serialize their access. Use a lower
priority than alarm/analysis and keep network delays out of capture and incident
handling. SDK polling must be serviced periodically; see the official
[networking API](https://www.raspberrypi.com/documentation/pico-sdk/networking.html).

## Why the lower layers need changes

Actual excerpt: source branch `cyw43_utk_compat.c`, `clock_get_hz`:

```c
uint32_t clock_get_hz(clock_handle_t clock)
{
    (void)clock;
    return 125000000u;
}
```

The active port uses SDK-managed clocks at 150 MHz. This compatibility file also
reimplements SDK time/resource/IRQ functions. Importing it risks duplicate
symbols or incorrect hardware behavior. Old makefiles select Cortex-M0+/RP2040,
and the copied PIO header retains an RP2040-selected program.

Actual excerpts: source branch `cyw43_utk_kernel.c`, task setup:

```c
#define CYW43_TASK_PRIORITY  4
#define CYW43_TASK_STACK     (8 * 1024)
```

```c
ctsk.stksz = CYW43_TASK_STACK;
task = tk_cre_tsk(&ctsk);
```

This task has no `TA_USERBUF` stack buffer. The active kernel has dynamic
allocation disabled and reserves priorities 1-4 for system work. Supply a static
stack, choose a compatible priority and recount kernel objects. All four
configured message buffers are already used. Only the existing consumer may
format console output; the radio owner must publish copied status instead.

Actual excerpt: `tls_kernel_alloc.c`, allocation backend:

```c
allocation_header_t *header = Kcalloc(1, sizeof(*header) + length);
```

The current linked firmware supplies neither this kernel allocation service nor
enough capacity in its 2048-byte libc heap for TLS. Allocation must fail safely
without delaying detection or releasing unsaved evidence.

## Memory under the approved Pico 2 W budget

The user approved a new ceiling of **479232 bytes (468 KiB)** on 2026-11-10:
90% of 532480 bytes (520 KiB), leaving a 53248-byte (52 KiB) reserve. This
supersedes the former216064-byte budget. The final v0.8 SD/GP19 profile reserves
**213844 bytes**, leaving **265388 bytes** under the new ceiling.
The existing source configuration implies the following capacity
requirements for an enabled connection:

| Component | Bytes | Evidence |
| --- | ---: | --- |
| Notification globals | 3948 | Measured `.bss` in RP2350 object |
| Radio/lwIP task stack | 8192 | `CYW43_TASK_STACK` |
| lwIP memory arena | 16384 | `lwipopts.h: MEM_SIZE` |
| TLS input/output buffer capacities | 18432 | `MBEDTLS_SSL_IN_CONTENT_LEN=16384`, output=2048 |
| Subtotal | **46956** | Before radio state, pbuf pools, TLS/certificate objects, allocator overhead and queue resources |

These are configured capacities, not a measured combined runtime peak. Added
to the v0.8 reservation, the subtotal is **260800 bytes**, about **49.0% of physical
SRAM**, with **218432 bytes** still below the new ceiling before remaining
overhead. The old budget blocker is resolved. This estimate does not prove the
full link or peak runtime fits; measure all services together. Preserve model,
history and evidence capacities. The RAM checker was subsequently restored and updated during integration;
the full dev1 image now passes the new limit.

## TLS and completeness findings

- The notifier configures a CA and hostname, but SDK 2.3.1 lwIP defaults
  `ALTCP_MBEDTLS_AUTHMODE` to `MBEDTLS_SSL_VERIFY_OPTIONAL`. The TLS adapter passes
  that setting to mbedTLS. No source-branch override or verification-result check
  was found. Explicitly require `MBEDTLS_SSL_VERIFY_REQUIRED`; supplying a CA and
  hostname alone does not make this default fail closed. A compile-time probe
  confirmed the optional default in the reviewed configuration.
- A valid trust root and trustworthy UTC are required for certificate date
  checking. Current port uptime is not UTC. Keep credentials outside tracked
  source and exports; no private configuration was read for this review.
- A complete branch search finds `monitor_notification_poll()` only declared and
  defined, with no caller. The checked-in configuration defaults Telegram off;
  its makefiles do not establish full ALTCP/TLS library wiring. This does not
  prove external configurations never worked, but the branch alone is not
  evidence of completed end-to-end integration.
- Candidate small fix: idle `STATE_WIFI_WAIT` schedules its next action ten
  seconds ahead; submit queues a request without resetting that timer. A newly
  submitted alert can consequently wait up to ten seconds before DNS starts.

## Verification and limits

- Original parser and original host tests: compiled with C11,
  `-Wall -Wextra -Werror`; executable reports `Telegram HTTP parser tests passed`.
- Unchanged notification/parser sources: compile-only RP2350 Arm Secure,
  Cortex-M33 software-float objects with SDK 2.3.1 and warnings as errors.
  A thin review adapter supplied platform prototypes; dummy configuration used
  placeholders. TLS was explicitly enabled for this compile experiment.
- Notification object has no direct kernel-call dependency; measured BSS is
  3948 bytes. This is not a full firmware link, task scheduling check or TLS test.
- Review artifacts and exact selected-source hashes remain local in
  `build/wifi-review/`. Credentials were excluded. Existing Wi-Fi host mocks do
  not establish validation of this custom-kernel integration.
- At review time, ignored platform/kernel and several host sources were absent.
  Integration subsequently recovered521missing Pico2files from saved local
  indexce173cd without overwriting existing files or changing the index. Baseline
  storage and full Wi-Fi builds now pass; preserved v0.8 images remain available.
- No flash, network connection, Telegram send or board validation was performed.

## Suggested port order

1. Restore the known local kernel/platform dependencies and preserve v0.8.
2. Apply the approved479232-byte ceiling to the restored RAM checker and
   account for the combined image, static stacks, bounded arena and peak TLS use.
3. Copy the parser, bounded text helper and notifier selectively with provenance;
   adapt the current SDK radio owner, static stack, bounded allocation and copied
   incident/status interface. Keep capture PIO0/DMA_IRQ1 ownership intact and
   inspect radio resource claims before startup.
4. Wire the polling hook, required TLS verification, trusted time and private
   credentials. Preserve bounded deadlines/retries and independent local alarm.
5. Verify the full link and resource report, then perform a focused successful
   notification and failure/recovery check with capture/analysis/SD active. Record
   actual memory and stack peaks; standalone compilation is not board evidence.

Conclusion: the user's assessment is right for the upper notification code.
The safe integration is a selective module port, with memory accounting and runtime work
resolved explicitly before it can be called a working v0.9 feature.
