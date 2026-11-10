# Wi-Fi remote alerts: v0.9-dev2

The `wifi` profile combines capture, GOOSE/SV analysis, GP19 alarm, supervision,
SD BIN/LOG evidence and Telegram HTTPS notifications. It uses the existing
notification/parser modules through a selective port. No branch merge was made.
The separate `storage` profile remains v0.8.0 and does not initialize the radio.

**Build and host checks pass. The dev2 board log demonstrates Wi-Fi/IP and
automatic network time. The user also confirms Telegram incident messages
arrived during the mixed test: the remote-alert functional milestone works.**
Message counts, delivery latency, recovery behavior and TLS runtime stack/arena
peaks have not been supplied; this does not establish full system qualification.
Blank configuration builds an offline image:
`WIFI configured=0`, with no radio task or connection attempts. The full radio,
TLS and fixed arena remain linked so its RAM report is representative.

## Configure and build

From `INF2004_Pico2W_Port`:

```powershell
Copy-Item config/wifi_notification_config.example.h config/wifi_notification_config.h
```

Edit the new private header locally. Supply your 2.4 GHz Wi-Fi SSID/password,
Telegram bot token, chat ID and a PEM trust root appropriate for
`api.telegram.org`. The private header is ignored; keep credentials out of logs,
commands, screenshots and commits. The example contains no working credentials
or certificate. Only `wifi_settings.c` reads the private header.

Encode a PEM certificate as adjacent C string literals, retaining newlines:

```c
/* Structure only: replace the middle line with the complete real PEM body. */
#define CA_ROOT_CERT "-----BEGIN CERTIFICATE-----\n" \
                     "COMPLETE_BASE64_CERTIFICATE_BODY\n" \
                     "-----END CERTIFICATE-----\n"
```

Then build:

```powershell
.\run_these.ps1 -Profile wifi -AlarmGpio 19 -SdPinsConfigured
```

Output: `build/wifi/pico2w_wifi_v09.uf2`. All previous profile names still work.
The radio uses SDK 2.3.1's RP2350 driver and polling architecture, not the old
125 MHz RP2040 compatibility layer. Capture retains PIO0/DMA_IRQ1; the SDK claims
available radio PIO/DMA resources separately (its PIO search starts from the last
block). SD retains its independently claimed DMA channels. No new kernel message
buffer is needed; the four existing MBFs remain sufficient.

## Automatic time after Wi-Fi connects

Dev2 obtains UTC automatically using the SDK's SNTP client in the existing radio
owner. Leave `MONITOR_UTC_AT_BOOT=0` (the default). After flashing, open PuTTY and
wait for `up=1`, then `utc=1`; no command or prompt is required. Status also shows
`time_source=1` and an increasing `time_syncs` count after network replies.
The default servers are `time.cloudflare.com` and `time.google.com`; optional
private `WIFI_NTP_SERVER`/`WIFI_NTP_FALLBACK` settings can select a local server.
DNS and UDP123 must be reachable. If time requests receive no reply, detection,
local alarm and SD continue; HTTPS waits for time and unsent alerts can expire.

SNTP starts once after an IP becomes available and continues its normal hourly
refresh/retry schedule through link changes. It uses the same Core0 owner and
existing lwIP resources, with six UDP PCB slots reserved for DHCP/DNS/SNTP. It
adds no kernel task, queue, heap or clock-setting calls to libc. The client is
kept alive rather than stopped during a pending DNS lookup; this avoids an SDK
late-callback path using a freed UDP endpoint. Replies are checked against the
server address/port and the request timestamp, and accepted dates are limited
to2024-2099. These checks do not authenticate network time. SNTP is an
unauthenticated bootstrap/refresh source; a manipulated clock can affect
certificate validity dates. TLS chain/hostname verification remains required.
The SDK [SNTP client](https://www.nongnu.org/lwip/2_0_x/group__sntp.html) supplies
transport/protocol handling; no custom NTP parser was added.

An optional USB command remains available for a trusted PC/local time source.
Dev1's logging replacement driver had no input callback, so that command could
not receive characters even though PuTTY transmitted them. **Dev2 fixes this**
by forwarding input through the original SDK USB backend while retaining queued
output. Host regression covers input through the registered replacement driver.

To use this fallback, generate the current command in PowerShell:

```powershell
"utc $([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
```

Paste the resulting line into the running PuTTY terminal and press Enter.
Expect `WIFI trusted UTC queued=...`, `utc=1` and `time_source=2`. A USB time
setting takes priority over later SNTP updates. A private nonzero
`MONITOR_UTC_AT_BOOT` is another optional override (`time_source=3`), but becomes
stale; leave it zero for automatic operation. SD investigation timestamps retain
their existing uptime basis; TLS clock synchronization does not rewrite evidence.

The station starts only with nonempty SSID/token/chat and a nontrivial CA value.
It supports open Wi-Fi or WPA2 AES PSK. New association attempts after a down or
failed link are rate limited to ten seconds; an ongoing DHCP exchange is not
restarted on each poll. HTTPS submission additionally requires Wi-Fi/IP and
available UTC. There is no automatic startup Telegram message; run the mixed
sender after `up=1`/`utc=1` to generate new incidents.

## Alert ownership and failure behavior

The consumer raises the existing alarm first, then copies a compact alert into
an eight-entry queue. There can be five distinct boot incidents under the current
ledger policy. The text includes incident number, protocol, APPID, source MAC,
decision uptime and whether RAM evidence was retained. It is a notification;
the full investigation record remains on SD. RAM evidence status does not claim
that the SD write has completed.

Actual excerpt: `health/detection.c`, `detection_observe`:

```c
alarm_submit(&event);
#if PORT_WIFI
wifi_port_submit(&event, p_result);
#endif
```

The priority14 Core0 task owns all radio, lwIP, DNS, TLS and HTTP calls. Its
12 KiB static stack is below alarm5, supervisor6, consumer7 and console8 in
priority. It yields to the kernel between service steps. The consumer owns
formatting and console input; the radio publishes atomic counters and never
calls printf. Core1 remains dedicated to capture. A radio initialization failure
ends only the radio task. Notifications are best effort and do not release or
retain packet evidence, acknowledge SD writes or clear alarms.

Each alert gets at most three attempts, with five seconds between failures.
An unsent alert expires sixty seconds after its decision time; expiry is checked
between attempts, while each in-flight DNS/TLS/send/response phase has its own
bounded timeout. A timeout after delivery can cause a duplicate Telegram message
on retry. Queue exhaustion drops the notification and counts it; detection and
SD continue. Repeated positive windows do not create repeated boot incidents.

TLS explicitly uses `MBEDTLS_SSL_VERIFY_REQUIRED`, a configured trust root,
hostname verification and the available UTC clock. The connected callback also checks the
verification result before allowing HTTP writes. The inherited idle timer is
reset on submission, removing the possible ten-second idle-to-DNS delay.
There is no insecure fallback.

## RAM and status

The first full image reserves about **394 KB**, including a fixed **96 KiB TLS
arena**, 12 KiB radio stack, lwIP arena/pools, all existing capture/history/evidence
buffers, bounded libc heap and both exception stacks. Read the exact current
total from `build/wifi/ram-verification.json`; the limit comes from
`config/ram_budget.h`: **479232 bytes**, 90% of 520 KiB physical SRAM.

TLS allocates only inside its fixed arena. Allocation failure returns NULL and
increments telemetry; it cannot borrow spare SRAM or the libc heap. The allocator
splits/coalesces adjacent free blocks and wipes released data. Its whole capacity
is already counted as static RAM; do not add its live allocation peak twice.
UTC calendar conversion is reentrant and avoids shared libc calendar state.

| Status | Meaning |
| --- | --- |
| `configured`, `started`, `init_error` | Required settings present, radio initialized, initialization failed |
| `up`, `utc`, `busy`, `joins` | IP available, UTC available, request active, join attempts |
| `time_source`, `time_syncs`, `time_rejected` | 0 unset / 1 network / 2 USB / 3 boot; accepted network updates; rejected out-of-range samples |
| `sent`, `failed` | Telegram API success, failed individual attempts |
| `expired`, `exhausted`, `queue_drop` | Alert expired, three attempts used, copied queue full |
| `result`, `http` | Last result category and HTTP response code |
| `TLS current/peak/arena/alloc_fail` | Radio-owned allocation telemetry and reserved capacity |
| `stack_used/stack_size` | Observed watermark estimate and reserved stack; not an overflow proof |

Result codes: 0 none/success, 1 Wi-Fi, 2 DNS, 3 TLS, 4 HTTP, 5 Telegram API,
6 timeout, 7 request. `sent` counts an HTTP response with API `ok:true`;
it does not establish that a person read the alert. No Wi-Fi watchdog reset
policy is added; existing capture/consumer/alarm supervision remains unchanged.

## Checks and functional confirmation

The build checks real software math/no VFP, the combined RAM reservation, and
that real radio/TLS/storage plus the fixed allocator survived linking. Local
`testing/host/run_wifi_tests.ps1` checks fragmented/chunked HTTP/JSON parsing,
partial writes, late DNS callbacks, TLS failures, rejection of an unverified
peer before HTTP, owner retry/expiry/offline/no-time/init-failure paths, automatic time enabling
alerts, invalid-time rejection, clock update/manual priority, reconnect while
time is pending, queue
copying/exhaustion/counter wrap, arena exhaustion/coalescing and UTC conversion.
Existing detection and storage suites also pass. These tests use simulated
transport and time; they do not prove a real TLS handshake or delivery.

The user has confirmed that the mixed test produced Telegram incident messages.
No repeat is needed solely to confirm delivery. Preserve this working dev2 image
while finalizing v0.9 documentation/version metadata. Runtime peaks, network
failure/recovery, workload loss/latency and detector accuracy remain part of
release qualification, rather than a new feature-development gate.

## Provenance

Selected source: local/cached `MicroTKernel_wifi_notification`, commit
`7dc251fe1d244fb9f389473f47333a5474ac2cc4`, under
`INF2004_ProjectTemplate/app_program/subsystem5/`: notifier, HTTP parser and
mbedTLS profile; bounded text helper from its parent directory. lwIP settings
derive from that branch's `lib/liblwip/sysdepend/pico_rp2040/lwipopts.h`.
Formatting/comments and platform configuration/time/TLS fixes are adapted here;
the protocol/parser algorithms are retained. The original parser tests and
adapted notification transport tests remain local under `testing/host`.
Exact source hashes are preserved locally in `build/wifi-review/source-manifest.json`.
Hardware/network/TLS libraries and their licenses remain supplied by Pico SDK
2.3.1. No old RP2040 SDK replacements, kernel allocator or old alarm startup
were imported. Missing Pico2 dependencies were restored from saved index
`ce173cdaa789095beac913ec04c4d91d2f447c4d`, without applying/dropping a stash,
overwriting existing files or modifying the Git index.
