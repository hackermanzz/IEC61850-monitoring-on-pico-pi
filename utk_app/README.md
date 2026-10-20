# IS18 on µT-Kernel 3 SMP: capture (Jonathan) and stream analysis (Shaun)

This folder is the µT-Kernel 3 SMP version of the capture and analysis path,
following the Tribunal 1 decisions.

## What runs where

| Task | Owner | Core | Priority | File |
|---|---|---|---|---|
| RMII Capture | Jonathan | processor 2 (core 1), alone | 1 | `rmii_capture_task.c`, `rmii_capture_hw.c` |
| Stream Analysis + RF | Shaun | processor 1 (core 0) | 6 | `stream_analysis_task.c`, `../rmii/examples/analyzer/analyzer.c` |
| Incident sink (stand in for Sean's Incident Manager) | Sean | processor 1 | 5 | `app_main.c` |

All numbers are in `app_config.h`.

## How frames move (all µT-Kernel objects)

1. **End of frame:** the CRS_DV falling edge interrupt fires on core 1 only. The interrupt is enabled only in core 1's NVIC and in `PROC1_INTE`.
2. **The interrupt does the minimum:** it stamps the time, stops PIO/DMA, rearms into the second sample buffer and calls `tk_wup_tsk`.
3. **The capture task picks up the frame:** it takes a block from the memory pool `mpf_frames` with `tk_get_mpf` (no waiting) and decodes straight into it. It then posts the block to the mailbox `mbx_frames` with `tk_snd_mbx`. That's about three kernel calls per frame.
4. **Stream Analysis processes it:** it waits on the mailbox (`tk_rcv_mbx`), runs the analyzer, then gives the block back (`tk_rel_mpf`).
5. **Results go to the Incident Manager:** they are small events in the message buffer `mbf_pred` (`tk_snd_mbf`, no waiting). For windows labelled malicious, an evidence block from `mpf_evidence` is attached. The Incident Manager must release it.

The kernel uses the SIO FIFO for its own messages between the cores, so none of this code touches it.

## Changes for each person

**Jonathan (capture):**
- Capture is now a µT task pinned with `TA_ASSPRC` / `TP_PRC2`.
- Two sample buffers (ping pong), so the receiver rearms inside the interrupt.
- No transmit state machine, no transmit buffers and no lwIP netif (passive).
- Non GOOSE/SV frames are dropped on core 1 before they use a pool block.
- If the pool is empty, the frame still gets a sequence number. Analysis then sees the gap.
- Heartbeat counter (moves even with no traffic), `decode_max_us`, `pool_empty`, `rx_overrun`.
- The PHY is soft reset over MDIO and its link is polled every 100 ms.

**Shaun (analysis):**
- Analysis is a µT task pinned to `TP_PRC1`, priority 6.
- **Gaps are handled per stream.** A gap marks streams as suspect, and each one checks its own counter (GOOSE stNum/sqNum, SV smpCnt) on its next frame. Only streams that really lost frames are reset, and a `STREAM_RESET` event goes to the Incident Manager. Counter jumps without a gap are not reset, because they are attack evidence.
- **Capture Overload Warning:** raised when more than 10 frames are lost in 1 s.
- **Timing:** every frame is timed against the 7,692 µs budget (`over_budget` counter).
- **16 GOOSE slots instead of 4, holding metadata only.** Each slot fell from 6,992 B to 920 B. Only the newest frame of a scored window is kept as raw bytes.
- The model features are unchanged, so the forest needs no retraining for these changes.

## Evidence already produced (host and build, not hardware)

- **The port builds:** `make SMP=1 WIFI=cyw43 PICO_SDK_PATH=<pico-sdk 2.2.0> IS18_LIBS=-lm` succeeds against `sirfonzie/mtk3smp-rp2040`, with no warnings from these files under `-Wall -Wextra`.
- **No behaviour change with old settings:** `sh tests/analyzer_compare/run.sh` replays the lab captures. With the old settings (4 slots, raw frames) the predictions are identical to the original analyzer.
- **New settings score every stream:** on `test.pcapng`, predictions go from 29,000 to 60,299 and unsupported streams from 62,621 to 0.
- **Gap policy keeps far more windows:** with 1 frame in 20 dropped, `svspoof` keeps 3,808 scored windows instead of 29 with the old global reset.
- **Static RAM of the new objects:** GOOSE slots 14,720 B, SV slot 44,920 B, sample buffers 31,200 B, frame pool 12,352 B, evidence pool 7,904 B.

## How to build inside the course port

1. **Get the right SDK:** the port is qualified with **Pico SDK 2.2.0**. Version 2.3.1 fails, because the port's include paths miss `pico/util/fixed_bitset.h`.
2. **Copy the files into `mtk3smp-rp2040/app_program/`.** First delete the port demo files there (`app_main.c`, `demo_tasks.c`, `demo_tasks.h`, `usb_console_compat.h`); our `app_main.c` takes the place of the demo one. Copy:
   - everything in this folder;
   - `rmii/examples/analyzer/analyzer.c` and `analyzer.h`;
   - `firmware/generated_batch/generated_batch_models.c` and `.h`;
   - `rmii/src/rmii_frame.c` and `rmii/src/include/rmii_frame.h`.
3. **Edit one line in `build_make/makefile`** so the maths library (`sqrtf`, `fabsf`) is linked. Change:
   ```
   -o "$(EXE_FILE).elf" $(OBJS)
   ```
   to:
   ```
   -o "$(EXE_FILE).elf" $(OBJS) $(IS18_LIBS)
   ```
4. **Build:**
   ```
   cd build_make
   make SMP=1 WIFI=cyw43 PICO_SDK_PATH=~/pico/pico-sdk IS18_LIBS=-lm -j8
   ```
   Flash `mtk3pico_smp1_uart_wifi.uf2`. The console is UART0 on GP0/GP1 at 115200.

## Not done yet (other owners, or needs the board)

- **Not run on hardware.** Check the `capture: running on processor 2` and `analysis: running on processor 1` lines, the 10 s stats line, bad_crc, decode time and analyze time.
- **Sean's `incident.c` still expects four raw frames.** Under µT it must read metadata with `analyzer_copy_last_batch_metadata()` and the newest bytes from the evidence block. The legacy Pico SDK build keeps working because its CMake now sets 4 slots and raw frames.
- **SV history 128 to 32 samples is not done.** It changes the features, so it needs Sean's retrain and new fixtures.
- **Health Monitor, SD, Network and USB Logger tasks are not written yet.** Read `g_rmii_capture_stats.heartbeat` and `g_stream_analysis_stats.heartbeat` from the Health Monitor.
- **`mtk3smp-rp2040/config/config.h` limits:** 4 mailboxes, 4 message buffers and 4 memory pools. This skeleton uses 1, 1 and 2. Raise them when the other tasks are added.
