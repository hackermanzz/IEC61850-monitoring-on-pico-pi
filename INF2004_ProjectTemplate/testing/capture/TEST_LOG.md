# Capture module: test log

Owner: Jonathan Chua. Module: `app_program/capture/`.

Each test prints one line, `[TEST] <ID> PASS|FAIL <description>`. Save the
console output of every run in `logs/` (for example
`logs/2026-11-10_board_hw.txt`) and fill in the result table below.

Evidence types (see `testing/README.md`):

- **host**: run on a PC, no hardware.
- **board**: run on the Pico W.
- **board + network**: run on the Pico W with the LAN8720 board, a cable and a
  GOOSE/SV publisher.

## Test cases

| ID | What it checks | Evidence |
|---|---|---|
| RF-01 | CRC-32 of "123456789" is 0xCBF43926 (published check value) | host, board |
| RF-02 | CRC-32 of the quick-fox sentence is 0x414FA339 | host, board |
| RF-03 | CRC-32 of a NULL buffer is 0 | host, board |
| RF-04 | Frame length is found from a matching FCS | host, board |
| RF-05 | Bytes after the FCS are ignored | host, board |
| RF-06 | A frame with one corrupted byte is rejected | host, board |
| RF-07 | Input shorter than header + FCS is rejected | host, board |
| RF-08 | Decoding ideal 50 MHz samples gives back the exact frame | host, board |
| RF-09 | Decoding tolerates up to ±4 samples of jitter per run | host, board |
| RF-10 | Decode + length search recover the frame, with idle line after it | host, board |
| RF-11 | Decoding never writes past the output buffer | host, board |
| RF-12 | Decoding rejects NULL or empty arguments | host, board |
| RF-13 | Samples without a start frame delimiter give no data | host, board |
| CAP-U01 | Releasing NULL to the frame pool is refused | board |
| CAP-U02 | The pool runs dry after at most `MONITOR_FRAME_BLOCKS` frames | board |
| CAP-U03 | Pool frames never overlap | board |
| CAP-U04 | Every acquired frame is released | board |
| CAP-U05 | The capture task keeps publishing its status | board |
| CAP-S01 | Synthetic frames are produced (`MONITOR_SYNTHETIC=1` only) | board |
| CAP-H01 | The PHY answers on MDIO | board + network |
| CAP-H02 | The PHY identifies as a LAN8720 (ID 0x0007 / 0xC0Fx) | board + network |
| CAP-H03 | The Ethernet link is up | board + network |
| CAP-H04 | The receiver started without a fault | board + network |
| CAP-H05 | Frames with a valid FCS are received in a 5 s window | board + network |
| CAP-H06 | No capture fails its FCS check in that window | board + network |
| CAP-H07 | Every GOOSE/SV frame gets the next sequence number | board + network |
| CAP-H08 | No receive buffer overruns in that window | board + network |

The RF cases build the exact samples the PIO receive program captures for a
known frame. Their expected results were also checked against a separate
Python model of the decoder.

## How to run

**Host.** From the repository root, with a C compiler (WSL, MSYS2 or Linux):

```sh
gcc -std=gnu11 -Wall -Wextra -DAPP_TEST=1 \
    -IINF2004_ProjectTemplate/app_program/capture \
    INF2004_ProjectTemplate/testing/capture/host_test_main.c \
    INF2004_ProjectTemplate/app_program/capture/test_rmii_frame.c \
    INF2004_ProjectTemplate/app_program/capture/rmii_frame.c -o rf_test
./rf_test
```

**Board.** Until the integration build lists the capture module, make these
local changes (do not commit them):

1. In `build_make/mtkernel_3/app_program/subdir.mk`, add
   `../app_program/capture/capture.c`, `task_producer.c`,
   `rmii_capture_hw.c`, `rmii_frame.c` and `test_rmii_frame.c` to
   `TEMP_SRCS`, and the Pico SDK `hardware_pio`, `hardware_dma` and
   `hardware_gpio` include folders to the include path.
2. In `usermain()` in `app_main.c`, call `capture_init()`, then
   `capture_start()`, then `capture_test()`.
3. Build with `make TEST=1` (add `MONITOR_SYNTHETIC=1` for the run without
   network), flash, and save the USB console output.

For the CAP-H cases, connect the LAN8720 to a laptop and keep a GOOSE or SV
publisher sending during the test.

## Results

| Date | Build | Evidence | Passed | Failed | Log file | Notes |
|---|---|---|---|---|---|---|
| | | | | | | |
