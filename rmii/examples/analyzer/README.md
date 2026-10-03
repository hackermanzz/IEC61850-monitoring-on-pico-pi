# LAN8720 live batch random-forest analyzer

This firmware replaces the button-generated examples with live Ethernet input:

```text
LAN8720 electrical signal
  -> PIO/DMA Ethernet frame capture on core 1
  -> timestamped frame queue
  -> VLAN + IEC 61850 GOOSE/SV parser on core 0
  -> per-stream rolling feature state
  -> generated C classifier
  -> recent GOOSE + SV score agreement controls Maker Pi GP15 LED
```

The old `examples/httpd` receiver remains available as a display/debug build.
The `pico_rmii_ethernet_analyzer` target performs live batch inference and
deliberately does not run DHCP or the web server. The separate
`firmware/main.cpp` serial demo is unchanged.

## Pins

The wiring remains the same as the receiver project:

| Function | Pico GPIO |
| --- | ---: |
| LAN8720 TXD0, TXD1 | GP0, GP1 (Grove 1) |
| LAN8720 TX_EN | GP2 (Grove 2) |
| LAN8720 MDIO, MDC | GP4, GP5 (Grove 3) |
| LAN8720 RXD0, RXD1 | GP6, GP7 (Grove 4) |
| LAN8720 CRS_DV | GP8 (Grove 5) |
| LAN8720 `nINT/REFCLKO` | GP20 may remain connected, but is unused |

This receive-only analyzer now runs the Pico from its internal 50 MHz clock.
GP20 and GP21 are unused by the firmware. An existing
`nINT/REFCLKO -> GP20` wire may remain connected, so the Grove wiring does not
need to change.

### Waveshare LAN8720 clock warning

The stock Waveshare-style board shown in the project photos uses its onboard
50 MHz oscillator for the LAN8720. This firmware independently samples the
receive pins using the Pico's internal 50 MHz clock. Its 10 Mbps run-length
decoder is designed to tolerate 9/10-sample dibit runs, making this a practical
firmware-only test without modifying the PHY board.

This is deliberately an experimental receive-only arrangement and is not a
general synchronous RMII implementation. CRC validation rejects damaged
captures. Use the serial statistics to evaluate it: `rx` should increase and
`bad_crc` should remain low. Reliable RMII transmission would require one
shared 50 MHz reference clock and the TX wiring.

This mapping is specific to the analyzer target and is arranged for the Maker
Pi Pico's Grove connectors. A Grove-to-female-Dupont cable, Grove terminal
breakout, or a split Grove cable is required because the LAN8720 module has a
2x6 pin header rather than a Grove socket. Unused Grove conductors must remain
insulated and disconnected.

For the receive-only analyzer, the physical `TXD0`, `TXD1`, and `TX_EN` wires
may initially be omitted. The shortest test setup is therefore:

- Grove 3: GP4 -> MDIO and GP5 -> MDC.
- Grove 4: GP6 -> RX0, GP7 -> RX1, GND -> GND, and 3V3 -> VCC.
- Grove 5: GP8 -> CRS; leave the GP9 signal wire disconnected. The firmware
  drives GP15 (not GP9) for the Maker Pi's onboard GPIO status LED.
- Existing LAN `nINT/REFCLKO` -> GP20 wire: it may remain connected, but this
  firmware does not read it.

Leave the LAN8720 `TX-EN`, `TX0`, `TX1`, and `NC` pins unconnected. This is
appropriate only while the firmware is acting as a passive receiver. Connect
the Grove 1/2 transmit mapping later if outbound Ethernet is required.

The analyzer reserves PIO1 state machines 0 and 1 for RMII. It deliberately
does not initialize the Pico W's CYW43 wireless chip. The Pico W onboard LED is
controlled through CYW43, so the Class 1 indicator instead uses GP15 for the
Maker Pi carrier's GPIO status LED. Keep the Grove 5 GP9 signal wire
disconnected. This prevents CYW43 SPI startup errors when the
analyzer is running `clk_sys` at its internal 50 MHz receive-sampling rate.

### Optional SPI SD card wiring

The analyzer uses GP0-GP8 and GP15; GP16-GP19 are available for an optional
SPI0 SD-card module. The Pico W board defaults are MISO GP16, CS GP17, SCK
GP18, and MOSI GP19. Check the carrier and connected peripherals before wiring;
the driver accepts explicit GPIOs and SPI instance settings rather than
assuming these defaults. The SD module is not initialized by `main.c` yet.

The file layer is in `sdcard_fs.h`. Call `sd_card_init()` with a board-specific
configuration first, then `sdcard_fs_mount()`. All file paths are ASCII,
root-relative paths using `/`, at most `SDCARD_FS_PATH_MAX` bytes, and may not
contain a drive prefix, leading or trailing slash, empty component, `.` or
`..` component, or FAT-reserved characters. Existing parent directories must
already exist. Reads and writes use byte offsets; reads return the number of
bytes actually read, and updates write an existing file without creating it.
An update offset must be at or before the current end of the file; use the file
size from `sdcard_fs_stat()` to append. Updates sync before returning. Call all
filesystem APIs from one core/thread at a time; this FatFs configuration does
not enable reentrancy. Unmount before calling `sd_card_deinit()` or before
reinitializing the raw card driver; mount again after reinitialization.
The card must already contain a FAT12, FAT16, or FAT32 volume; mounting does
not format the card. A card without a FAT volume returns
`SDCARD_FS_NO_FILESYSTEM`.
File operations are synchronous and block the calling core while SPI and FAT
metadata are accessed. In the analyzer, large writes or card busy periods on
core 0 can delay draining the eight-frame RMII capture queue and cause packet
drops. Do not call filesystem APIs from an ISR or core 1; if logging volume
becomes significant, queue bounded records for a lower-priority writer.

Example call sequence for `main.c` after wiring the module:

```c
sd_card_config_t card_config = {
    .spi = spi0,
    .sck_gpio = 18u,
    .mosi_gpio = 19u,
    .miso_gpio = 16u,
    .cs_gpio = 17u,
    .init_baud_hz = 400000u,
    .transfer_baud_hz = 12000000u,
};
uint32_t bytes_written = 0u;
const char log_data[] = "analyzer started\r\n";

if (sd_card_init(&card_config) == SD_CARD_OK &&
    sdcard_fs_mount() == SDCARD_FS_OK &&
    sdcard_fs_create("capture.log") == SDCARD_FS_OK) {
    (void) sdcard_fs_update("capture.log", 0u, log_data,
                            (uint32_t) (sizeof(log_data) - 1u),
                            &bytes_written);
}
```

`SDCARD_FS_ALREADY_EXISTS`, `SDCARD_FS_NOT_FOUND`, `SDCARD_FS_INVALID_PATH`,
`SDCARD_FS_OFFSET_OUT_OF_RANGE`, and `SDCARD_FS_IO_ERROR` distinguish common
failure cases. The bundled FatFs R0.15 source and its redistribution terms are
under `third_party/fatfs`; the local config enables FAT read/write, bounded
96-character long names, one volume, fixed 512-byte sectors, and no heap or
filesystem locking.

## Build and flash

Open the top-level `rmii` folder with the
Raspberry Pi Pico VS Code extension, select **Pico W**, and build the target:

```text
pico_rmii_ethernet_analyzer
```

Flash `pico_rmii_ethernet_analyzer.uf2` by holding BOOTSEL while connecting the
Pico, then copy the UF2 to the `RPI-RP2` drive. Open the USB serial port at
115200 baud.

The offline CLI validation in this workspace used Pico SDK 2.3.1, the bundled
ARM GCC 15.2 toolchain and Ninja. Its configure command included
`-DCMAKE_EXE_LINKER_FLAGS="-mcpu=cortex-m0plus -mthumb -mfloat-abi=soft"`
because this standalone CMake configuration did not apply the architecture
flags to the final link automatically. This is a local configure/toolchain
detail; the analyzer target does not override SDK linker behavior. The
validation used `-DPICO_NO_PICOTOOL=1`, so CMake does not automatically create
or refresh a UF2 after rebuilding. A UF2 was manually produced from the current
ELF with picotool. From the `rmii` directory, run this after rebuilding the
analyzer ELF:

```powershell
$picotool = Join-Path $env:USERPROFILE '.pico-sdk\picotool\2.3.1\picotool\picotool.exe'
& $picotool uf2 convert build-analyzer-validation/examples/analyzer/pico_rmii_ethernet_analyzer.elf -t elf build-analyzer-validation/examples/analyzer/pico_rmii_ethernet_analyzer.uf2 -t uf2 --platform rp2040
```

The firmware has not been run or tested on the actual hardware.

## BARR-C:2018 checks

The analyzer implementation and generated model runtime use C99 to meet
BARR-C:2018 rule 1.1.a. `c99_static_assert_compat.h` adapts the Pico SDK 2.3.1
C headers' `static_assert` spelling without modifying SDK files. The repository
`tools/check_barr_style.ps1` checks clang-format on listed files. The official
kit `.clang-tidy` profile is also in the repository, but its current
first-party findings are recorded in `BARR_C_TIDY_FINDINGS.md` and are still
under review. Barr Group's kit maps 61 of the standard's 167 rules to
mechanical gates; remaining rules require other analysis or human review.
See Barr Group's [BARR-C:2018 standard and enforcement kit]
(https://barrgroup.com/embedded-c-coding-standard).

## Current batch inference contract

The live analyzer now follows `tools/pcap_events.py`, `tools/batch_pipeline.py`,
and the runtime schema in `firmware/generated_batch/generated_batch_models.h`.
Each GOOSE frame contributes 13 causal features; each SV Ethernet frame
contributes 18 features after processing every ASDU. Feature values are
aggregated as mean, max, last, and population standard deviation over four
stream frames, producing 52 GOOSE or 72 SV model inputs. Windows advance by
two frames. Partial windows are not scored.

Stream identity is APPID + GOOSE `gocbRef` or the first ASDU's SV `svID` +
destination MAC. A 14-ASDU Ethernet packet may contain distinct `svID` values;
the packet is one model input and all of its ASDUs are processed under that
first-ASDU stream identity, matching the training pipeline's model schema.
Source MAC is used only for `publisher_change`. Capture-wide age context and
pending batches reset after an RMII queue sequence gap. Raw GOOSE test bits and
SV reserved marker bits are excluded from inference. Thresholds and waveform
settings come from the generated model header.

The LED now uses a cross-protocol agreement rule in `main.c`: the latest
GOOSE and SV probabilities must each be at least `kMaliciousProbabilityGate`
(currently 0.65) and both predictions must be no more than
`kModelAgreementWindowUs` (currently 1,000,000 microseconds / 1 second) old.
These are separate from each model's original trained thresholds. A newer low
score replaces that protocol's earlier score, and old scores expire, so the
LED turns off when agreement ends. The rule compares the most recent score per
protocol; it does not match a GOOSE stream to a particular SV stream.

RP2040 capacity is bounded to four GOOSE streams, two SV streams, fourteen
ASDUs per SV frame, and 64-byte stream identifiers. Unsupported capacity is
counted and affected input is not scored. These stream slots are fixed for the
runtime session and are not reclaimed automatically; captures with more than
four distinct GOOSE or two distinct SV identities will leave later identities
unsupported. SV histories keep the configured 128 samples per channel and ASDU
position. RMII reception remains asynchronous at 50 MHz with an eight-frame
queue and 10 Mbps advertised speed. The firmware reports average and maximum
analyzer time per frame in its ten-second summary; measure target throughput
and watch queue drops before relying on live timing behavior.

The firmware has not been run or tested on the actual hardware; measure target
throughput and validate capture behavior before relying on it.
