# Coding standard: BARR-C:2018

All C code in this project follows the *Embedded C Coding Standard*
(BARR-C:2018, Barr Group). This page explains how the team applies it, which
rules are checked automatically, and where the project deviates.

## Before every commit

1. Start new files from `templates/module.h` and `templates/module.c`.
2. Format: `clang-format -i <files>` (uses `.clang-format`; clang-format 16+,
   which ships with the VS Code C/C++ extension).
3. Check: `python tools/barr_check.py <your folder>`, then fix every finding.
4. Review the checklist below for the rules a tool cannot check.

## Naming quick reference

| Item | Rule | Example |
|---|---|---|
| Folder | what the module does, never a number | `capture/` |
| File (module) | lowercase, digits, `_`; `.c` + `.h` pair; unique in the first 8 characters (4.1, 4.2.a) | `rmii_frame.c` |
| Public function | `<module>_<verb>`, no capitals, max 31 chars (6.1) | `rmii_frame_crc()` |
| Task function | ends in `_task` (6.4) | `producer_task()` |
| ISR | ends in `_isr`, `static` (6.5) | `crs_dv_isr()` |
| Type | lowercase, ends in `_t`, public ones start with the module (5.1) | `capture_frame_t` |
| Macro | no lowercase letters (6.1.f) | `CAPTURE_FRAME_CAPACITY` |
| Variable | lowercase, at least 3 chars, max 31 (7.1) | `word_count` |
| Global (file scope too) | `g_` prefix (7.1.j) | `g_stats` |
| Pointer | `p_` prefix; pointer to pointer `pp_` (7.1.k, l) | `p_frame` |
| Boolean | `b_` prefix, phrased as a question (7.1.m) | `b_is_full` |
| Handle (kernel ID, file) | `h_` prefix (7.1.n) | `gh_frame_pool` |

Combined prefixes go in the order `[g][p|pp][b|h]`, e.g. `gb_armed`.

## Checked by `tools/barr_check.py`

| Rule | Check |
|---|---|
| 1.2.a | No line longer than 80 characters |
| 1.7.a-d | No `auto`, `register`, `goto`, `continue` |
| 2.1.b | No `/*`, `//` or backslash inside a comment |
| 3.3.c | File ends with `/*** end of file ***/` and a newline |
| 3.5.a | No tab characters |
| 3.6.a-b | LF line endings; no other non-printing characters except form feed |
| 4.1.a | File names: lowercase letters, digits and `_` only |
| 4.2.a | Every `.c` file has a `.h` file with the same name |
| 4.2.b | Every header has an `#ifndef` / `#define` include guard |
| 4.3.c | Every `.c` file includes its own header |
| 5.2.b | No `short` or `long` |
| 8.5.b | No `abort()`, `exit()`, `setjmp()`, `longjmp()` |
| format | With `--format`, the file matches `.clang-format` |

## Code review checklist (not automated)

- **1.3.a** braces around every `if`/`else`/`for`/`while`/`do`/`switch` body.
- **1.4** parentheses instead of precedence; each `&&`/`||` operand that is
  not a single identifier or constant is in parentheses.
- **1.6.a** every cast has a comment saying why it is safe.
- **1.8** `static` for module-private items; `const` where values do not
  change; `volatile` for data shared with an ISR or another task.
- **2.1.c** no commented-out code; use `#if 0` or `#ifndef NDEBUG`.
- **2.2** comments are full sentences; every module and function has a
  Doxygen comment; use `WARNING:`, `NOTE:` and `TODO:` markers.
- **3.1, 3.2, 3.3.b** spacing and alignment (mostly handled by clang-format);
  a blank line before and after each block.
- **4.2.c** headers expose only what other modules need; no `extern`
  variables in headers.
- **4.3.b** source file sections in template order.
- **5.2.a, 5.3** fixed-width types (`uint8_t`, `int32_t`, ...); no mixing of
  signed and unsigned; `u` suffix on unsigned constants.
- **6.2** functions under 100 lines; preferably one `return` at the end.
- **6.3** functions instead of function-like macros.
- **7.2** every variable initialized; pointers without a target set to `NULL`.
- **8.2** nesting at most two levels; every `else if` chain ends in `else`.
- **8.3** every `switch` has `default`; `break` aligned with its `case`.
- **8.4** no magic numbers in loops; infinite loops are `for (;;)`.
- **8.6** constant on the left of `==`, e.g. `if (NULL == p_frame)`.

## Project deviations

| Rule | Deviation | Reason |
|---|---|---|
| 1.1.a | The build uses `-std=gnu11`, not C99. | Set by the shared micro T-Kernel template build. C11 `_Static_assert` is used for compile-time layout checks. |
| 1.1.c | `__builtin_ctz` and `__asm volatile("nop")` are used. | Only in hardware/driver modules, each with a `NOTE:` comment. |
| 5.2.a | micro T-Kernel types (`ER`, `ID`, `INT`, `T_MSG`, ...) appear in kernel calls. | They are the kernel API types. |
| 6.2.c | The frame parsers and stream look-ups in `analysis/analyzer.c` return as soon as input is malformed or the answer is known. | One exit is a preferred practice, not a rule; early returns keep the bounds checks flat and easy to review. |
| 7.1.m | The `bool` members of `analyzer_result_t` have no `b_` prefix. | The storage, health and alarm modules share these member names. |
| all | Generated files (for example `*.pio.h` from `pioasm`) and `third_party/` are not checked. | They must not be edited by hand. |

## Abbreviations (rule 1.5.b)

The abbreviations in Appendix A of BARR-C:2018 may be used. The project adds:

| Abbreviation | Meaning |
|---|---|
| apdu | application protocol data unit |
| appid | IEC 61850 application identifier |
| asdu | application service data unit (one SV sample set) |
| ber | Basic Encoding Rules (ASN.1) |
| conf_rev | configuration revision (confRev) |
| crc | cyclic redundancy check |
| crs_dv | carrier sense / receive data valid (RMII signal) |
| diag | diagnostics |
| dibit | a two-bit RMII receive symbol |
| dma | direct memory access |
| fcs | frame check sequence (Ethernet CRC-32) |
| fnv | Fowler-Noll-Vo hash |
| gocb | GOOSE control block (gocbRef) |
| goose | Generic Object Oriented Substation Event (IEC 61850-8-1) |
| hw | hardware |
| iec | International Electrotechnical Commission |
| mac | medium access control (Ethernet address) |
| mbx | mailbox (micro T-Kernel) |
| mdc / mdio | management data clock / input-output (PHY management bus) |
| mpf | fixed-size memory pool (micro T-Kernel) |
| nds_com | needs commissioning (ndsCom) |
| pdu | protocol data unit |
| phy | Ethernet physical-layer transceiver (LAN8720) |
| pio | programmable I/O block (RP2040) |
| rmii | Reduced Media-Independent Interface |
| scd / scl | substation configuration description / language |
| sfd | start frame delimiter |
| sm | PIO state machine |
| smp | symmetric multiprocessing |
| smp_cnt / smp_synch | SV sample count / sample synchronisation |
| sq / st | GOOSE sequence / state number (sqNum, stNum) |
| sv | Sampled Values (IEC 61850-9-2) |
| tls | Transport Layer Security |
| tlv | tag-length-value element |
| ttl | time allowed to live |
| vlan | virtual LAN (IEEE 802.1Q tag) |

## Reference

Barr Group, *Embedded C Coding Standard* (BARR-C:2018),
https://barrgroup.com/embedded-systems/books/embedded-c-coding-standard
