#!/usr/bin/env python3
"""Send a short GOOSE/SV attack pattern to the isolated Pico test link.

Preview is the default. Live transmission uses Scapy at Layer 2 and requires
both --send and --confirm-isolated-lab. This fixed eight-packet profile is
the one checked against the current RF bundle: one 4-frame batch per protocol,
with the two model results less than one second apart.
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path


# Easy-to-change lab settings. These values match the profile checked against
# the current model bundle; changing them can change the model's classification.
DEFAULT_INTERFACE = "Ethernet"
SV_PERIOD_US = 2_000
GOOSE_PERIOD_US = 100_000
SV_SAMPLE_COUNTS = (15, 12, 17, 18)  # includes a backwards step, then a jump
SV_FRAME_COUNT = len(SV_SAMPLE_COUNTS)
GOOSE_STATE_NUMBERS = (1, 101, 201, 301)
GOOSE_FRAME_COUNT = len(GOOSE_STATE_NUMBERS)
MODEL_AGREEMENT_WINDOW_US = 1_000_000
FIRMWARE_PROBABILITY_GATE = 0.65

# Reference scores for this profile from the current joblib and generated C
# models. The sender does not load or run a model at runtime.
CURRENT_GOOSE_MALICIOUS_SCORE = 0.7631
CURRENT_SV_MALICIOUS_SCORE = 0.9658
CURRENT_GOOSE_MODEL_THRESHOLD = 0.0262
CURRENT_SV_MODEL_THRESHOLD = 0.9452

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


GOOSE_DST = bytes.fromhex("010ccd010001")
SV_DST = bytes.fromhex("010ccd040001")
GOOSE_APPID = 0x1000
SV_APPID = 0x4000
STREAM_ID = "PicoFlagTest"


def ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + ber_length(len(value)) + value


def ber_uint(value: int) -> bytes:
    if value < 0:
        raise ValueError("BER unsigned value cannot be negative")
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


def ethernet_frame(destination: bytes, ether_type: int, payload: bytes) -> bytes:
    # Locally administered unicast placeholder for preview. Live mode replaces
    # it with the selected Windows interface's actual MAC address.
    source = bytes.fromhex("020000000001")
    return destination + source + struct.pack(">H", ether_type) + payload


def goose_frame(sequence: int, epoch_seconds: float) -> bytes:
    seconds = int(epoch_seconds)
    fraction = int((epoch_seconds - seconds) * (1 << 24))
    utc_time = struct.pack(">I", seconds & 0xFFFFFFFF) + fraction.to_bytes(3, "big") + b"\x0a"
    state_number = GOOSE_STATE_NUMBERS[sequence]
    fields = b"".join((
        tlv(0x80, f"{STREAM_ID}/GOOSE".encode()),
        tlv(0x81, ber_uint(2000)),
        tlv(0x82, b"PicoFlagTest"),
        tlv(0x83, b"PicoFlagTest"),
        tlv(0x84, utc_time),
        tlv(0x85, ber_uint(state_number)),
        tlv(0x86, ber_uint(0)),
        tlv(0x87, b"\x01"),  # GOOSE test marker
        tlv(0x88, ber_uint(1)),
        tlv(0x89, b"\x00"),
        tlv(0x8A, ber_uint(1)),
        tlv(0xAB, tlv(0x83, bytes((sequence & 1,)))),
    ))
    apdu = tlv(0x61, fields)
    payload = struct.pack(">HHHH", GOOSE_APPID, 8 + len(apdu), 0, 0) + apdu
    return ethernet_frame(GOOSE_DST, 0x88B8, payload)


def sv_frame(sequence: int) -> bytes:
    # Deliberate one-step counter regression followed by a jump. The sample
    # values switch from a varying six-channel waveform to a flat signal.
    if sequence == 0:
        channels = (1000.0, 2000.0, 3000.0, 100.0, 200.0, 300.0)
    else:
        channels = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    seq_data = struct.pack(">8f", *channels, 0.0, 0.0)
    asdu = tlv(0x30, b"".join((
        tlv(0x80, f"{STREAM_ID}/SV".encode()),
        tlv(0x82, SV_SAMPLE_COUNTS[sequence].to_bytes(2, "big")),
        tlv(0x83, (1).to_bytes(4, "big")),
        tlv(0x85, b"\x00"),
        tlv(0x87, seq_data),
    )))
    apdu = tlv(0x60, tlv(0x80, b"\x01") + tlv(0xA2, asdu))
    payload = struct.pack(">HHHH", SV_APPID, 8 + len(apdu), 0x8000, 0) + apdu
    return ethernet_frame(SV_DST, 0x88BA, payload)


@dataclass(frozen=True)
class ScheduledFrame:
    relative_us: int
    protocol: str
    raw: bytes


def make_test_frames(start_epoch: int) -> list[ScheduledFrame]:
    """Build four malformed/state-changing packets for each RF stream."""
    frames: list[ScheduledFrame] = []

    # GOOSE carries the test bit, toggled data, and repeated large stNum jumps.
    for sequence in range(GOOSE_FRAME_COUNT):
        relative_us = sequence * GOOSE_PERIOD_US
        timestamp = start_epoch + relative_us / 1_000_000.0
        frames.append(ScheduledFrame(
            relative_us,
            "GOOSE",
            goose_frame(sequence, timestamp),
        ))

    # SV carries the reserved marker. smpCnt moves backwards once, and the
    # waveform becomes flat after the first sample to make the break visible.
    for index in range(SV_FRAME_COUNT):
        relative_us = index * SV_PERIOD_US
        frames.append(ScheduledFrame(
            relative_us,
            "SV",
            sv_frame(index),
        ))

    # Keep the same tie ordering used for model calibration: GOOSE before SV
    # when both are scheduled at the first timestamp.
    return sorted(frames, key=lambda frame: frame.relative_us)


def resolve_interface(interface_name: str):
    from scapy.all import conf

    try:
        interface = conf.ifaces.dev_from_name(interface_name)
    except (KeyError, ValueError):
        interface = None
    if interface is None:
        wanted = interface_name.casefold()
        for candidate in conf.ifaces.values():
            labels = (
                str(getattr(candidate, "name", "") or ""),
                str(getattr(candidate, "description", "") or ""),
            )
            if any(label.casefold() == wanted for label in labels if label):
                interface = candidate
                break
    if interface is None:
        available = sorted({
            str(getattr(item, "name", item)) for item in conf.ifaces.values()
        })
        raise RuntimeError(
            f"Scapy cannot find {interface_name!r}. Available: {', '.join(available)}"
        )
    return interface


def send_frames(frames: list[ScheduledFrame], interface_name: str) -> None:
    try:
        from scapy.all import Ether, conf, get_if_hwaddr, sendp
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for live sending. Install it with "
            "`python -m pip install scapy`; Windows also needs Npcap."
        ) from exc

    interface = resolve_interface(interface_name)
    source = bytes.fromhex(get_if_hwaddr(interface).replace(":", ""))
    try:
        sock = conf.L2socket(iface=interface)
    except Exception as exc:
        raise RuntimeError(
            "could not open the Ethernet interface; run PowerShell as "
            "Administrator and check that Npcap is installed"
        ) from exc

    start = time.perf_counter()
    largest_lateness = 0.0
    try:
        for frame in frames:
            deadline = start + frame.relative_us / 1_000_000.0
            remaining = deadline - time.perf_counter()
            if remaining > 0.002:
                time.sleep(remaining - 0.001)
            while time.perf_counter() < deadline:
                pass
            largest_lateness = max(
                largest_lateness,
                max(0.0, time.perf_counter() - deadline),
            )
            raw = frame.raw[:6] + source + frame.raw[12:]
            packet = Ether(raw)
            if bytes(packet) != raw:
                raise RuntimeError(f"Scapy changed the {frame.protocol} frame bytes")
            sendp(packet, socket=sock, verbose=False)
    finally:
        sock.close()

    print(f"sent_packets={len(frames)}")
    print(f"largest_schedule_lateness_ms={largest_lateness * 1000.0:.3f}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default=DEFAULT_INTERFACE)
    parser.add_argument("--send", action="store_true", help="transmit packets live")
    parser.add_argument(
        "--confirm-isolated-lab",
        action="store_true",
        help="confirm the selected Ethernet cable goes only to the Pico test link",
    )
    args = parser.parse_args()
    if args.send and not args.confirm_isolated_lab:
        parser.error("--send requires --confirm-isolated-lab")

    start_epoch = int(time.time())
    frames = make_test_frames(start_epoch)
    print(f"interface={args.interface}")
    print(f"profile=malicious packets={len(frames)} GOOSE=4 SV=4 SV_ASDUs=1")
    print(
        "current_model_reference="
        f"GOOSE {CURRENT_GOOSE_MALICIOUS_SCORE:.4f} "
        f"(threshold {CURRENT_GOOSE_MODEL_THRESHOLD:.4f}), "
        f"SV {CURRENT_SV_MALICIOUS_SCORE:.4f} "
        f"(threshold {CURRENT_SV_MODEL_THRESHOLD:.4f})"
    )
    print(
        f"firmware_gate={FIRMWARE_PROBABILITY_GATE:.2f} "
        f"agreement_window_ms={MODEL_AGREEMENT_WINDOW_US / 1000:.0f}"
    )
    print(
        "sv_attack=smpCnt_backwards+flat_waveform; "
        "goose_attack=stNum_jumps+test_bit+data_change"
    )

    if args.send:
        print("lab_confirmation=isolated Pico Ethernet link")
        send_frames(frames, args.interface)
    else:
        print("mode=preview; add --send --confirm-isolated-lab to transmit")
        for index, frame in enumerate(frames):
            print(
                f"packet={index + 1} at_ms={frame.relative_us / 1000:.3f} "
                f"protocol={frame.protocol} bytes={len(frame.raw)}"
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
