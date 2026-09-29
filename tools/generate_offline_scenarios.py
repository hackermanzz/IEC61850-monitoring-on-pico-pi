"""Create labelled IEC 61850 *event metadata* for offline detector exercises.

This script does not create packets, open a network interface, or transmit data.
Synthetic captures check training mechanics; they cannot validate field accuracy.
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

from monitor_features import EVENT_COLUMNS


SCENARIOS = (
    "benign_a", "benign_b", "legitimate_fault", "goose_replay",
    "goose_counter_jump", "goose_false_trip", "goose_wrong_publisher",
    "sv_replay", "sv_counter_jump", "mixed_subtle",
)


def event(capture: str, protocol: str, timestamp: float, **values: object) -> dict[str, str]:
    row = {name: "" for name in EVENT_COLUMNS}
    row.update({
        "capture_id": capture, "scenario_id": capture, "protocol": protocol,
        "timestamp": f"{timestamp:.6f}", "bus_id": "bus1",
        "attack": "0", "label_source": "offline_scenario_manifest",
    })
    row.update({key: str(value) for key, value in values.items()})
    return row


def generate(seed: int = 7, cycles: int = 240) -> list[dict[str, str]]:
    if cycles < 100:
        raise ValueError("cycles must be at least 100")
    rng = random.Random(seed)
    result: list[dict[str, str]] = []
    goose_mac = "02:00:00:00:01:01"
    sv_mac = "02:00:00:00:01:02"
    other_mac = "02:00:00:00:ee:01"
    for capture in SCENARIOS:
        for cycle in range(cycles):
            tick = cycle * 0.1 + rng.uniform(-0.0008, 0.0008)
            fault = int(capture == "legitimate_fault" and 70 <= cycle < 95)
            # Five SV observations per GOOSE period provide preceding context.
            for sample in range(5):
                ts = tick - 0.08 + sample * 0.02
                smp = (cycle * 5 + sample) % 65536
                attack = capture in {"sv_replay", "sv_counter_jump", "mixed_subtle"} and 50 <= cycle < 180 and cycle % 3 == 0 and sample == 4
                if attack and capture == "sv_replay":
                    smp = (smp - 12) % 65536
                elif attack and capture == "sv_counter_jump":
                    smp = (smp + 600) % 65536
                elif attack:
                    smp = (smp - 1) % 65536
                result.append(event(
                    capture, "SV", ts, src_mac=sv_mac,
                    expected_src_mac=sv_mac, stream_id="MU1",
                    smp_cnt=smp, smpcnt_modulus=65536, no_asdu=1, sv_fault=fault,
                    attack=int(attack),
                ))
            st = 10 + cycle // 60
            sq = cycle % 60 + 1
            src = goose_mac
            trip = fault
            attack = capture in {
                "goose_replay", "goose_counter_jump", "goose_false_trip",
                "goose_wrong_publisher", "mixed_subtle",
            } and 50 <= cycle < 180 and cycle % 3 == 0
            if attack and capture == "goose_replay":
                st = max(1, st - 2)
                sq = max(1, sq - 7)
            elif attack and capture == "goose_counter_jump":
                st += 80
            elif attack and capture == "goose_false_trip":
                trip = 1
            elif attack and capture == "goose_wrong_publisher":
                src = other_mac
            elif attack:
                trip = 1  # counter and timing look normal; SV remains healthy
            result.append(event(
                capture, "GOOSE", tick, src_mac=src,
                expected_src_mac=goose_mac, stream_id="GCB1",
                sv_reference_stream="MU1",
                st_num=st, sq_num=sq, trip_asserted=trip,
                attack=int(attack),
            ))
    return sorted(result, key=lambda row: (row["capture_id"], float(row["timestamp"])))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--cycles", type=int, default=240)
    args = parser.parse_args()
    rows = generate(args.seed, args.cycles)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=EVENT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} offline event rows across {len(SCENARIOS)} captures to {args.output}")


if __name__ == "__main__":
    main()
