"""Convert notebook GOOSE/SV CSV exports plus an independent label manifest.

The GOOSE `test` and SV `simulated` fields are deliberately ignored. Labels
must come from a reviewed manifest of capture provenance and exact frames or
attack windows. Time windows need extra selectors when legitimate traffic
overlaps them.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from monitor_features import EVENT_COLUMNS


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def bit(value: str) -> str:
    text = str(value).strip().lower()
    if text in {"true", "1"}:
        return "1"
    if text in {"false", "0"}:
        return "0"
    return ""


def matches(rule: dict, row: dict, protocol: str, source_row: int) -> bool:
    if rule.get("protocol") != protocol:
        return False
    if rule.get("capture_id") != row.get("source_pcap"):
        return False
    if "source_row" in rule and int(rule["source_row"]) != source_row:
        return False
    if "start_ts" in rule and float(row["timestamp"]) < float(rule["start_ts"]):
        return False
    if "end_ts" in rule and float(row["timestamp"]) >= float(rule["end_ts"]):
        return False
    if "src_mac" in rule and str(rule["src_mac"]).lower() != str(row.get("src_mac", "")).lower():
        return False
    stream = row.get("goCbRef") if protocol == "GOOSE" else row.get("svID")
    if "stream_id" in rule and rule["stream_id"] != stream:
        return False
    return True


def convert(
    goose: list[dict[str, str]], sv: list[dict[str, str]],
    manifest: dict, topology: dict, goose_trip_value: str,
) -> list[dict[str, str]]:
    captures = manifest.get("captures", {})
    rules = manifest.get("overrides", [])
    match_count = [0] * len(rules)
    restart_rules = manifest.get("authorized_restarts", [])
    restart_match_count = [0] * len(restart_rules)
    result: list[dict[str, str]] = []
    for protocol, source in (("GOOSE", goose), ("SV", sv)):
        for source_row, raw in enumerate(source):
            capture = raw.get("source_pcap", "")
            if capture not in captures:
                raise ValueError(f"capture {capture!r} has no reviewed manifest entry")
            config = captures[capture]
            if config.get("default_attack") not in (0, 1) or not config.get("label_source"):
                raise ValueError(f"capture {capture!r} needs default_attack and label_source")
            selected = []
            for index, rule in enumerate(rules):
                if matches(rule, raw, protocol, source_row):
                    match_count[index] += 1
                    selected.append(rule)
            if len(selected) > 1:
                raise ValueError(f"overlapping label rules on {protocol} CSV row {source_row}")
            label = selected[0] if selected else config
            stream = raw.get("goCbRef") if protocol == "GOOSE" else raw.get("svID")
            if not stream:
                raise ValueError(f"{protocol} CSV row {source_row} has no decoded stream ID")
            topo = topology.get(protocol, {}).get(stream, {})
            if not topo.get("expected_src_mac"):
                raise ValueError(f"topology has no trusted publisher for {protocol} stream {stream!r}")
            attack = label.get("attack", label.get("default_attack"))
            if attack not in (0, 1):
                raise ValueError(f"{protocol} CSV row {source_row} has no independent label")
            event = {name: "" for name in EVENT_COLUMNS}
            event.update({
                "capture_id": capture,
                "scenario_id": str(label.get("scenario_id", config.get("scenario_id", capture))),
                "protocol": protocol,
                "timestamp": raw["timestamp"],
                "src_mac": raw.get("src_mac", ""),
                "expected_src_mac": topo["expected_src_mac"],
                "stream_id": stream,
                "bus_id": topo.get("bus_id", ""),
                "attack": str(attack),
                "label_source": str(label.get("label_source", config["label_source"])),
            })
            if protocol == "GOOSE":
                event["sv_reference_stream"] = topo.get("sv_reference_stream", "")
                event["st_num"] = raw.get("stNum", "")
                event["sq_num"] = raw.get("sqNum", "")
                event["trip_asserted"] = str(int(bit(raw.get("boolean", "")) == goose_trip_value)) if bit(raw.get("boolean", "")) else ""
                for index, restart_rule in enumerate(restart_rules):
                    if matches(restart_rule, raw, protocol, source_row):
                        restart_match_count[index] += 1
                        event["restart_authorized"] = "1"
            else:
                event["smp_cnt"] = raw.get("smpCnt", "")
                event["smpcnt_modulus"] = str(topo.get("smpcnt_modulus", ""))
                event["no_asdu"] = raw.get("noASDU", "")
                event["sv_fault"] = bit(raw.get("sv_fault", ""))
            result.append(event)
    unmatched = [index for index, count in enumerate(match_count) if count == 0]
    if unmatched:
        raise ValueError(f"label override(s) matched no frame: {unmatched}")
    unmatched_restarts = [index for index, count in enumerate(restart_match_count) if count == 0]
    if unmatched_restarts:
        raise ValueError(f"authorized restart(s) matched no frame: {unmatched_restarts}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose-csv", type=Path, required=True)
    parser.add_argument("--sv-csv", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--goose-trip-value", choices=("true", "false"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    topology = json.loads(args.topology.read_text(encoding="utf-8"))
    rows = convert(
        read_csv(args.goose_csv), read_csv(args.sv_csv), manifest,
        topology, bit(args.goose_trip_value),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=EVENT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} independently labelled decoded events to {args.output}")


if __name__ == "__main__":
    main()
