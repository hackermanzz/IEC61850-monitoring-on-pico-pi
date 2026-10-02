"""Create small real-PCAP fixtures for host/Pico batch-model parity checks.

The fixture stores the source Ethernet frame bytes and timestamps beside the
exact named model-input vector. Labels, marker fields, and audit metadata are
never copied into the feature vector.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from batch_pipeline import build_batches  # noqa: E402
from pcap_events import _blocks, decode_ethernet_frame, decode_pcapng  # noqa: E402


DEFAULT_INPUT = ROOT / "Test Dataset" / "test.pcapng"
DEFAULT_OUTPUT = ROOT / "firmware" / "generated_batch" / "real_packet_fixtures.json"
BUNDLE = ROOT / "rf_batch_models" / "iec61850_rf_batch_bundle.joblib"
TARGETS = {("GOOSE", ""): "goose", ("SV", "1"): "sv_1_asdu", ("SV", "14"): "sv_14_asdu"}


def stream_key(event: dict[str, Any]) -> str:
    appid = int(str(event.get("appid") or 0), 0) if str(event.get("appid") or "0").lower().startswith("0x") else int(event.get("appid") or 0)
    return (
        f"{event['stream_id']}|appid={appid:04x}|"
        f"dst={str(event.get('dst_mac', '')).lower()}"
    )


def frame_indices_for_batch(batch: dict[str, Any], events: list[dict[str, Any]]) -> list[int]:
    indices = sorted({
        int(event["frame_index"])
        for event in events
        if event["capture_id"] == batch["capture_id"]
        and event["protocol"] == batch["protocol"]
        and stream_key(event) == batch["stream_id"]
        and int(batch["start_frame"]) <= int(event["frame_index"]) <= int(batch["end_frame"])
    })
    if len(indices) != int(batch["batch_frames"]):
        raise ValueError(f"batch frame mapping failed: expected {batch['batch_frames']}, found {len(indices)}")
    return indices


def selected_packet_bytes(pcap_path: Path, frame_indices: set[int]) -> dict[int, bytes]:
    selected = {}
    for frame_index, (_linktype, packet, _timestamp) in enumerate(_blocks(pcap_path)):
        if frame_index in frame_indices:
            selected[frame_index] = packet
            if len(selected) == len(frame_indices):
                break
    if selected.keys() != frame_indices:
        missing = sorted(frame_indices - selected.keys())
        raise ValueError(f"source PCAP did not contain expected frame indices: {missing}")
    return selected


def make_case(
    pcap_path: Path,
    batch: dict[str, Any],
    events: list[dict[str, Any]],
    model_entry: dict[str, Any],
    case_id: str,
) -> dict[str, Any]:
    feature_names = [str(name) for name in model_entry["feature_names"]]
    feature_values = {name: float(batch[name]) for name in feature_names}
    if any(not math.isfinite(value) for value in feature_values.values()):
        raise ValueError(f"{case_id} contains non-finite model features")
    forbidden_fragments = ("attack", "label", "marker", "raw_test", "raw_simulated", "scenario")
    if any(any(fragment in name.lower() for fragment in forbidden_fragments) for name in feature_names):
        raise ValueError("a label/audit field unexpectedly appears in the trained model input schema")

    indices = frame_indices_for_batch(batch, events)
    feature_array = np.asarray([feature_values[name] for name in feature_names], dtype=np.float32).reshape(1, -1)
    model = model_entry["model"]
    positive_index = int(np.flatnonzero(np.asarray(model.classes_) == 1)[0])
    expected_probability = float(model.predict_proba(feature_array)[0, positive_index])
    return {
        "case_id": case_id,
        "capture_file": pcap_path.name,
        "protocol": batch["protocol"],
        "asdu_shape": batch["asdu_shape"] or None,
        "batch_frame_indices": indices,
        "frame_count": len(indices),
        "feature_names": feature_names,
        "features": feature_values,
        "expected_probability_float32_inputs": expected_probability,
        "threshold": float(model_entry["threshold"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, action="append", dest="pcaps")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    pcaps = args.pcaps or [DEFAULT_INPUT]
    bundle = joblib.load(BUNDLE)
    config = bundle["feature_config"]
    chosen: dict[str, tuple[Path, dict[str, Any], list[dict[str, Any]]]] = {}

    for pcap_path in pcaps:
        events, diagnostics = decode_pcapng(pcap_path)
        if not events:
            continue
        batches = build_batches(events, config)
        for batch in batches:
            shape = str(batch.get("asdu_shape") or "")
            case_id = TARGETS.get((str(batch["protocol"]), shape))
            if case_id and case_id not in chosen:
                chosen[case_id] = (pcap_path, batch, events)
        if len(chosen) == len(TARGETS):
            break
    missing = sorted(set(TARGETS.values()) - chosen.keys())
    if missing:
        raise ValueError(f"could not find representative batches for: {missing}")

    # Keep only the streams whose batches become the three fixtures. Filtering
    # changes cross-protocol age features, so rebuild all batches from a fresh
    # state using precisely the event sequence that the firmware will replay.
    for pcap_path in sorted({value[0] for value in chosen.values()}, key=str):
        source_events = next(events for path, _batch, events in chosen.values() if path == pcap_path)
        retained_streams = {
            batch["stream_id"]
            for path, batch, _events in chosen.values()
            if path == pcap_path
        }
        retained_frame_indices = {
            int(event["frame_index"])
            for event in source_events
            if stream_key(event) in retained_streams
        }
        # An SV Ethernet packet is one model input even when its ASDUs carry
        # different svIDs. Keep every decoded ASDU row for each selected
        # packet so Python builds the same per-frame point as firmware.
        filtered = [
            event for event in source_events
            if int(event["frame_index"]) in retained_frame_indices
        ]
        rebuilt_batches = build_batches(filtered, config)
        for case_id, (path, original_batch, _events) in list(chosen.items()):
            if path != pcap_path:
                continue
            rebuilt = next((batch for batch in rebuilt_batches
                            if batch["protocol"] == original_batch["protocol"]
                            and batch["asdu_shape"] == original_batch["asdu_shape"]
                            and batch["stream_id"] == original_batch["stream_id"]
                            and batch["start_frame"] == original_batch["start_frame"]
                            and batch["end_frame"] == original_batch["end_frame"]), None)
            if rebuilt is None:
                raise ValueError(f"filtered replay did not reproduce selected batch window {case_id}")
            chosen[case_id] = (path, rebuilt, filtered)

    context_ends = {
        pcap_path: max(int(batch["end_frame"]) for selected_path, batch, _events in chosen.values() if selected_path == pcap_path)
        for pcap_path, _batch, _events in chosen.values()
    }
    capture_prefixes = []
    for pcap_path, max_frame in context_ends.items():
        source_events = next(events for selected_path, _batch, events in chosen.values() if selected_path == pcap_path)
        context_events = [event for event in source_events if int(event["frame_index"]) <= max_frame]
        events_by_frame: dict[int, list[dict[str, Any]]] = {}
        for event in context_events:
            events_by_frame.setdefault(int(event["frame_index"]), []).append(event)
        frame_representatives = [rows[0] for rows in events_by_frame.values()]
        stream_counts = {
            protocol: len({
                stream_key(event)
                for event in frame_representatives
                if event["protocol"] == protocol
            })
            for protocol in ("GOOSE", "SV")
        }
        if stream_counts["GOOSE"] > 4 or stream_counts["SV"] > 2:
            raise ValueError(f"filtered fixture exceeds analyzer stream-state caps: {stream_counts}")
        context_indices = {int(event["frame_index"]) for event in context_events}
        packet_bytes = selected_packet_bytes(pcap_path, context_indices)
        prefix_frames = []
        for index in sorted(events_by_frame):
            rows = events_by_frame[index]
            decoded_rows, decode_error = decode_ethernet_frame(
                packet_bytes[index], float(rows[0]["timestamp"]),
                pcap_path.name, index,
            )
            if decode_error is not None:
                raise ValueError(
                    f"fixture source frame {index} no longer decodes: {decode_error}"
                )
            if len(decoded_rows) != len(rows):
                raise ValueError(
                    f"fixture frame {index} retains {len(rows)} rows but packet decodes "
                    f"{len(decoded_rows)} rows"
                )
            advertised_count = rows[0].get("no_asdu") or None
            if rows[0]["protocol"] == "SV":
                if advertised_count is None or int(advertised_count) != len(rows):
                    raise ValueError(
                        f"fixture frame {index} row count {len(rows)} does not match "
                        f"advertised SV ASDU count {advertised_count}"
                    )
            prefix_frames.append({
                "frame_index": index,
                "timestamp": float(rows[0]["timestamp"]),
                "protocol": rows[0]["protocol"],
                "asdu_count": len(decoded_rows),
                "advertised_no_asdu": advertised_count,
                "ethernet_frame_base64": base64.b64encode(packet_bytes[index]).decode("ascii"),
            })
        prefix = {
            "capture_file": pcap_path.name,
            "source_sha256": bundle.get("source_sha256", {}).get(pcap_path.name),
            "reset_before_frame_index": 0,
            "through_frame_index": max_frame,
            "replay_note": "Replay every listed IEC frame in ascending frame_index from a fresh analyzer state. Frames are selected by retained model stream identity, but every decoded ASDU row in each retained SV Ethernet frame is kept because firmware processes all ASDUs in the packet as one model input. All expected batch features and probabilities were recomputed from this filtered frame sequence. Non-GOOSE/SV Ethernet frames are omitted because the batch pipeline ignores them.",
            "fixture_correction": "The previous fixture filtered decoded SV rows by svID while retaining the original complete Ethernet packet for replay. Firmware processed every ASDU from that packet, so the prior sv_14_asdu expected waveform features represented only one ASDU. The corrected fixture preserves every decoded row for each selected frame and verifies decoded row count against the packet and advertised noASDU.",
            "tracked_stream_counts": stream_counts,
            "tracked_stream_state_caps": {"GOOSE": 4, "SV": 2},
            "retained_stream_keys": sorted({
                stream_key(event) for event in frame_representatives
            }),
            "frames": prefix_frames,
        }
        capture_prefixes.append(prefix)

    cases = []
    for case_id in ("goose", "sv_1_asdu", "sv_14_asdu"):
        pcap_path, batch, events = chosen[case_id]
        protocol = str(batch["protocol"])
        case = make_case(
            pcap_path,
            batch,
            events,
            bundle["models"][protocol],
            case_id,
        )
        case["capture_file"] = pcap_path.name
        cases.append(case)

    fixture = {
        "format": 1,
        "provenance": "decoded from supplied PCAPNG captures with tools/pcap_events.py and tools/batch_pipeline.py",
        "model_inputs_exclude_labels": True,
        "capture_prefixes": capture_prefixes,
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(fixture, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "bytes": args.output.stat().st_size,
        "prefix_frames": [len(prefix["frames"]) for prefix in capture_prefixes],
        "cases": [{"case_id": case["case_id"], "capture": case["capture_file"], "frames": case["frame_count"], "batch_frame_indices": case["batch_frame_indices"], "features": len(case["feature_names"]), "asdu_shape": case["asdu_shape"]} for case in cases],
    }, indent=2))


if __name__ == "__main__":
    main()
