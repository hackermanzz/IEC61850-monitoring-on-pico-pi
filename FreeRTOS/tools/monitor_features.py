"""Causal, capture-local IEC 61850 event features for offline model training.

Input is decoded event metadata, not raw network frames. The same feature
contract must be implemented and checked on the eventual monitoring device.
"""

from __future__ import annotations

import csv
import math
import statistics
from collections import defaultdict, deque
from pathlib import Path


EVENT_COLUMNS = (
    "capture_id", "scenario_id", "protocol", "timestamp", "src_mac",
    "expected_src_mac", "stream_id", "bus_id", "sv_reference_stream", "st_num", "sq_num",
    "smp_cnt", "smpcnt_modulus", "no_asdu", "trip_asserted", "sv_fault", "restart_authorized", "attack",
    "label_source", "conf_rev", "smp_synch", "appid",
    "expected_conf_rev", "expected_appid",
)
OPTIONAL_EVENT_COLUMNS = ("conf_rev", "smp_synch", "appid", "expected_conf_rev", "expected_appid")
REQUIRED_EVENT_COLUMNS = tuple(name for name in EVENT_COLUMNS if name not in OPTIONAL_EVENT_COLUMNS)

GOOSE_FEATURES = (
    "dt", "dt_ratio", "stnum_delta", "stnum_decrease", "sqnum_delta",
    "sqnum_back", "publisher_mismatch", "sv_disagreement", "history_ready",
)
SV_FEATURES = (
    "smpcnt_delta", "smpcnt_delta_abs", "smpcnt_back",
    "smpcnt_delta_roll_std", "dt", "dt_roll_med", "dt_ratio", "noASDU",
    "smpcnt_missing", "noASDU_missing", "conf_rev_changed", "conf_rev_mismatch",
    "conf_rev_missing", "conf_rev_expected_missing", "smp_synch_0", "smp_synch_1",
    "smp_synch_2", "smp_synch_other", "smp_synch_missing", "appid_mismatch",
    "appid_missing", "appid_expected_missing",
    "publisher_mismatch", "history_ready",
)


def _number(value: str | None) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"non-finite numeric event value: {value!r}")
    return result


def _integer(value: str | None) -> int | None:
    result = _number(value)
    if result is None:
        return None
    if result != int(result):
        raise ValueError(f"expected integer event value: {value!r}")
    return int(result)


def _protocol_integer(value: str | None) -> int | None:
    """Parse a decoded integer that may be written as decimal or 0x-prefixed hex."""
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return _integer(text)


def _bit(value: str | None) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    if str(value).strip().lower() in {"1", "true", "yes"}:
        return 1
    if str(value).strip().lower() in {"0", "false", "no"}:
        return 0
    raise ValueError(f"expected boolean event value: {value!r}")


def read_events(path: str | Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = set(REQUIRED_EVENT_COLUMNS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"event CSV is missing columns: {sorted(missing)}")
        rows = list(reader)
    # These protocol fields were not exported by older notebook versions.
    # Missing fields remain explicit so downstream features can distinguish
    # absent decoder data from a protocol value of zero.
    for row in rows:
        for field in OPTIONAL_EVENT_COLUMNS:
            row.setdefault(field, "")
    if not rows:
        raise ValueError("event CSV is empty")
    for index, row in enumerate(rows, 2):
        for field in ("capture_id", "scenario_id", "protocol", "stream_id", "label_source"):
            if not row[field].strip():
                raise ValueError(f"row {index}: {field} is required")
        if row["protocol"] not in {"GOOSE", "SV"}:
            raise ValueError(f"row {index}: protocol must be GOOSE or SV")
        if _bit(row["attack"]) is None:
            raise ValueError(f"row {index}: independent attack label is required")
        if _number(row["timestamp"]) is None:
            raise ValueError(f"row {index}: timestamp is required")
    return rows


def compute_features(
    rows: list[dict[str, str]], *, max_stnum_step: int = 20,
    max_smp_delta: int = 100, sv_agreement_window: float = 0.5,
) -> list[dict]:
    """Use only preceding events in the same capture; never infer trusted MACs."""
    if max_stnum_step < 1 or max_smp_delta < 1 or sv_agreement_window <= 0:
        raise ValueError("feature thresholds must be positive")
    indexed = sorted(
        enumerate(rows),
        key=lambda pair: (pair[1]["capture_id"], float(pair[1]["timestamp"]), pair[0]),
    )
    state: dict[tuple, dict] = defaultdict(
        lambda: {"ts": None, "st": None, "sq": None, "smp": None, "conf_rev": None,
                 "intervals": deque(maxlen=20), "smp_deltas": deque(maxlen=20)}
    )
    last_sv: dict[tuple[str, str], tuple[float, int]] = {}
    output: list[dict] = []
    for row_index, row in indexed:
        capture = row["capture_id"]
        protocol = row["protocol"]
        timestamp = float(row["timestamp"])
        src = row["src_mac"].lower().strip()
        expected = row["expected_src_mac"].lower().strip()
        stream = row["stream_id"]
        # An SV Ethernet frame may carry many ASDUs whose smpCnt values are
        # not a single sequence. Track each position across frames instead of
        # comparing unrelated ASDUs inside the same frame.
        asdu_index = _integer(row.get("asdu_index")) if protocol == "SV" else None
        key = (capture, protocol, stream, src, asdu_index)
        previous = state[key]
        prior_ts = previous["ts"]
        dt = None if prior_ts is None else timestamp - prior_ts
        if dt is not None and dt < 0:
            raise ValueError("timestamps must be monotonic within each publisher stream")
        prior_med = statistics.median(previous["intervals"]) if previous["intervals"] else None
        dt_ratio = dt / prior_med if dt is not None and prior_med and prior_med > 0 else 1.0
        mismatch = int(bool(expected and src and src != expected))
        label = _bit(row["attack"])
        record = {
            "row_index": row_index, "capture_id": capture,
            "scenario_id": row["scenario_id"], "protocol": protocol,
            "attack": label, "label_source": row["label_source"],
            "frame_index": row.get("frame_index", ""),
            "asdu_index": asdu_index if asdu_index is not None else "",
            "source_pcap": row.get("source_pcap", ""),
            "frame_length": row.get("frame_length", ""),
        }
        accept_for_state = True
        if protocol == "GOOSE":
            st = _integer(row["st_num"])
            sq = _integer(row["sq_num"])
            old_st, old_sq = previous["st"], previous["sq"]
            st_delta = st - old_st if st is not None and old_st is not None else 0
            sq_delta = sq - old_sq if sq is not None and old_sq is not None and st == old_st else 0
            authorized_restart = _bit(row.get("restart_authorized")) == 1
            if authorized_restart:
                st_delta = 0
                sq_delta = 0
                dt = None
                dt_ratio = 1.0
                previous["intervals"].clear()
            sv_ref = row.get("sv_reference_stream", "")
            sv = last_sv.get((capture, sv_ref)) if sv_ref else None
            trip = _bit(row["trip_asserted"])
            sv_disagreement = int(
                trip == 1 and sv is not None and 0 <= timestamp - sv[0] <= sv_agreement_window and sv[1] == 0
            )
            record.update({
                "dt": dt if dt is not None else 0.0,
                "dt_ratio": dt_ratio,
                "stnum_delta": st_delta,
                "stnum_decrease": int(st_delta < 0 and not authorized_restart),
                "sqnum_delta": sq_delta,
                "sqnum_back": int(sq_delta < 0),
                "publisher_mismatch": mismatch,
                "sv_disagreement": sv_disagreement,
                "history_ready": int(not authorized_restart and prior_ts is not None and old_st is not None and old_sq is not None),
            })
            # One implausible frame must not poison the following baseline.
            accept_for_state = authorized_restart or not (st_delta < 0 or st_delta > max_stnum_step or sq_delta < 0 or mismatch)
            if accept_for_state:
                previous["st"], previous["sq"] = st, sq
        else:
            smp = _integer(row["smp_cnt"])
            old_smp = previous["smp"]
            raw_delta = smp - old_smp if smp is not None and old_smp is not None else 0
            modulus = _integer(row.get("smpcnt_modulus"))
            if modulus is not None and modulus < 2:
                raise ValueError("smpcnt_modulus must be at least 2")
            conf_rev = _integer(row.get("conf_rev"))
            old_conf_rev = previous["conf_rev"]
            smp_synch = _integer(row.get("smp_synch"))
            appid = _protocol_integer(row.get("appid"))
            expected_conf_rev = _protocol_integer(row.get("expected_conf_rev"))
            expected_appid = _protocol_integer(row.get("expected_appid"))
            conf_rev_mismatch = conf_rev is not None and expected_conf_rev is not None and conf_rev != expected_conf_rev
            appid_mismatch = appid is not None and expected_appid is not None and appid != expected_appid
            wrap_band = min(max_smp_delta, max(1, modulus // 16)) if modulus else 0
            wrapped = bool(
                old_smp is not None and smp is not None and modulus is not None
                and old_smp >= modulus - wrap_band and smp < wrap_band
            )
            delta = (smp + modulus - old_smp) if wrapped else raw_delta
            delta_std = statistics.pstdev(previous["smp_deltas"]) if len(previous["smp_deltas"]) > 1 else 0.0
            record.update({
                "smpcnt_delta": delta,
                "smpcnt_delta_abs": abs(delta),
                "smpcnt_back": int(raw_delta < 0 and not wrapped),
                "smpcnt_delta_roll_std": delta_std,
                "dt": dt if dt is not None else 0.0,
                "dt_roll_med": prior_med if prior_med is not None else 0.0,
                "dt_ratio": dt_ratio,
                "noASDU": _integer(row["no_asdu"]) or 0,
                "smpcnt_missing": int(smp is None),
                "noASDU_missing": int(_integer(row["no_asdu"]) is None),
                "conf_rev_changed": int(conf_rev is not None and old_conf_rev is not None and conf_rev != old_conf_rev),
                "conf_rev_mismatch": int(conf_rev_mismatch),
                "conf_rev_missing": int(conf_rev is None),
                "conf_rev_expected_missing": int(expected_conf_rev is None),
                "smp_synch_0": int(smp_synch == 0),
                "smp_synch_1": int(smp_synch == 1),
                "smp_synch_2": int(smp_synch == 2),
                "smp_synch_other": int(smp_synch is not None and smp_synch not in {0, 1, 2}),
                "smp_synch_missing": int(smp_synch is None),
                "appid_mismatch": int(appid_mismatch),
                "appid_missing": int(appid is None),
                "appid_expected_missing": int(expected_appid is None),
                "publisher_mismatch": mismatch,
                "history_ready": int(prior_ts is not None and old_smp is not None),
            })
            # Missing counters and events that violate trusted publisher/config
            # baselines must not advance or erase the trusted rolling state.
            accept_for_state = (
                smp is not None
                and not (raw_delta < 0 and not wrapped)
                and 0 <= delta <= max_smp_delta
                and not mismatch
                and not conf_rev_mismatch
                and not appid_mismatch
            )
            if old_smp is not None and accept_for_state:
                previous["smp_deltas"].append(delta)
            if accept_for_state:
                previous["smp"] = smp
                if conf_rev is not None:
                    previous["conf_rev"] = conf_rev
            fault = _bit(row["sv_fault"])
            if accept_for_state and fault is not None:
                last_sv[(capture, stream)] = (timestamp, fault)
        if accept_for_state:
            if dt is not None:
                previous["intervals"].append(dt)
            previous["ts"] = timestamp
        output.append(record)
    return output
