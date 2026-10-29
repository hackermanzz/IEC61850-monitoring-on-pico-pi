"""Stateful packet-batch features for IEC 61850 GOOSE and SV inference.

SV waveform continuity is measured between the same ASDU position in adjacent
frames. It uses configured relative changes and robust history, never raw
waveform magnitudes as a standalone identity feature. A batch is one training
and scoring example regardless of how many ASDUs its SV frames carry.
"""

from __future__ import annotations

import math
import statistics
import struct
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable


GOOSE_FRAME_FEATURES = (
    "dt", "dt_ratio", "stnum_delta_abs", "stnum_back", "stnum_jump",
    "sqnum_delta_abs", "sqnum_back", "publisher_change", "history_ready", "age_since_any_sv_frame",
    "data_boolean_true", "data_boolean_missing", "data_boolean_changed",
)
SV_FRAME_FEATURES = (
    "dt", "dt_ratio", "age_since_any_goose_frame", "no_asdu",
    "smpcnt_back_count", "smpcnt_repeat_count", "smpcnt_gap_count",
    "smpcnt_delta_abs_max", "wave_rel_change_mean", "wave_rel_change_max",
    "wave_jump_fraction", "wave_plateau_fraction", "wave_jump_count",
    "wave_history_coverage", "wave_change_robust_ratio",
    "wave_channel_range_rel_mean", "wave_channel_range_rel_max", "publisher_change",
)


def decode_channels(seq_data: str, layout: dict) -> tuple[float, ...]:
    raw = bytes.fromhex(str(seq_data))
    offsets = layout["offsets"]
    fmt = layout.get("format", ">f")
    width = struct.calcsize(fmt)
    needed = max(offsets) + width if offsets else 0
    if len(raw) < needed:
        raise ValueError(f"SV seqData has {len(raw)} bytes; configured channels need {needed}")
    values = tuple(struct.unpack_from(fmt, raw, offset)[0] for offset in offsets)
    if any(not math.isfinite(value) for value in values):
        raise ValueError("SV seqData contains non-finite configured channel value")
    return values


def _as_int(value, default=None):
    if value is None or str(value).strip() == "":
        return default
    return int(str(value), 0) if str(value).lower().startswith("0x") else int(value)


def _as_float(value, default=0.0):
    if value is None or str(value).strip() == "":
        return default
    return float(value)


def _label_batch(rows: list[dict]) -> tuple[int | None, str, str]:
    labels = [str(r.get("attack", "")).strip() for r in rows]
    known = {x for x in labels if x in {"0", "1"}}
    if "1" in known:
        label = 1
    elif any(x not in {"0", "1"} for x in labels):
        label = None
    elif known == {"0"}:
        label = 0
    else:
        label = None
    scenarios = sorted({str(r.get("scenario_id", "")) for r in rows if r.get("scenario_id")})
    sources = sorted({str(r.get("label_source", "")) for r in rows if r.get("label_source")})
    return label, ";".join(scenarios), ";".join(sources)


@dataclass
class _StreamState:
    timestamp: float | None = None
    st_num: int | None = None
    sq_num: int | None = None
    counters: dict[int, int] | None = None
    wave_histories: dict[int, list[deque]] | None = None
    intervals: deque | None = None
    wave_deltas: deque | None = None
    source: str | None = None
    data_boolean: bool | None = None

    def __post_init__(self):
        self.counters = {} if self.counters is None else self.counters
        self.wave_histories = {} if self.wave_histories is None else self.wave_histories
        self.intervals = deque() if self.intervals is None else self.intervals
        self.wave_deltas = deque() if self.wave_deltas is None else self.wave_deltas


class StatefulBatchFeatureBuilder:
    """Incremental frame-to-batch feature builder shared by training/inference.

    Feed events in PCAP order. Keep one instance alive across input chunks.
    Call ``update(chunk)`` repeatedly and ``flush()`` once at a capture/end of
    stream to emit pending frames and partial batches.
    """

    def __init__(self, config: dict):
        self.config = config
        batch_size = int(config["batch"]["size_frames"])
        batch_stride = int(config["batch"]["stride_frames"])
        if batch_size < 1 or batch_stride < 1 or batch_stride > batch_size:
            raise ValueError("batch size/stride must be positive and stride cannot exceed size")
        if batch_stride < batch_size and config["batch"].get("emit_partial", True):
            raise ValueError("overlapping windows must disable partial flush batches")
        self.pending_key = None
        self.pending_rows: list[dict] = []
        self.states: dict[tuple, _StreamState] = defaultdict(self._new_state)
        self.latest_goose: dict[str, float] = {}
        self.latest_sv: dict[str, float] = {}
        self.batch_points: dict[tuple, list[tuple[dict, dict]]] = defaultdict(list)
        self._last_capture: str | None = None

    def update(self, events: Iterable[dict]) -> list[dict]:
        emitted = []
        for event in events:
            capture = str(event["capture_id"])
            if self._last_capture is not None and capture != self._last_capture:
                emitted.extend(self._close_frame())
                emitted.extend(self._flush_capture(self._last_capture))
                self.states = defaultdict(self._new_state)
                self.latest_goose.pop(self._last_capture, None)
                self.latest_sv.pop(self._last_capture, None)
            self._last_capture = capture
            key = (capture, int(event["frame_index"]))
            if self.pending_key is not None and key != self.pending_key:
                emitted.extend(self._close_frame())
            self.pending_key = key
            self.pending_rows.append(dict(event))
        return emitted

    def flush(self) -> list[dict]:
        emitted = self._close_frame()
        if self._last_capture is not None:
            emitted.extend(self._flush_capture(self._last_capture))
        self.pending_key = None
        self.pending_rows = []
        self._last_capture = None
        self.states = defaultdict(self._new_state)
        self.latest_goose.clear()
        self.latest_sv.clear()
        return emitted

    def _new_state(self) -> _StreamState:
        return _StreamState(
            intervals=deque(maxlen=int(self.config["timing"]["history_frames"])),
            wave_deltas=deque(maxlen=int(self.config["waveform"]["history_samples"])),
        )

    def _close_frame(self) -> list[dict]:
        if not self.pending_rows:
            return []
        rows = self.pending_rows
        self.pending_rows = []
        first = rows[0]
        protocol = first["protocol"]
        if any(r["protocol"] != protocol for r in rows):
            raise ValueError("one Ethernet frame was decoded as multiple protocols")
        point = self._goose_point(first) if protocol == "GOOSE" else self._sv_point(rows)
        stream = str(first["stream_id"])
        appid = _as_int(first.get("appid"), 0)
        dst = str(first.get("dst_mac", "")).lower()
        stream_key = f"{stream}|appid={appid:04x}|dst={dst}"
        key = (str(first["capture_id"]), protocol, stream_key)
        slot = self.batch_points[key]
        slot.append((point, rows))
        return self._emit_ready(key)

    def _timing(self, state: _StreamState, timestamp: float) -> tuple[float, float, float]:
        if not math.isfinite(timestamp):
            raise ValueError("timestamp must be finite")
        if state.timestamp is not None and timestamp < state.timestamp:
            raise ValueError(f"timestamp regressed from {state.timestamp} to {timestamp}")
        dt = 0.0 if state.timestamp is None else timestamp - state.timestamp
        prior = statistics.median(state.intervals) if state.intervals else 0.0
        ratio = dt / prior if prior > 0 else 1.0
        return dt, ratio, prior

    def _goose_point(self, row: dict) -> dict:
        capture, stream = str(row["capture_id"]), str(row["stream_id"])
        src = str(row.get("src_mac", "")).lower()
        key = (capture, "GOOSE", stream, _as_int(row.get("appid"), 0), str(row.get("dst_mac", "")).lower())
        state = self.states[key]
        ts = float(row["timestamp"])
        dt, ratio, _ = self._timing(state, ts)
        st, sq = _as_int(row.get("st_num")), _as_int(row.get("sq_num"))
        sd = st - state.st_num if st is not None and state.st_num is not None else 0
        qd = sq - state.sq_num if sq is not None and state.sq_num is not None and st == state.st_num else 0
        sv_ts = self.latest_sv.get(capture)
        age_sv = max(0.0, ts - sv_ts) if sv_ts is not None else self.config["timing"]["missing_age_s"]
        feature = {
            "dt": dt, "dt_ratio": ratio,
            "stnum_delta_abs": abs(sd), "stnum_back": int(sd < 0),
            "stnum_jump": int(sd > self.config["counter"]["max_stnum_step"]),
            "sqnum_delta_abs": abs(qd), "sqnum_back": int(qd < 0),
            "publisher_change": int(state.source is not None and src != state.source),
            "history_ready": int(state.timestamp is not None and state.st_num is not None),
            "age_since_any_sv_frame": age_sv,
            "data_boolean_true": int(str(row.get("boolean", "")).strip().lower() in {"true", "1", "yes"}),
            "data_boolean_missing": int(str(row.get("boolean", "")).strip().lower() not in {"true", "1", "yes", "false", "0", "no"}),
            "data_boolean_changed": int(
                state.data_boolean is not None
                and str(row.get("boolean", "")).strip().lower() in {"true", "1", "yes", "false", "0", "no"}
                and state.data_boolean != (str(row.get("boolean", "")).strip().lower() in {"true", "1", "yes"})
            ),
        }
        if state.timestamp is not None and dt > 0:
            state.intervals.append(dt)
        state.timestamp, state.st_num, state.sq_num = ts, st, sq
        state.source = src
        boolean_text = str(row.get("boolean", "")).strip().lower()
        if boolean_text in {"true", "1", "yes", "false", "0", "no"}:
            state.data_boolean = boolean_text in {"true", "1", "yes"}
        self.latest_goose[capture] = ts
        return feature

    def _sv_point(self, rows: list[dict]) -> dict:
        first = rows[0]
        capture, stream = str(first["capture_id"]), str(first["stream_id"])
        src = str(first.get("src_mac", "")).lower()
        timestamp = float(first["timestamp"])
        state = self.states[(capture, "SV", stream, _as_int(first.get("appid"), 0), str(first.get("dst_mac", "")).lower())]
        dt, ratio, _ = self._timing(state, timestamp)
        counter_back = counter_repeat = counter_gap = 0
        delta_abs: list[float] = []
        changes: list[float] = []
        jumps = 0
        plateaus = 0
        value_count = 0
        channel_cfg = self.config["sv_channels"]
        by_channel: list[list[float]] = [[] for _ in channel_cfg["offsets"]]
        history_len = int(self.config["waveform"]["history_samples"])
        for row in rows:
            idx = int(row["asdu_index"])
            counter = _as_int(row.get("smp_cnt"))
            previous_counter = state.counters.get(idx)
            if counter is not None and previous_counter is not None:
                delta = counter - previous_counter
                delta_abs.append(abs(delta))
                counter_back += int(delta < 0)
                counter_repeat += int(delta == 0)
                counter_gap += int(abs(delta) > self.config["counter"]["max_smp_delta"])
            if counter is not None:
                state.counters[idx] = counter
            values = decode_channels(row.get("seq_data", ""), channel_cfg)
            for ch, value in enumerate(values):
                by_channel[ch].append(value)
            if idx not in state.wave_histories:
                state.wave_histories[idx] = [deque(maxlen=history_len) for _ in values]
            channel_histories = state.wave_histories[idx]
            if any(channel_histories):
                for ch, (cur, history) in enumerate(zip(values, channel_histories)):
                    if not history:
                        continue
                    baseline = statistics.median(history)
                    scale = float(channel_cfg["relative_scale"][ch])
                    rel = abs(cur - baseline) / max(abs(baseline), scale, self.config["waveform"]["epsilon"])
                    changes.append(rel)
                    jumps += int(rel >= self.config["waveform"]["relative_jump_limit"])
                    plateaus += int(rel <= self.config["waveform"]["plateau_relative_limit"])
                    value_count += 1
            for history, value in zip(channel_histories, values):
                history.append(value)
        wave_history = list(state.wave_deltas)
        robust_baseline = statistics.median(wave_history) if wave_history else 0.0
        channel_ranges = []
        for ch, values in enumerate(by_channel):
            if values:
                center = abs(statistics.median(values))
                scale = max(center, float(channel_cfg["relative_scale"][ch]), self.config["waveform"]["epsilon"])
                channel_ranges.append((max(values) - min(values)) / scale)
        if changes:
            state.wave_deltas.extend(changes)
        goose_ts = self.latest_goose.get(capture)
        age_goose = max(0.0, timestamp - goose_ts) if goose_ts is not None else self.config["timing"]["missing_age_s"]
        feature = {
            "dt": dt, "dt_ratio": ratio, "age_since_any_goose_frame": age_goose,
            "no_asdu": int(first.get("no_asdu") or 0),
            "smpcnt_back_count": counter_back, "smpcnt_repeat_count": counter_repeat,
            "smpcnt_gap_count": counter_gap,
            "smpcnt_delta_abs_max": max(delta_abs, default=0.0),
            "wave_rel_change_mean": statistics.fmean(changes) if changes else 0.0,
            "wave_rel_change_max": max(changes, default=0.0),
            "wave_jump_fraction": jumps / value_count if value_count else 0.0,
            "wave_plateau_fraction": plateaus / value_count if value_count else 0.0,
            "wave_jump_count": jumps,
            "wave_history_coverage": min(1.0, len(wave_history) / max(1, self.config["waveform"]["history_min_samples"])),
            "wave_change_robust_ratio": min(
                float(self.config["waveform"]["robust_ratio_cap"]),
                max(changes, default=0.0) / max(robust_baseline, self.config["waveform"]["epsilon"]),
            ),
            "wave_channel_range_rel_mean": statistics.fmean(channel_ranges) if channel_ranges else 0.0,
            "wave_channel_range_rel_max": max(channel_ranges, default=0.0),
            "publisher_change": int(state.source is not None and src != state.source),
        }
        if state.timestamp is not None and dt > 0:
            state.intervals.append(dt)
        state.timestamp = timestamp
        state.source = src
        self.latest_sv[capture] = timestamp
        return feature

    def _emit_ready(self, key: tuple) -> list[dict]:
        emitted = []
        size = int(self.config["batch"]["size_frames"])
        stride = int(self.config["batch"]["stride_frames"])
        points = self.batch_points[key]
        while len(points) >= size:
            emitted.append(self._aggregate(key, points[:size]))
            del points[:stride]
        return emitted

    def _aggregate(self, key: tuple, chunk: list[tuple[dict, list[dict]]]) -> dict:
        capture, protocol, stream = key
        names = GOOSE_FRAME_FEATURES if protocol == "GOOSE" else SV_FRAME_FEATURES
        result = {}
        for name in names:
            values = [float(point[name]) for point, _ in chunk]
            result[f"{name}__mean"] = statistics.fmean(values)
            result[f"{name}__max"] = max(values)
            result[f"{name}__last"] = values[-1]
            result[f"{name}__std"] = statistics.pstdev(values) if len(values) > 1 else 0.0
        events = [row for _, rows in chunk for row in rows]
        label, scenario, sources = _label_batch(events)
        sv_shapes = {str(row.get("no_asdu", "")) for row in events if row.get("protocol") == "SV"}
        marker_field = "raw_test" if protocol == "GOOSE" else "raw_simulated"
        marker_positive = any(str(row.get(marker_field, "")).strip().lower() in {"true", "1", "yes"} for row in events)
        attack_times = [float(row["timestamp"]) for row in events if str(row.get("attack", "")).strip() == "1"]
        result.update({
            "protocol": protocol, "capture_id": capture, "stream_id": stream,
            "batch_frames": len(chunk), "start_frame": int(chunk[0][1][0]["frame_index"]),
            "end_frame": int(chunk[-1][1][0]["frame_index"]),
            "timestamp_start": float(chunk[0][1][0]["timestamp"]),
            "timestamp_end": float(chunk[-1][1][0]["timestamp"]),
            "attack": label, "scenario_id": scenario, "label_source": sources,
            "asdu_shape": next(iter(sv_shapes)) if len(sv_shapes) == 1 else ("mixed" if sv_shapes else ""),
            "marker_positive_audit": int(marker_positive),
            "first_attack_timestamp": min(attack_times) if attack_times else "",
        })
        return result

    def _flush_capture(self, capture: str) -> list[dict]:
        output = []
        for key, points in list(self.batch_points.items()):
            if key[0] != capture:
                continue
            if points and self.config["batch"].get("emit_partial", True):
                output.append(self._aggregate(key, points))
            del self.batch_points[key]
        return output


def build_batches(events: list[dict], config: dict, *, chunk_size: int | None = None) -> list[dict]:
    """Batch helper; ``chunk_size`` exercises streaming/chunk parity."""
    builder = StatefulBatchFeatureBuilder(config)
    output = []
    step = chunk_size or len(events) or 1
    for start in range(0, len(events), step):
        output.extend(builder.update(events[start:start + step]))
    output.extend(builder.flush())
    return output


def feature_names(protocol: str) -> tuple[str, ...]:
    base = GOOSE_FRAME_FEATURES if protocol == "GOOSE" else SV_FRAME_FEATURES
    return tuple(f"{name}__{agg}" for name in base for agg in ("mean", "max", "last", "std"))
