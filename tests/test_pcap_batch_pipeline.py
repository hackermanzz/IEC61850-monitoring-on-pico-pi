from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from batch_pipeline import StatefulBatchFeatureBuilder, build_batches
from pcap_events import _blocks, _ethernet, decode_ethernet_frame, decode_pcapng


def config(*, batch_size=1, stride=1):
    return {
        "batch": {"size_frames": batch_size, "stride_frames": stride, "emit_partial": False},
        "sv_channels": {
            "offsets": [0, 4, 8, 12, 16, 20], "format": ">f",
            "relative_scale": [1.0] * 6,
        },
        "waveform": {
            "epsilon": 1e-6, "relative_jump_limit": 0.05,
            "plateau_relative_limit": 1e-6, "history_min_samples": 2,
            "history_samples": 8, "robust_ratio_cap": 100.0,
        },
        "counter": {"max_smp_delta": 100, "max_stnum_step": 20},
        "timing": {"missing_age_s": 10.0, "history_frames": 8},
    }


def sv_event(frame, timestamp, value, *, counter=None, capture="fixture.pcapng", asdu=0):
    data = b"".join(struct.pack(">f", value) for _ in range(6)) + b"\x00" * 8
    return {
        "capture_id": capture, "source_pcap": capture, "frame_index": frame,
        "asdu_index": asdu, "timestamp": timestamp, "protocol": "SV",
        "src_mac": "00:11:22:33:44:55", "dst_mac": "01:0c:cd:01:00:01",
        "stream_id": "sv_stream", "appid": 0x4000, "no_asdu": 1,
        "smp_cnt": counter if counter is not None else frame,
        "seq_data": data.hex(), "raw_simulated": "False", "attack": "0",
        "scenario_id": "benign", "label_source": "test_fixture",
    }


def _check_decode_all_asdus_and_unsigned_smpcnt():
    source = ROOT / "Training Dataset" / "traininglegitfault.pcapng"
    events, diagnostics = decode_pcapng(source)
    assert diagnostics["malformed_iec_frames"] == []
    sv_rows = [row for row in events if row["protocol"] == "SV"]
    grouped = {}
    for row in sv_rows:
        grouped.setdefault(row["frame_index"], []).append(row)
    fourteen = next(rows for rows in grouped.values() if len(rows) == 14)
    assert [row["asdu_index"] for row in fourteen] == list(range(14))
    assert all(len(bytes.fromhex(row["seq_data"])) == 32 for row in fourteen)
    assert max(int(row["smp_cnt"]) for row in sv_rows) > 32767


def _check_sv_sbit_is_distinct_from_other_reserved1_bits():
    source = ROOT / "Training Dataset" / "baseline_new.pcapng"
    packet = next(
        packet for linktype, packet, _timestamp in _blocks(source)
        if linktype == 1 and _ethernet(packet)[2] == 0x88BA
    )
    for reserved, expected in ((0x8000, "True"), (0x0800, "False")):
        changed = bytearray(packet)
        vlan_offset = 4 if packet[12:14] in {b"\x81\x00", b"\x88\xa8", b"\x91\x00"} else 0
        reserved_offset = 14 + vlan_offset + 4
        changed[reserved_offset:reserved_offset + 2] = reserved.to_bytes(2, "big")
        decoded, error = decode_ethernet_frame(bytes(changed), 1.0, "fixture.pcapng", 1)
        assert error is None
        assert decoded and all(row["raw_simulated"] == expected for row in decoded)


def _check_waveform_continuity_recovers_after_one_extreme_sample():
    rows = [sv_event(i, float(i), value) for i, value in enumerate((100.0, 100.0, 10000.0, 100.0, 100.0))]
    batches = build_batches(rows, config())
    assert batches[2]["wave_rel_change_max__max"] > 0.05
    assert batches[3]["wave_rel_change_max__max"] < 1e-6
    assert batches[3]["wave_jump_fraction__max"] == 0


def _check_benign_interleaved_counter_regressions_are_features_not_labels():
    counters = (30541, 41450, 30542, 41451, 30543, 41452)
    rows = [sv_event(i, i * 0.53, 100.0, counter=value) for i, value in enumerate(counters)]
    batches = build_batches(rows, config())
    assert [row["attack"] for row in batches] == [0] * len(counters)
    assert sum(row["smpcnt_back_count__max"] for row in batches) == 2


def _check_chunk_parity_and_capture_state_reset():
    cfg = config(batch_size=2, stride=1)
    first = [sv_event(i, float(i), 100.0 + i, capture="one.pcapng") for i in range(8)]
    second = [sv_event(i, float(i), 500.0 + i, capture="two.pcapng") for i in range(8)]
    rows = first + second
    all_at_once = build_batches(rows, cfg)
    chunked = build_batches(rows, cfg, chunk_size=3)
    independent = build_batches(first, cfg) + build_batches(second, cfg)
    assert all_at_once == chunked == independent
    second_capture = [row for row in all_at_once if row["capture_id"] == "two.pcapng"]
    assert second_capture[0]["wave_history_coverage__max"] == 0


def _check_timestamp_regression_fails_loudly():
    rows = [sv_event(0, 2.0, 1.0), sv_event(1, 1.0, 2.0)]
    builder = StatefulBatchFeatureBuilder(config())
    builder.update(rows)
    try:
        builder.flush()
    except ValueError as error:
        assert "timestamp regressed" in str(error)
    else:
        raise AssertionError("timestamp regression was not rejected")


def _check_live_frame_decoder_matches_pcap_loader():
    source = ROOT / "Training Dataset" / "baseline_new.pcapng"
    events, diagnostics = decode_pcapng(source)
    decoded_direct = []
    for frame_index, (linktype, packet, timestamp) in enumerate(_blocks(source)):
        if linktype != 1:
            continue
        rows, error = decode_ethernet_frame(packet, timestamp, source.name, frame_index)
        assert error is None
        decoded_direct.extend(rows)
    assert decoded_direct == events
    assert diagnostics["malformed_iec_frames"] == []


class PcapBatchPipelineTests(unittest.TestCase):
    def test_decode_all_asdus_and_unsigned_smpcnt(self):
        _check_decode_all_asdus_and_unsigned_smpcnt()

    def test_sv_sbit_is_distinct_from_other_reserved1_bits(self):
        _check_sv_sbit_is_distinct_from_other_reserved1_bits()

    def test_waveform_continuity_recovers_after_one_extreme_sample(self):
        _check_waveform_continuity_recovers_after_one_extreme_sample()

    def test_benign_interleaved_counter_regressions_are_features_not_labels(self):
        _check_benign_interleaved_counter_regressions_are_features_not_labels()

    def test_chunk_parity_and_capture_state_reset(self):
        _check_chunk_parity_and_capture_state_reset()

    def test_timestamp_regression_fails_loudly(self):
        _check_timestamp_regression_fails_loudly()

    def test_live_frame_decoder_matches_pcap_loader(self):
        _check_live_frame_decoder_matches_pcap_loader()
