"""Targeted checks for label provenance and causal event features."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from generate_offline_scenarios import generate
from monitor_features import compute_features
from prepare_notebook_events import convert


def goose(capture: str, timestamp: float, st: int, sq: int, attack: int = 0) -> dict:
    return {
        "capture_id": capture, "scenario_id": capture, "protocol": "GOOSE",
        "timestamp": str(timestamp), "src_mac": "aa", "expected_src_mac": "aa",
        "stream_id": "g1", "bus_id": "", "st_num": str(st), "sq_num": str(sq),
        "smp_cnt": "", "no_asdu": "", "trip_asserted": "", "sv_fault": "",
        "attack": str(attack), "label_source": "manual_review",
    }


class MonitorPipelineTests(unittest.TestCase):
    def test_first_packet_has_no_cross_capture_history(self) -> None:
        records = compute_features([
            goose("first", 1, 10, 1), goose("first", 2, 10, 2),
            goose("second", 10, 10, 1),
        ])
        self.assertEqual(records[0]["history_ready"], 0)
        self.assertEqual(records[1]["dt"], 1)
        self.assertEqual(records[2]["history_ready"], 0)
        self.assertEqual(records[2]["dt"], 0)

    def test_counter_regression_does_not_poison_baseline(self) -> None:
        records = compute_features([
            goose("a", 1, 10, 10),
            goose("a", 2, 9, 3, 1),
            goose("a", 3, 10, 11),
        ])
        self.assertEqual(records[1]["stnum_decrease"], 1)
        self.assertEqual(records[2]["stnum_delta"], 0)
        self.assertEqual(records[2]["sqnum_delta"], 1)

    def test_reviewed_restart_resets_counter_history(self) -> None:
        restarted = goose("a", 2, 1, 1)
        restarted["restart_authorized"] = "1"
        records = compute_features([goose("a", 1, 10, 10), restarted, goose("a", 3, 1, 2)])
        self.assertEqual(records[1]["stnum_decrease"], 0)
        self.assertEqual(records[1]["history_ready"], 0)
        self.assertEqual(records[2]["sqnum_delta"], 1)

    def test_sv_agreement_requires_fresh_mapped_stream(self) -> None:
        sv = goose("a", 1.0, 0, 0)
        sv.update({
            "protocol": "SV", "stream_id": "mu1", "src_mac": "bb",
            "expected_src_mac": "bb", "smp_cnt": "1", "no_asdu": "1",
            "sv_fault": "0",
        })
        recent = goose("a", 1.2, 10, 1)
        recent.update({"trip_asserted": "1", "sv_reference_stream": "mu1"})
        stale = goose("a", 2.0, 10, 2)
        stale.update({"trip_asserted": "1", "sv_reference_stream": "mu1"})
        records = compute_features([sv, recent, stale])
        self.assertEqual(records[1]["sv_disagreement"], 1)
        self.assertEqual(records[2]["sv_disagreement"], 0)

    def test_sv_wrap_uses_configured_modulus(self) -> None:
        first = goose("a", 1, 0, 0)
        second = goose("a", 2, 0, 0)
        for row, count in ((first, 65535), (second, 0)):
            row.update({
                "protocol": "SV", "stream_id": "mu1", "src_mac": "bb",
                "expected_src_mac": "bb", "smp_cnt": str(count),
                "smpcnt_modulus": "65536", "no_asdu": "1",
            })
        records = compute_features([first, second])
        self.assertEqual(records[1]["smpcnt_delta"], 1)
        self.assertEqual(records[1]["smpcnt_back"], 0)

    def test_notebook_test_bit_cannot_set_label(self) -> None:
        raw = [{
            "source_pcap": "capture1.pcapng", "timestamp": "1.0", "src_mac": "aa",
            "goCbRef": "g1", "stNum": "1", "sqNum": "1", "boolean": "True",
            "test": "True", "Attack": "1",
        }]
        manifest = {"captures": {"capture1.pcapng": {
            "default_attack": 0, "label_source": "operator_log",
        }}, "overrides": []}
        topology = {"GOOSE": {"g1": {"expected_src_mac": "aa", "bus_id": "bus1"}}}
        result = convert(raw, [], manifest, topology, "0")
        self.assertEqual(result[0]["attack"], "0")
        manifest["overrides"] = [{
            "capture_id": "capture1.pcapng", "protocol": "GOOSE",
            "source_row": 0, "attack": 1, "label_source": "packet_review",
        }]
        self.assertEqual(convert(raw, [], manifest, topology, "0")[0]["attack"], "1")

    def test_offline_generator_has_distinct_attack_modes(self) -> None:
        rows = generate(cycles=100)
        modes = {row["scenario_id"] for row in rows if row["attack"] == "1"}
        self.assertIn("goose_replay", modes)
        self.assertIn("goose_false_trip", modes)
        self.assertIn("sv_replay", modes)


if __name__ == "__main__":
    unittest.main()
