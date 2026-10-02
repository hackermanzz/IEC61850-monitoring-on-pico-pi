from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from lab_capture_labels import LAB_LABEL_CONFIG, TEST_CAPTURE, TRAIN_CAPTURES, label_events


def event(capture: str, protocol: str, **values: object) -> dict:
    row = {
        "capture_id": capture,
        "source_pcap": capture,
        "protocol": protocol,
        "stream_id": "GCB1" if protocol == "GOOSE" else "MU1",
        "timestamp": "1.0",
        "src_mac": "02:00:00:00:00:01",
        "no_asdu": "14",
        "raw_test": "false",
        "raw_simulated": "0x0000",
    }
    row.update({key: str(value) for key, value in values.items()})
    return row


class LabCaptureLabelTests(unittest.TestCase):
    def test_all_seven_training_captures_are_required_and_contribute(self) -> None:
        rows = []
        for capture in sorted(TRAIN_CAPTURES):
            protocol = "SV" if capture in {"pureSV.pcapng", "svspoof.pcapng"} else "GOOSE"
            rows.append(event(capture, protocol))
        labeled = label_events(rows, "train")
        self.assertEqual(len(labeled), 7)
        self.assertEqual({row["capture_id"] for row in labeled}, TRAIN_CAPTURES)
        self.assertTrue(all(row["attack"] in {"0", "1"} for row in labeled))

        with self.assertRaisesRegex(ValueError, "missing required capture"):
            label_events(rows[:-1], "train")

    def test_training_marker_fields_are_weak_attack_evidence(self) -> None:
        rows = [
            event("goosedelta500.pcapng", "GOOSE", raw_test="255"),
            event("goosedelta500.pcapng", "GOOSE", raw_test="0"),
            event("pureSV.pcapng", "SV", raw_simulated="0x8000"),
            event("pureSV.pcapng", "SV", raw_simulated="0x0800"),
            event("svspoof.pcapng", "GOOSE", raw_test="true"),
        ]
        # Include benign rows from every remaining training capture.
        rows.extend(
            event(capture, "GOOSE")
            for capture in TRAIN_CAPTURES - {"goosedelta500.pcapng", "pureSV.pcapng"}
        )
        labeled = label_events(rows, "train")
        self.assertEqual([r["attack"] for r in labeled[:5]], ["1", "0", "1", "0", "1"])
        self.assertIn("raw_test_weak", labeled[0]["label_source"])
        self.assertIn("raw_simulated_weak", labeled[2]["label_source"])
        self.assertEqual(labeled[0]["raw_test"], "255")

    def test_goose_sv_correlation_capture_labels_sv_from_s_bit(self) -> None:
        rows = [
            event("gooseSVcorrmismatch.pcapng", "GOOSE", raw_test="1"),
            event("gooseSVcorrmismatch.pcapng", "SV", raw_simulated="0x8000"),
            event("gooseSVcorrmismatch.pcapng", "SV", raw_simulated="0x0000"),
        ]
        rows.extend(
            event(capture, "GOOSE")
            for capture in TRAIN_CAPTURES - {"gooseSVcorrmismatch.pcapng"}
        )
        labeled = label_events(rows, "train")
        self.assertEqual([r["attack"] for r in labeled[:3]], ["1", "1", "0"])

    def test_test_capture_uses_only_markers_and_ignores_shape(self) -> None:
        rows = [
            event(TEST_CAPTURE, "GOOSE", raw_test="255"),
            event(TEST_CAPTURE, "GOOSE", raw_test="0"),
            event(TEST_CAPTURE, "SV", raw_simulated="0x8000", no_asdu="1"),
            event(TEST_CAPTURE, "SV", raw_simulated="0x0800", no_asdu="14"),
        ]
        labeled = label_events(rows, "test")
        self.assertEqual([row["attack"] for row in labeled], ["1", "0", "1", "0"])
        self.assertTrue(all(row["scenario_id"] == "heldout_lab_test" for row in labeled))

    def test_editable_config_is_applied_and_must_cover_every_capture(self) -> None:
        config = {name: {**entry, "markers": dict(entry["markers"])} for name, entry in LAB_LABEL_CONFIG.items()}
        config["goosedelta500.pcapng"]["scenario"] = "edited_delta_scenario"
        rows = [event(capture, "GOOSE") for capture in TRAIN_CAPTURES]
        labeled = label_events(rows, "train", config=config)
        self.assertEqual(
            next(row["scenario_id"] for row in labeled if row["capture_id"] == "goosedelta500.pcapng"),
            "edited_delta_scenario",
        )
        del config["baseline_new.pcapng"]
        with self.assertRaisesRegex(ValueError, "no entry for capture"):
            label_events(rows, "train", config=config)

        selector_config = {
            name: {**entry, "markers": dict(entry["markers"])}
            for name, entry in LAB_LABEL_CONFIG.items()
        }
        selector_config[TEST_CAPTURE]["markers"] = {"SV": "raw_test"}
        row = event(TEST_CAPTURE, "SV", raw_test="false", raw_simulated="0x8000")
        self.assertEqual(label_events([row], "test", config=selector_config)[0]["attack"], "0")

    def test_capture_paths_are_editable_and_coverage_remains_strict(self) -> None:
        custom_train = "added_training.pcapng"
        custom_test = "site_test.pcapng"
        config = {name: dict(entry) for name, entry in LAB_LABEL_CONFIG.items()}
        config[custom_train] = {"scenario": "new_lab_train", "markers": {"GOOSE": "raw_test", "SV": "raw_simulated"}}
        config[custom_test] = {"scenario": "new_lab_test", "markers": {"GOOSE": "raw_test", "SV": "raw_simulated"}}
        train_rows = [event(custom_train, "GOOSE")]
        test_rows = [event(custom_test, "SV")]
        self.assertEqual(
            label_events(train_rows, "train", config, expected_training_captures={custom_train})[0]["scenario_id"],
            "new_lab_train",
        )
        self.assertEqual(
            label_events(test_rows, "test", config, test_capture=custom_test)[0]["scenario_id"],
            "new_lab_test",
        )

    def test_rejects_unknown_markers_split_and_cross_split_captures(self) -> None:
        with self.assertRaisesRegex(ValueError, "unrecognized marker"):
            label_events(
                [event("test.pcapng", "GOOSE", raw_test="maybe")], "test"
            )
        with self.assertRaisesRegex(ValueError, "split must"):
            label_events([event("test.pcapng", "GOOSE")], "validation")
        with self.assertRaisesRegex(ValueError, "unexpected capture"):
            label_events([event("test.pcapng", "GOOSE")], "train")
        with self.assertRaisesRegex(ValueError, "SV Reserved1"):
            label_events([event("test.pcapng", "SV", raw_simulated="0x10000")], "test")
        with self.assertRaisesRegex(ValueError, "missing configured marker"):
            label_events([event("test.pcapng", "SV", raw_simulated="")], "test")


if __name__ == "__main__":
    unittest.main()
