"""Apply explicit, capture-specific provisional labels to the supplied lab PCAPs.

These are weak labels grounded in lab scenario provenance and packet markers,
not independently verified ground truth. In particular, IEC GOOSE ``test`` and
SV ``simulated`` are sender-controlled protocol bits. They are evidence only in
the named scenario captures and must not be exported as model features.
"""

from __future__ import annotations

from pathlib import Path


TRAIN_CAPTURES = frozenset({
    "baseline_new.pcapng",
    "goosedelta500.pcapng",
    "gooseSVcorrmismatch.pcapng",
    "pureSV.pcapng",
    "svspoof.pcapng",
    "traininglegitfault.pcapng",
    "tripspoof.pcapng",
})
TEST_CAPTURE = "test.pcapng"

# Every capture uses both protocol markers. Scenario names come from capture
# provenance; the user's lab convention authorizes the marker bit as its attack
# label across this supplied dataset. These sender-controlled bits are weak
# evidence outside this lab and never model inputs.
_MARKERS = {"GOOSE": "raw_test", "SV": "raw_simulated"}
LAB_LABEL_CONFIG = {
    "baseline_new.pcapng": {
        "scenario": "baseline_benign",
        "markers": dict(_MARKERS),
    },
    "traininglegitfault.pcapng": {
        "scenario": "legitimate_fault_benign",
        "markers": dict(_MARKERS),
    },
    "goosedelta500.pcapng": {
        "scenario": "goose_delta_500",
        "markers": dict(_MARKERS),
    },
    "gooseSVcorrmismatch.pcapng": {
        "scenario": "goose_sv_correlation_mismatch",
        "markers": dict(_MARKERS),
    },
    "pureSV.pcapng": {
        "scenario": "pure_sv_attack",
        "markers": dict(_MARKERS),
    },
    "svspoof.pcapng": {
        "scenario": "sv_spoof",
        "markers": dict(_MARKERS),
    },
    "tripspoof.pcapng": {
        "scenario": "trip_spoof",
        "markers": dict(_MARKERS),
    },
    TEST_CAPTURE: {
        "scenario": "heldout_lab_test",
        "markers": dict(_MARKERS),
    },
}


def _marker(value: object) -> bool | None:
    """Parse a decoded marker, preserving missing/unknown as None.

    GOOSE BOOLEAN may be represented as 255/1/true; SV simulation is a bit.
    This parser intentionally rejects arbitrary values instead of defaulting
    them to benign.
    """
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "255", "0xff"}:
        return True
    if text in {"0", "false", "no", "0x00"}:
        return False
    raise ValueError(f"unrecognized marker value {value!r}")


def _sv_s_bit(value: object) -> bool | None:
    """Decode the S bit from SV Reserved1, never treating other bits as S."""
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip().lower()
    if text in {"true", "yes"}:
        return True
    if text in {"false", "no"}:
        return False
    try:
        raw = int(text, 0)
    except ValueError as exc:
        try:
            raw = int(text, 16)
        except ValueError:
            raise ValueError(f"unrecognized SV Reserved1 value {value!r}") from exc
    if not 0 <= raw <= 0xffff:
        raise ValueError(f"SV Reserved1 is outside 16-bit range: {value!r}")
    return bool(raw & 0x8000)


def _capture(row: dict) -> str:
    source = str(row.get("source_pcap", "")).strip()
    capture_id = str(row.get("capture_id", "")).strip()
    if not source and capture_id:
        source = Path(capture_id).name
    if not capture_id and source:
        capture_id = source
    if source and Path(source).name != source:
        source = Path(source).name
    if capture_id and Path(capture_id).name != capture_id:
        capture_id = Path(capture_id).name
    if source and capture_id and source != capture_id:
        raise ValueError(f"capture_id/source_pcap disagree: {capture_id!r} vs {source!r}")
    return source or capture_id


def label_events(
    events: list[dict], split: str,
    config: dict[str, dict] | None = None,
    expected_training_captures: set[str] | list[str] | None = None,
    test_capture: str | None = None,
) -> list[dict]:
    """Return one labelled copy per decoded event for ``train`` or ``test``.

    Training requires all seven named captures in one call so it is auditable
    that every supplied training PCAP contributes. Test accepts only
    ``test.pcapng``. Labels use the lab's GOOSE test and SV S-bit markers as
    authorized weak supervision. Marker fields remain audit-only and must not
    be model features. Unmarked rows map to benign under this lab policy; an
    attack with an unset marker is a known label-noise risk.
    """
    if split not in {"train", "test"}:
        raise ValueError("split must be 'train' or 'test'")
    if not events:
        raise ValueError("no events supplied")

    label_config = LAB_LABEL_CONFIG if config is None else config
    train_names = frozenset(
        Path(name).name for name in
        (TRAIN_CAPTURES if expected_training_captures is None else expected_training_captures)
    )
    test_name = Path(test_capture or TEST_CAPTURE).name
    expected = train_names if split == "train" else frozenset({test_name})
    result: list[dict] = []
    seen: set[str] = set()

    for index, original in enumerate(events):
        row = dict(original)
        capture = _capture(row)
        if capture not in expected:
            raise ValueError(f"{split} split contains unexpected capture {capture!r}")
        protocol = str(row.get("protocol", "")).strip()
        if protocol not in {"GOOSE", "SV"}:
            raise ValueError(f"event {index} has unsupported protocol {protocol!r}")
        if not str(row.get("stream_id", "")).strip():
            raise ValueError(f"event {index} in {capture} has no stream_id")

        seen.add(capture)
        if capture not in label_config:
            raise ValueError(f"label config has no entry for capture {capture!r}")
        cfg = label_config[capture]
        scenario = cfg["scenario"]
        marker_field = cfg["markers"].get(protocol)
        marker_value = None
        if marker_field:
            marker_value = (
                _sv_s_bit(row.get(marker_field)) if protocol == "SV"
                else _marker(row.get(marker_field))
            )
            if marker_value is None:
                raise ValueError(
                    f"event {index} in {capture} is missing configured marker {marker_field!r}"
                )

        if marker_value is True:
            attack = "1"
            label_source = f"lab_scenario_plus_{marker_field}_weak"
        else:
            attack = "0"
            if marker_field:
                label_source = f"lab_scenario_unmarked_assumed_benign_{marker_field}"
            else:
                label_source = "capture_provenance_benign"

        row.update({
            "capture_id": capture,
            "source_pcap": capture,
            "scenario_id": scenario,
            "attack": attack,
            "label_source": label_source,
            "expected_src_mac": "",  # No independent topology file is supplied.
            "expected_conf_rev": "",
            "expected_appid": "",
            "sv_reference_stream": "",
            "bus_id": "",
            "restart_authorized": "",
            "trip_asserted": "",
            "sv_fault": "",
        })
        result.append(row)

    missing = expected - seen
    if missing:
        raise ValueError(f"{split} split is missing required capture(s): {sorted(missing)}")
    if split == "train" and seen != train_names:
        raise ValueError("training split must contain every supplied training capture")
    return result
