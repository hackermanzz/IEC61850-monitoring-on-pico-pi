"""Train capture-held-out IEC 61850 research detectors from labelled event CSV.

No label is inferred from the GOOSE test bit or SV simulation bit. Each row
must carry its own independently assigned attack label and provenance.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut

from monitor_features import GOOSE_FEATURES, SV_FEATURES, compute_features, read_events


def classifier() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_leaf=5,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )


def weights_for_captures(captures: list[str]) -> np.ndarray:
    counts = Counter(captures)
    return np.asarray([1.0 / counts[capture] for capture in captures], dtype=float)


def metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": tp / (tp + fn) if tp + fn else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def fpr_threshold(y: np.ndarray, probabilities: np.ndarray, limit: float) -> float:
    negatives = np.sort(probabilities[y == 0])[::-1]
    if len(negatives) == 0:
        raise ValueError("threshold selection needs legitimate validation rows")
    allowed_fp = math.floor(limit * len(negatives))
    if allowed_fp >= len(negatives):
        return 0.0
    return float(np.nextafter(negatives[allowed_fp], 1.0))


def fit_one(records: list[dict], protocol: str, test_capture: str, max_fpr: float) -> tuple[dict, object]:
    features = GOOSE_FEATURES if protocol == "GOOSE" else SV_FEATURES
    selected = [row for row in records if row["protocol"] == protocol]
    if not selected:
        raise ValueError(f"no {protocol} rows")
    train = [row for row in selected if row["capture_id"] != test_capture]
    test = [row for row in selected if row["capture_id"] == test_capture]
    if not test:
        raise ValueError(f"test capture {test_capture!r} has no {protocol} rows")
    groups = np.asarray([row["capture_id"] for row in train])
    if len(set(groups)) < 3:
        raise ValueError(f"{protocol} needs at least three non-test captures for grouped validation")
    x = np.asarray([[float(row[name]) for name in features] for row in train], dtype=float)
    y = np.asarray([row["attack"] for row in train], dtype=int)
    x_test = np.asarray([[float(row[name]) for name in features] for row in test], dtype=float)
    y_test = np.asarray([row["attack"] for row in test], dtype=int)
    if len(np.unique(y)) != 2:
        raise ValueError(f"{protocol} training captures must contain both classes")

    # All threshold tuning uses out-of-fold predictions from entire held-out captures.
    oof = np.full(len(train), np.nan, dtype=float)
    for train_index, valid_index in LeaveOneGroupOut().split(x, y, groups):
        if len(np.unique(y[train_index])) != 2:
            raise ValueError(f"{protocol} fold has only one class after holding out a capture")
        model = classifier()
        fold_groups = groups[train_index].tolist()
        model.fit(x[train_index], y[train_index], sample_weight=weights_for_captures(fold_groups))
        oof[valid_index] = model.predict_proba(x[valid_index])[:, 1]
    if not np.isfinite(oof).all():
        raise RuntimeError("incomplete out-of-fold predictions")
    threshold = fpr_threshold(y, oof, max_fpr)
    fold_reports = []
    for capture in sorted(set(groups.tolist())):
        mask = groups == capture
        fold_reports.append({
            "capture_id": capture,
            "support": int(mask.sum()),
            "metrics": metrics(y[mask], (oof[mask] >= threshold).astype(int)),
        })
    final_model = classifier()
    final_model.fit(x, y, sample_weight=weights_for_captures(groups.tolist()))

    probability = final_model.predict_proba(x_test)[:, 1]
    ml_pred = (probability >= threshold).astype(int)
    # A configured publisher mismatch is a separate, auditable identity rule.
    rule_pred = np.asarray([int(row["publisher_mismatch"]) for row in test], dtype=int)
    final_pred = np.maximum(rule_pred, ml_pred)
    report = {
        "protocol": protocol,
        "test_capture": test_capture,
        "feature_names": list(features),
        "threshold": threshold,
        "max_validation_fpr": max_fpr,
        "train_captures": sorted(set(groups.tolist())),
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
        "train_label_sources": dict(Counter(row["label_source"] for row in train)),
        "test_label_sources": dict(Counter(row["label_source"] for row in test)),
        "validation_folds": fold_reports,
        "validation_ml": metrics(y, (oof >= threshold).astype(int)),
        "test_ml": metrics(y_test, ml_pred),
        "test_publisher_rule": metrics(y_test, rule_pred),
        "test_combined": metrics(y_test, final_pred),
        "feature_importance_impurity": dict(zip(features, map(float, final_model.feature_importances_))),
    }
    return report, final_model


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--test-capture", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-validation-fpr", type=float, default=0.01)
    parser.add_argument("--max-stnum-step", type=int, default=20)
    parser.add_argument("--max-smp-delta", type=int, default=100)
    parser.add_argument("--sv-agreement-window", type=float, default=0.5)
    args = parser.parse_args()
    if not 0 < args.max_validation_fpr < 1:
        parser.error("--max-validation-fpr must be between 0 and 1")
    events = read_events(args.events)
    if args.test_capture not in {row["capture_id"] for row in events}:
        parser.error("--test-capture is not in the event file")
    feature_config = {
        "max_stnum_step": args.max_stnum_step,
        "max_smp_delta": args.max_smp_delta,
        "sv_agreement_window": args.sv_agreement_window,
    }
    features = compute_features(events, **feature_config)
    results = [fit_one(features, protocol, args.test_capture, args.max_validation_fpr)
               for protocol in ("GOOSE", "SV")]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for report, model in results:
        protocol = report["protocol"].lower()
        joblib.dump(model, args.output_dir / f"rf_{protocol}_research.joblib")
        print(f"{protocol.upper()} held-out {args.test_capture}: {json.dumps(report['test_combined'])}")
    summary = {
        "status": "research_only_requires_field_validation",
        "event_source": str(args.events),
        "feature_config": feature_config,
        "reports": [report for report, _ in results],
    }
    (args.output_dir / "evaluation.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote research models and evaluation to {args.output_dir}")


if __name__ == "__main__":
    main()
