"""Find deterministic feature vectors that exercise both binary labels.

These are firmware self-test vectors, not examples of semantically valid
network traffic. Model files contain decision boundaries but not the original
feature-engineering pipeline or training rows.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "firmware" / "generated" / "example_vectors.json"
RNG = np.random.default_rng(20260912)


def threshold_candidates(model, feature_count: int) -> list[np.ndarray]:
    pools: list[list[float]] = [[] for _ in range(feature_count)]
    if hasattr(model, "estimators_"):
        for estimator in model.estimators_:
            tree = estimator.tree_
            for feature, threshold in zip(tree.feature, tree.threshold, strict=True):
                if feature >= 0:
                    value = np.float32(threshold)
                    pools[int(feature)].extend(
                        [
                            float(value),
                            float(np.nextafter(value, np.float32(-np.inf))),
                            float(np.nextafter(value, np.float32(np.inf))),
                        ]
                    )
    else:
        raw = json.loads(model.get_booster().save_raw(raw_format="json"))
        trees = raw["learner"]["gradient_booster"]["model"]["trees"]
        for tree in trees:
            for left, feature, threshold in zip(
                tree["left_children"], tree["split_indices"], tree["split_conditions"], strict=True
            ):
                if int(left) >= 0:
                    value = np.float32(threshold)
                    pools[int(feature)].extend(
                        [
                            float(value),
                            float(np.nextafter(value, np.float32(-np.inf))),
                            float(np.nextafter(value, np.float32(np.inf))),
                        ]
                    )
    return [np.unique(np.asarray([0.0, 1.0, *values], dtype=np.float32)) for values in pools]


def sample_rows(pools: list[np.ndarray], count: int) -> np.ndarray:
    rows = np.empty((count, len(pools)), dtype=np.float32)
    for feature, pool in enumerate(pools):
        rows[:, feature] = RNG.choice(pool, count)
    return rows


def sample_sv_rows(pools: list[np.ndarray], count: int) -> np.ndarray:
    rows = sample_rows(pools, count)
    # Keep the counter-derived inputs internally plausible. The exact rolling
    # feature definitions still require the original feature-engineering code.
    rows[:, 0] = np.rint(rows[:, 0])
    rows[:, 1] = np.abs(rows[:, 0])
    rows[:, 2] = (rows[:, 0] < 0).astype(np.float32)
    rows[:, 7] = np.clip(np.rint(rows[:, 7]), 0, None)
    return rows


def best_examples(models: list, rows: np.ndarray) -> dict:
    probabilities = [np.asarray(model.predict_proba(rows)[:, 1], dtype=np.float32) for model in models]
    combined = np.stack(probabilities, axis=1)
    class_1_score = combined.min(axis=1)
    class_2_score = combined.max(axis=1)
    class_1_index = int(np.argmax(class_1_score))
    class_2_index = int(np.argmin(class_2_score))
    return {
        "class_1": {
            "original_label": 1,
            "features": [float(value) for value in rows[class_1_index]],
            "probabilities": [float(values[class_1_index]) for values in probabilities],
        },
        "class_2": {
            "original_label": 0,
            "features": [float(value) for value in rows[class_2_index]],
            "probabilities": [float(values[class_2_index]) for values in probabilities],
        },
    }


def main() -> None:
    rf_sv = joblib.load(ROOT / "rf_sv_stream_detector.joblib")
    xgb_sv = joblib.load(ROOT / "xgb_sv_stream_detector.joblib")
    xgb_goose = joblib.load(ROOT / "xgb_goose_detector.joblib")

    rf_pools = threshold_candidates(rf_sv, 8)
    xgb_pools = threshold_candidates(xgb_sv, 8)
    combined_pools = [np.unique(np.concatenate([rf_pool, xgb_pool])) for rf_pool, xgb_pool in zip(rf_pools, xgb_pools, strict=True)]
    sv_rows = sample_sv_rows(combined_pools, 200_000)
    goose_rows = sample_rows(threshold_candidates(xgb_goose, 6), 100_000)
    goose_rows[:, 5] = RNG.integers(0, 2, size=goose_rows.shape[0])

    output = {
        "mapping": {
            "class_1": "original model label 1; LED on",
            "class_2": "original model label 0; LED off",
        },
        "warning": (
            "Synthetic boundary-based firmware test vectors only. They do not establish "
            "whether either label means attack, anomaly, or normal traffic."
        ),
        "sv": {
            "feature_names": [str(value) for value in rf_sv.feature_names_in_],
            "models": ["rf_sv", "xgb_sv"],
            **best_examples([rf_sv, xgb_sv], sv_rows),
        },
        "goose": {
            "feature_names": list(xgb_goose.get_booster().feature_names),
            "models": ["xgb_goose"],
            **best_examples([xgb_goose], goose_rows),
        },
    }
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
