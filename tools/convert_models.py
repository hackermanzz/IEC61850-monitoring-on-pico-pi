"""Convert the three trusted joblib classifiers into RP2040-friendly C++ data.

The generated representation is flash-resident, has no dynamic allocation, and
requires only a few bytes of working RAM during prediction.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "firmware" / "generated"

FLAG_LEAF = 0x01
FLAG_MISSING_RIGHT = 0x02


@dataclass(frozen=True)
class Node:
    value: float
    left: int
    right: int
    feature: int
    flags: int


@dataclass
class EmbeddedModel:
    symbol: str
    source_file: str
    kind: str
    feature_names: list[str]
    nodes: list[Node]
    roots: list[int]
    base_margin: float = 0.0


def floor_float32(value: float) -> float:
    """Largest float32 not greater than value."""
    result = np.float32(value)
    if float(result) > value:
        result = np.nextafter(result, np.float32(-np.inf), dtype=np.float32)
    return float(result)


def ceil_float32(value: float) -> float:
    """Smallest float32 not less than value."""
    result = np.float32(value)
    if float(result) < value:
        result = np.nextafter(result, np.float32(np.inf), dtype=np.float32)
    return float(result)


def convert_random_forest(path: Path, symbol: str) -> EmbeddedModel:
    model = joblib.load(path)
    if not isinstance(model, RandomForestClassifier):
        raise TypeError(f"{path.name} is not a RandomForestClassifier")
    classes = np.asarray(model.classes_)
    positive = np.flatnonzero(classes == 1)
    if classes.size != 2 or positive.size != 1:
        raise ValueError(f"{path.name} must be a binary classifier with class 1")
    positive_index = int(positive[0])

    nodes: list[Node] = []
    roots: list[int] = []
    for estimator in model.estimators_:
        tree = estimator.tree_
        base = len(nodes)
        roots.append(base)
        for index in range(tree.node_count):
            left = int(tree.children_left[index])
            right = int(tree.children_right[index])
            if left == right:  # sklearn uses -1/-1 for a leaf
                values = np.asarray(tree.value[index][0], dtype=np.float64)
                total = float(values.sum())
                probability = float(values[positive_index] / total) if total else 0.0
                nodes.append(Node(probability, 0, 0, 0, FLAG_LEAF))
            else:
                missing_right = not bool(tree.missing_go_to_left[index])
                flags = FLAG_MISSING_RIGHT if missing_right else 0
                nodes.append(
                    Node(
                        floor_float32(float(tree.threshold[index])),
                        base + left,
                        base + right,
                        int(tree.feature[index]),
                        flags,
                    )
                )

    return EmbeddedModel(
        symbol=symbol,
        source_file=path.name,
        kind="random_forest",
        feature_names=[str(value) for value in model.feature_names_in_],
        nodes=nodes,
        roots=roots,
    )


def parse_base_score(raw_value: str | float | list[float]) -> float:
    if isinstance(raw_value, str):
        parsed = json.loads(raw_value) if raw_value.startswith("[") else float(raw_value)
    else:
        parsed = raw_value
    probability = float(parsed[0] if isinstance(parsed, list) else parsed)
    if not 0.0 < probability < 1.0:
        raise ValueError(f"binary logistic base score must be in (0, 1), got {probability}")
    return math.log(probability / (1.0 - probability))


def convert_xgboost(path: Path, symbol: str) -> EmbeddedModel:
    model = joblib.load(path)
    if not isinstance(model, XGBClassifier):
        raise TypeError(f"{path.name} is not an XGBClassifier")
    booster = model.get_booster()
    raw = json.loads(booster.save_raw(raw_format="json"))
    learner = raw["learner"]
    if learner["objective"]["name"] != "binary:logistic":
        raise ValueError(f"{path.name} does not use binary:logistic")
    gradient_booster = learner["gradient_booster"]
    if gradient_booster["name"] != "gbtree":
        raise ValueError(f"{path.name} does not use the supported gbtree booster")

    feature_names = [str(value) for value in learner.get("feature_names", [])]
    feature_count = int(learner["learner_model_param"]["num_feature"])
    if not feature_names:
        feature_names = [f"f{index}" for index in range(feature_count)]
    if len(feature_names) != feature_count:
        raise ValueError(f"{path.name} has inconsistent feature metadata")

    nodes: list[Node] = []
    roots: list[int] = []
    trees = gradient_booster["model"]["trees"]
    for tree in trees:
        base = len(nodes)
        roots.append(base)
        left_children = tree["left_children"]
        right_children = tree["right_children"]
        split_conditions = tree["split_conditions"]
        split_indices = tree["split_indices"]
        default_left = tree["default_left"]
        split_types = tree["split_type"]
        if any(int(value) != 0 for value in split_types):
            raise ValueError(f"{path.name} contains unsupported categorical splits")
        for index, left in enumerate(left_children):
            left = int(left)
            right = int(right_children[index])
            if left == -1:
                nodes.append(Node(float(np.float32(split_conditions[index])), 0, 0, 0, FLAG_LEAF))
            else:
                flags = 0 if bool(default_left[index]) else FLAG_MISSING_RIGHT
                nodes.append(
                    Node(
                        # XGBoost stores split conditions as float32.  The JSON
                        # decimal is a round-trippable rendering of that value.
                        float(np.float32(split_conditions[index])),
                        base + left,
                        base + right,
                        int(split_indices[index]),
                        flags,
                    )
                )

    return EmbeddedModel(
        symbol=symbol,
        source_file=path.name,
        kind="xgboost",
        feature_names=feature_names,
        nodes=nodes,
        roots=roots,
        base_margin=parse_base_score(learner["learner_model_param"]["base_score"]),
    )


def c_float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("generated model contains a non-finite constant")
    text = format(float(np.float32(value)), ".9g")
    if "e" not in text.lower() and "." not in text:
        text += ".0"
    return text + "f"


def render_header(models: list[EmbeddedModel]) -> str:
    declarations = []
    for model in models:
        declarations.append(
            f"Prediction predict_{model.symbol}(const float features[{len(model.feature_names)}]);\n"
            f"extern const char* const {model.symbol}_feature_names[{len(model.feature_names)}];"
        )
    return """// Generated by tools/convert_models.py. Do not edit manually.
#ifndef PICO_ML_GENERATED_MODELS_H
#define PICO_ML_GENERATED_MODELS_H

#include <cstddef>
#include <cstdint>

namespace pico_ml
{

struct Prediction
{
    std::uint8_t label;
    float probability;
};

""" + "\n\n".join(declarations) + "\n\n} // namespace pico_ml\n\n#endif // PICO_ML_GENERATED_MODELS_H\n"


def render_model_arrays(model: EmbeddedModel) -> str:
    node_lines = [
        f"    {{{c_float(node.value)}, {node.left}, {node.right}, {node.feature}, {node.flags}, 0}},"
        for node in model.nodes
    ]
    roots = [str(root) for root in model.roots]
    root_lines = [
        "    " + ", ".join(roots[index : index + 10]) + ","
        for index in range(0, len(roots), 10)
    ]
    feature_lines = [f'    "{name}",' for name in model.feature_names]
    return f"""
const char* const {model.symbol}_feature_names[{len(model.feature_names)}] = {{
{chr(10).join(feature_lines)}
}};

static const ModelNode {model.symbol}_nodes[{len(model.nodes)}] = {{
{chr(10).join(node_lines)}
}};

static const std::uint16_t {model.symbol}_roots[{len(model.roots)}] = {{
{chr(10).join(root_lines)}
}};
"""


def render_source(models: list[EmbeddedModel]) -> str:
    arrays = "\n".join(render_model_arrays(model) for model in models)
    functions = []
    for model in models:
        feature_count = len(model.feature_names)
        if model.kind == "random_forest":
            body = f"""    float sum = 0.0f;
    for (std::size_t tree = 0; tree < {len(model.roots)}; ++tree)
    {{
        sum += walk_tree(
            {model.symbol}_nodes, {model.symbol}_roots[tree],
            features, false);
    }}
    const float probability = sum / {c_float(float(len(model.roots)))};"""
        else:
            body = f"""    float margin = {c_float(model.base_margin)};
    for (std::size_t tree = 0; tree < {len(model.roots)}; ++tree)
    {{
        margin += walk_tree(
            {model.symbol}_nodes, {model.symbol}_roots[tree],
            features, true);
    }}
    const float probability = sigmoid(margin);"""
        functions.append(
            f"""Prediction predict_{model.symbol}(const float features[{feature_count}])
{{
{body}
    return {{static_cast<std::uint8_t>(probability >= 0.5f), probability}};
}}"""
        )

    return """// Generated by tools/convert_models.py. Do not edit manually.
#include "generated_models.h"

#include <cmath>

namespace pico_ml
{
namespace
{

constexpr std::uint8_t kLeaf = 0x01;
constexpr std::uint8_t kMissingRight = 0x02;

struct alignas(4) ModelNode
{
    float value;
    std::uint16_t left;
    std::uint16_t right;
    std::uint8_t feature;
    std::uint8_t flags;
    std::uint16_t reserved;
};

static_assert(sizeof(ModelNode) == 12, "ModelNode layout changed");

float walk_tree(
    const ModelNode* nodes,
    std::uint16_t root,
    const float* features,
    bool strict_less_than)
{
    std::uint16_t index = root;
    while ((nodes[index].flags & kLeaf) == 0)
    {
        const ModelNode& node = nodes[index];
        const float input = features[node.feature];
        if (std::isnan(input))
        {
            index = (node.flags & kMissingRight) ? node.right : node.left;
        }
        else
        {
            const bool go_left = strict_less_than ?
                (input < node.value) : (input <= node.value);
            index = go_left ? node.left : node.right;
        }
    }
    return nodes[index].value;
}

float sigmoid(float value)
{
    if (value >= 0.0f)
    {
        return 1.0f / (1.0f + std::exp(-value));
    }
    const float exponential = std::exp(value);
    return exponential / (1.0f + exponential);
}

}  // namespace
""" + arrays + "\n" + "\n\n".join(functions) + "\n\n}  // namespace pico_ml\n"


def predict_embedded(model: EmbeddedModel, rows: np.ndarray) -> np.ndarray:
    probabilities = np.empty(rows.shape[0], dtype=np.float32)
    for row_index, row in enumerate(np.asarray(rows, dtype=np.float32)):
        result = np.float32(0.0 if model.kind == "random_forest" else model.base_margin)
        for root in model.roots:
            index = root
            while not (model.nodes[index].flags & FLAG_LEAF):
                node = model.nodes[index]
                value = row[node.feature]
                if np.isnan(value):
                    go_right = bool(node.flags & FLAG_MISSING_RIGHT)
                    index = node.right if go_right else node.left
                else:
                    go_left = value < node.value if model.kind == "xgboost" else value <= node.value
                    index = node.left if go_left else node.right
            result = np.float32(result + np.float32(model.nodes[index].value))
        if model.kind == "random_forest":
            probabilities[row_index] = np.float32(result / len(model.roots))
        else:
            probabilities[row_index] = np.float32(1.0 / (1.0 + math.exp(-float(result))))
    return probabilities


def validation_rows(model: EmbeddedModel, count: int = 1000) -> np.ndarray:
    rng = np.random.default_rng(20260912)
    thresholds: list[list[float]] = [[] for _ in model.feature_names]
    for node in model.nodes:
        if not (node.flags & FLAG_LEAF):
            thresholds[node.feature].append(node.value)
    rows = np.zeros((count, len(model.feature_names)), dtype=np.float32)
    for feature, values in enumerate(thresholds):
        candidates = np.asarray(values or [0.0], dtype=np.float32)
        selected = rng.choice(candidates, size=count)
        direction = rng.integers(-2, 3, size=count)
        adjusted = selected.copy()
        adjusted[direction < 0] = np.nextafter(adjusted[direction < 0], np.float32(-np.inf))
        adjusted[direction > 0] = np.nextafter(adjusted[direction > 0], np.float32(np.inf))
        rows[:, feature] = adjusted
    # Exercise the models' recorded missing-value directions too.
    for feature in range(len(model.feature_names)):
        rows[feature, feature] = np.nan
    return rows


def validate(model: EmbeddedModel, path: Path) -> dict:
    original = joblib.load(path)
    rows = validation_rows(model)
    reference = np.asarray(original.predict_proba(rows)[:, 1], dtype=np.float32)
    embedded = predict_embedded(model, rows)
    reference_labels = reference >= np.float32(0.5)
    embedded_labels = embedded >= np.float32(0.5)
    return {
        "samples": int(rows.shape[0]),
        "label_mismatches": int(np.count_nonzero(reference_labels != embedded_labels)),
        "maximum_probability_error": float(np.max(np.abs(reference - embedded))),
    }


def manifest_entry(model: EmbeddedModel, validation: dict) -> dict:
    return {
        "symbol": model.symbol,
        "source_file": model.source_file,
        "kind": model.kind,
        "features": model.feature_names,
        "tree_count": len(model.roots),
        "node_count": len(model.nodes),
        "estimated_flash_bytes": len(model.nodes) * 12 + len(model.roots) * 2,
        "validation": validation,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--skip-validation", action="store_true")
    args = parser.parse_args()

    jobs = [
        (convert_random_forest, ROOT / "rf_sv_stream_detector.joblib", "rf_sv"),
        (convert_xgboost, ROOT / "xgb_goose_detector.joblib", "xgb_goose"),
        (convert_xgboost, ROOT / "xgb_sv_stream_detector.joblib", "xgb_sv"),
    ]
    models = [converter(path, symbol) for converter, path, symbol in jobs]
    for model in models:
        if len(model.nodes) > 65535:
            raise ValueError(f"{model.symbol} exceeds the uint16 node-index limit")

    validations = {}
    if not args.skip_validation:
        for model, (_, path, _) in zip(models, jobs, strict=True):
            validations[model.symbol] = validate(model, path)
            if validations[model.symbol]["label_mismatches"]:
                raise RuntimeError(f"validation failed for {model.symbol}: {validations[model.symbol]}")

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "generated_models.h").write_text(render_header(models), encoding="utf-8")
    (args.output / "generated_models.cpp").write_text(render_source(models), encoding="utf-8")
    manifest = {
        "format": 1,
        "node_layout_bytes": 12,
        "models": [manifest_entry(model, validations.get(model.symbol, {})) for model in models],
    }
    (args.output / "model_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
