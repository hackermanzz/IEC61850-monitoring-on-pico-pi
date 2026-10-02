"""Export the batch GOOSE/SV Random Forest bundle as flash-resident C.

Run with the model-conversion environment:
    python tools/convert_batch_models.py

The generated predictor returns the class-1 probability. Firmware applies the
bundle threshold exported in generated_batch_models.h.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = ROOT / "rf_batch_models" / "iec61850_rf_batch_bundle.joblib"
DEFAULT_OUTPUT = ROOT / "firmware" / "generated_batch"
LEAF = 0x01
MISSING_RIGHT = 0x02


@dataclass(frozen=True)
class Node:
    value: float
    left: int
    right: int
    feature: int
    flags: int


@dataclass
class EmbeddedModel:
    protocol: str
    feature_names: list[str]
    threshold: float
    nodes: list[Node]
    roots: list[int]
    max_depth: int


def floor_float32(value: float) -> float:
    result = np.float32(value)
    if float(result) > value:
        result = np.nextafter(result, np.float32(-np.inf), dtype=np.float32)
    return float(result)


def c_float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError(f"non-finite C constant: {value}")
    text = format(float(np.float32(value)), ".9g")
    if "e" not in text.lower() and "." not in text:
        text += ".0"
    return text + "f"


def convert_model(protocol: str, entry: dict[str, Any]) -> EmbeddedModel:
    model = entry.get("model")
    if not isinstance(model, RandomForestClassifier):
        raise TypeError(f"{protocol} model is not a RandomForestClassifier")
    feature_names = [str(value) for value in entry.get("feature_names", ())]
    if not feature_names or len(feature_names) != int(model.n_features_in_):
        raise ValueError(f"{protocol} feature_names do not match model feature count")
    if hasattr(model, "feature_names_in_") and feature_names != [str(x) for x in model.feature_names_in_]:
        raise ValueError(f"{protocol} feature order differs from the fitted model")
    classes = np.asarray(model.classes_)
    positives = np.flatnonzero(classes == 1)
    if len(classes) != 2 or positives.size != 1:
        raise ValueError(f"{protocol} must be a binary classifier with class 1")
    positive_index = int(positives[0])
    threshold = float(entry["threshold"])
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(f"{protocol} has invalid threshold {threshold}")

    nodes: list[Node] = []
    roots: list[int] = []
    max_depth = 0
    for estimator in model.estimators_:
        tree = estimator.tree_
        base = len(nodes)
        roots.append(base)
        max_depth = max(max_depth, int(tree.max_depth))
        for index in range(tree.node_count):
            left = int(tree.children_left[index])
            right = int(tree.children_right[index])
            if left == right:
                values = np.asarray(tree.value[index][0], dtype=np.float64)
                total = float(values.sum())
                probability = float(values[positive_index] / total) if total else 0.0
                nodes.append(Node(float(np.float32(probability)), 0, 0, 0, LEAF))
            else:
                # Preserve sklearn's NaN routing for the few trees that use it.
                missing_right = not bool(tree.missing_go_to_left[index])
                nodes.append(Node(
                    floor_float32(float(tree.threshold[index])),
                    base + left,
                    base + right,
                    int(tree.feature[index]),
                    MISSING_RIGHT if missing_right else 0,
                ))

    if not roots:
        raise ValueError(f"{protocol} forest contains no trees")
    if len(nodes) > 65535 or max(roots, default=0) > 65535:
        raise ValueError(f"{protocol} exceeds uint16 node-index limits")
    if max((n.feature for n in nodes if not (n.flags & LEAF)), default=0) >= len(feature_names):
        raise ValueError(f"{protocol} split references a missing feature")
    return EmbeddedModel(protocol, feature_names, threshold, nodes, roots, max_depth)


def validate_runtime_config(config: dict[str, Any], models: list[EmbeddedModel]) -> dict[str, Any]:
    batch = config.get("batch")
    channels = config.get("sv_channels")
    waveform = config.get("waveform")
    counter = config.get("counter")
    timing = config.get("timing")
    if not all(isinstance(block, dict) for block in (batch, channels, waveform, counter, timing)):
        raise ValueError("bundle is missing one or more runtime config blocks")

    offsets = channels.get("offsets")
    scales = channels.get("relative_scale")
    if channels.get("format") != ">f":
        raise ValueError(f"unsupported SV channel format {channels.get('format')!r}; expected '>f'")
    if not isinstance(offsets, (list, tuple)) or len(offsets) != 6:
        raise ValueError("SV runtime currently requires exactly six channel offsets")
    if not isinstance(scales, (list, tuple)) or len(scales) != len(offsets):
        raise ValueError("SV relative_scale length must match the six channel offsets")
    if len(models[1].feature_names) != 72:
        raise ValueError("SV model must have 72 features for the six-channel batch schema")

    def positive_int(block: dict[str, Any], key: str) -> int:
        value = block[key]
        if isinstance(value, bool) or int(value) != value or int(value) < 1:
            raise ValueError(f"runtime config {key} must be a positive integer")
        return int(value)

    def finite_number(value: Any, key: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"runtime config {key} must be finite")
        return number

    batch_size = positive_int(batch, "size_frames")
    batch_stride = positive_int(batch, "stride_frames")
    if batch_stride > batch_size:
        raise ValueError("batch stride_frames cannot exceed size_frames")
    if bool(batch.get("emit_partial", False)):
        raise ValueError("firmware schema does not support partial batches")
    if any(isinstance(value, bool) or int(value) != value or int(value) < 0 for value in offsets):
        raise ValueError("SV channel offsets must be non-negative integers")

    return {
        "batch": {"size_frames": batch_size, "stride_frames": batch_stride, "emit_partial": False},
        "sv_channels": {
            "offsets": [int(value) for value in offsets],
            "format": ">f",
            "relative_scale": [finite_number(value, "relative_scale") for value in scales],
        },
        "waveform": {
            "epsilon": finite_number(waveform["epsilon"], "epsilon"),
            "relative_jump_limit": finite_number(waveform["relative_jump_limit"], "relative_jump_limit"),
            "plateau_relative_limit": finite_number(waveform["plateau_relative_limit"], "plateau_relative_limit"),
            "history_min_samples": positive_int(waveform, "history_min_samples"),
            "history_samples": positive_int(waveform, "history_samples"),
            "robust_ratio_cap": finite_number(waveform["robust_ratio_cap"], "robust_ratio_cap"),
        },
        "counter": {
            "max_smp_delta": positive_int(counter, "max_smp_delta"),
            "max_stnum_step": positive_int(counter, "max_stnum_step"),
        },
        "timing": {
            "missing_age_s": finite_number(timing["missing_age_s"], "missing_age_s"),
            "history_frames": positive_int(timing, "history_frames"),
        },
    }


def render_header(models: list[EmbeddedModel], config: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    goose, sv = models
    runtime = validate_runtime_config(config, models)
    batch = runtime["batch"]
    channels = runtime["sv_channels"]
    waveform = runtime["waveform"]
    counter = runtime["counter"]
    timing = runtime["timing"]
    schema = {
        "schema_version": 1,
        "feature_names": {model.protocol: model.feature_names for model in models},
        "runtime_config": runtime,
    }
    canonical_schema = json.dumps(schema, sort_keys=True, separators=(",", ":"), allow_nan=False)
    fingerprint = hashlib.sha256(canonical_schema.encode("utf-8")).hexdigest()
    offsets = ", ".join(str(value) for value in channels["offsets"])
    scales = ", ".join(c_float(value) for value in channels["relative_scale"])
    header = f'''/* Generated by tools/convert_batch_models.py. Do not edit manually. */
#ifndef PICO_ML_GENERATED_BATCH_MODELS_H
#define PICO_ML_GENERATED_BATCH_MODELS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{{
#endif

#define PICO_ML_BATCH_SCHEMA_VERSION UINT32_C(1)
#define PICO_ML_BATCH_SIZE_FRAMES UINT32_C({batch["size_frames"]})
#define PICO_ML_BATCH_STRIDE_FRAMES UINT32_C({batch["stride_frames"]})
#define PICO_ML_BATCH_SCHEMA_FINGERPRINT                                       \\
  "{fingerprint}"
#define PICO_ML_BATCH_GOOSE_THRESHOLD {c_float(goose.threshold)}
#define PICO_ML_BATCH_SV_THRESHOLD {c_float(sv.threshold)}

#define PICO_ML_BATCH_SV_CHANNEL_COUNT UINT32_C({len(channels["offsets"])})
    extern const uint32_t
        g_pico_ml_batch_sv_channel_offsets[PICO_ML_BATCH_SV_CHANNEL_COUNT];
    extern const char g_pico_ml_batch_sv_channel_format[];
    extern const float
        g_pico_ml_batch_sv_relative_scale[PICO_ML_BATCH_SV_CHANNEL_COUNT];

#define PICO_ML_BATCH_WAVE_EPSILON {c_float(waveform["epsilon"])}
#define PICO_ML_BATCH_WAVE_RELATIVE_JUMP_LIMIT {c_float(waveform["relative_jump_limit"])}
#define PICO_ML_BATCH_WAVE_PLATEAU_RELATIVE_LIMIT {c_float(waveform["plateau_relative_limit"])}
#define PICO_ML_BATCH_WAVE_HISTORY_MIN_SAMPLES UINT32_C({waveform["history_min_samples"]})
#define PICO_ML_BATCH_WAVE_HISTORY_SAMPLES UINT32_C({waveform["history_samples"]})
#define PICO_ML_BATCH_WAVE_ROBUST_RATIO_CAP {c_float(waveform["robust_ratio_cap"])}

#define PICO_ML_BATCH_COUNTER_MAX_SMP_DELTA UINT32_C({counter["max_smp_delta"]})
#define PICO_ML_BATCH_COUNTER_MAX_STNUM_STEP UINT32_C({counter["max_stnum_step"]})
#define PICO_ML_BATCH_TIMING_MISSING_AGE_SECONDS {c_float(timing["missing_age_s"])}
#define PICO_ML_BATCH_TIMING_HISTORY_FRAMES UINT32_C({timing["history_frames"]})

    enum
    {{
        PICO_ML_BATCH_GOOSE_FEATURE_COUNT = {len(goose.feature_names)},
        PICO_ML_BATCH_SV_FEATURE_COUNT    = {len(sv.feature_names)}
    }};
    float pico_ml_batch_predict_goose (
        const float features[PICO_ML_BATCH_GOOSE_FEATURE_COUNT]);
    float pico_ml_batch_predict_sv (
        const float features[PICO_ML_BATCH_SV_FEATURE_COUNT]);
    extern const char * const
        g_pico_ml_batch_goose_feature_names[PICO_ML_BATCH_GOOSE_FEATURE_COUNT];
    extern const char * const
        g_pico_ml_batch_sv_feature_names[PICO_ML_BATCH_SV_FEATURE_COUNT];

#ifdef __cplusplus
}}
#endif

#endif /* PICO_ML_GENERATED_BATCH_MODELS_H */
'''
    return header, schema


def render_arrays(model: EmbeddedModel, symbol: str) -> str:
    names = "\n".join(f'    {json.dumps(name)},' for name in model.feature_names)
    nodes = "\n".join(
        f"    {{{c_float(node.value)}, {node.left}, {node.right}, {node.feature}, {node.flags}, 0}},"
        for node in model.nodes
    )
    roots = "\n".join(
        "    " + ", ".join(str(root) for root in model.roots[index:index + 10]) + ","
        for index in range(0, len(model.roots), 10)
    )
    return f'''const char *const g_pico_ml_batch_{symbol}_feature_names[{len(model.feature_names)}] = {{
{names}
}};

static const generated_batch_model_node_t g_{symbol}_nodes[{len(model.nodes)}] = {{
{nodes}
}};

static const uint16_t g_{symbol}_roots[{len(model.roots)}] = {{
{roots}
}};
'''


def render_source(models: list[EmbeddedModel], config: dict[str, Any]) -> str:
    goose, sv = models
    runtime = validate_runtime_config(config, models)
    channels = runtime["sv_channels"]
    return f'''/* Generated by tools/convert_batch_models.py. Do not edit manually. */
#include "generated_batch_models.h"

#include <math.h>
#include <stddef.h>

enum {{
    MODEL_NODE_LEAF = 0x01,
    MODEL_NODE_MISSING_RIGHT = 0x02,
    MODEL_NODE_SIZE_BYTES = 12U,
    GOOSE_TREE_COUNT = {len(goose.roots)}U,
    GOOSE_NODE_COUNT = {len(goose.nodes)}U,
    SV_TREE_COUNT = {len(sv.roots)}U,
    SV_NODE_COUNT = {len(sv.nodes)}U
}};

typedef struct
{{
    float value;
    uint16_t left;
    uint16_t right;
    uint8_t feature;
    uint8_t flags;
    uint16_t reserved;
}} generated_batch_model_node_t;

typedef char generated_batch_model_node_size_check_t[
    (sizeof(generated_batch_model_node_t) == MODEL_NODE_SIZE_BYTES) ? 1 : -1];

static float walk_tree(const generated_batch_model_node_t *nodes, uint16_t node_count,
                       uint16_t feature_count, uint16_t root,
                       const float *features)
{{
    uint16_t index = root;
    uint16_t steps = 0U;
    while ((node_count > index) && (node_count > steps) &&
           (0U == (nodes[index].flags & MODEL_NODE_LEAF)))
    {{
        const generated_batch_model_node_t *node = &nodes[index];
        float input = 0.0f;
        if (feature_count <= node->feature)
        {{
            return 0.0f;
        }}
        input = features[node->feature];
        if (isnan(input))
        {{
            index = (0U != (node->flags & MODEL_NODE_MISSING_RIGHT)) ? node->right : node->left;
        }}
        else
        {{
            index = (input <= node->value) ? node->left : node->right;
        }}
        steps++;
    }}
    return (node_count > index) ? nodes[index].value : 0.0f;
}}
''' + "\n".join((render_arrays(goose, "goose"), render_arrays(sv, "sv"))) + f'''
const uint32_t g_pico_ml_batch_sv_channel_offsets[PICO_ML_BATCH_SV_CHANNEL_COUNT] = {{{", ".join(str(v) for v in channels["offsets"])}}};
const char g_pico_ml_batch_sv_channel_format[] = {json.dumps(channels["format"])};
const float g_pico_ml_batch_sv_relative_scale[PICO_ML_BATCH_SV_CHANNEL_COUNT] = {{{", ".join(c_float(v) for v in channels["relative_scale"])}}};

float pico_ml_batch_predict_goose(const float features[PICO_ML_BATCH_GOOSE_FEATURE_COUNT])
{{
    uint16_t tree = 0U;
    float sum = 0.0f;
    if (NULL == features)
    {{
        return 0.0f;
    }}
    for (tree = 0U; tree < GOOSE_TREE_COUNT; tree++)
    {{
        sum += walk_tree(g_goose_nodes, GOOSE_NODE_COUNT,
                         PICO_ML_BATCH_GOOSE_FEATURE_COUNT,
                         g_goose_roots[tree], features);
    }}
    return sum / (float) GOOSE_TREE_COUNT;
}}

float pico_ml_batch_predict_sv(const float features[PICO_ML_BATCH_SV_FEATURE_COUNT])
{{
    uint16_t tree = 0U;
    float sum = 0.0f;
    if (NULL == features)
    {{
        return 0.0f;
    }}
    for (tree = 0U; tree < SV_TREE_COUNT; tree++)
    {{
        sum += walk_tree(g_sv_nodes, SV_NODE_COUNT,
                         PICO_ML_BATCH_SV_FEATURE_COUNT,
                         g_sv_roots[tree], features);
    }}
    return sum / (float) SV_TREE_COUNT;
}}
'''


def write_utf8_lf(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(content)


def predict_embedded(model: EmbeddedModel, rows: np.ndarray) -> np.ndarray:
    output = np.empty(rows.shape[0], dtype=np.float32)
    for row_number, row in enumerate(np.asarray(rows, dtype=np.float32)):
        total = np.float32(0.0)
        for root in model.roots:
            index = root
            while not (model.nodes[index].flags & LEAF):
                node = model.nodes[index]
                value = row[node.feature]
                if np.isnan(value):
                    index = node.right if node.flags & MISSING_RIGHT else node.left
                else:
                    index = node.left if value <= node.value else node.right
            total = np.float32(total + np.float32(model.nodes[index].value))
        output[row_number] = np.float32(total / np.float32(len(model.roots)))
    return output


def synthetic_boundary_rows(model: EmbeddedModel, count: int = 2048) -> np.ndarray:
    """Probe float32 values at and around actual split thresholds."""
    rng = np.random.default_rng(20260929)
    rows = np.zeros((count, len(model.feature_names)), dtype=np.float32)
    by_feature: list[list[float]] = [[] for _ in model.feature_names]
    for node in model.nodes:
        if not node.flags & LEAF:
            by_feature[node.feature].append(node.value)
    for feature, thresholds in enumerate(by_feature):
        candidates = np.asarray(thresholds or [0.0], dtype=np.float32)
        selected = rng.choice(candidates, size=count)
        direction = rng.integers(-1, 2, size=count)
        rows[:, feature] = selected
        lower = direction < 0
        upper = direction > 0
        rows[lower, feature] = np.nextafter(rows[lower, feature], np.float32(-np.inf))
        rows[upper, feature] = np.nextafter(rows[upper, feature], np.float32(np.inf))
    rows[0, :] = np.nan
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--skip-validation", action="store_true")
    args = parser.parse_args()

    bundle = joblib.load(args.bundle)
    if not isinstance(bundle, dict) or not isinstance(bundle.get("models"), dict):
        raise ValueError("bundle does not contain a models mapping")
    entries = bundle["models"]
    models = [convert_model(protocol, entries[protocol]) for protocol in ("GOOSE", "SV")]
    validations: dict[str, dict[str, Any]] = {}
    if not args.skip_validation:
        for protocol, embedded in zip(("GOOSE", "SV"), models, strict=True):
            reference_model = entries[protocol]["model"]
            rows = synthetic_boundary_rows(embedded)
            classes = np.asarray(reference_model.classes_)
            positive_index = int(np.flatnonzero(classes == 1)[0])
            reference = np.asarray(reference_model.predict_proba(rows)[:, positive_index], dtype=np.float32)
            emitted = predict_embedded(embedded, rows)
            reference_labels = reference >= np.float32(embedded.threshold)
            emitted_labels = emitted >= np.float32(embedded.threshold)
            validations[protocol] = {
                "rows": int(rows.shape[0]),
                "label_mismatches_at_0_5": int(np.count_nonzero((reference >= 0.5) != (emitted >= 0.5))),
                "label_mismatches_at_exported_threshold": int(np.count_nonzero(reference_labels != emitted_labels)),
                "maximum_probability_error": float(np.max(np.abs(reference - emitted))),
                "validation_kind": "float32 synthetic probes at model split boundaries; no feature-bearing real-row file in bundle",
            }
            if validations[protocol]["label_mismatches_at_0_5"] or validations[protocol]["label_mismatches_at_exported_threshold"]:
                raise RuntimeError(f"embedded parity failed for {protocol}: {validations[protocol]}")

    args.output.mkdir(parents=True, exist_ok=True)
    header, runtime_schema = render_header(models, bundle.get("feature_config", {}))
    write_utf8_lf(args.output / "generated_batch_models.h", header)
    source = render_source(models, bundle.get("feature_config", {}))
    source_path = args.output / "generated_batch_models.c"
    write_utf8_lf(source_path, source)
    stale_cpp_path = args.output / "generated_batch_models.cpp"
    if stale_cpp_path.exists():
        stale_cpp_path.unlink()
    generated_c_bytes = source_path.stat().st_size
    manifest_models = []
    for embedded in models:
        threshold_float32 = float(np.float32(embedded.threshold))
        names_bytes = sum(len(name.encode("utf-8")) + 1 for name in embedded.feature_names)
        # Pointer size is four bytes for RP2040; model arrays are aligned to 4 bytes.
        estimated_name_data_bytes = names_bytes + len(embedded.feature_names) * 4
        manifest_models.append({
            "protocol": embedded.protocol,
            "features": embedded.feature_names,
            "feature_count": len(embedded.feature_names),
            "tree_count": len(embedded.roots),
            "node_count": len(embedded.nodes),
            "maximum_depth": embedded.max_depth,
            "threshold": embedded.threshold,
            "threshold_float32": threshold_float32,
            "threshold_float32_drift": threshold_float32 - embedded.threshold,
            "estimated_tree_flash_bytes": len(embedded.nodes) * 12 + len(embedded.roots) * 2,
            "estimated_feature_name_flash_bytes_rp2040": estimated_name_data_bytes,
            "validation": validations.get(embedded.protocol),
        })
    manifest = {
        "format": 1,
        "bundle": str(args.bundle.relative_to(ROOT) if args.bundle.is_relative_to(ROOT) else args.bundle),
        "artifact_type": bundle.get("artifact_type"),
        "source_sha256": bundle.get("source_sha256", {}),
        "batch": runtime_schema["runtime_config"]["batch"],
        "runtime_config": runtime_schema["runtime_config"],
        "schema_fingerprint_sha256": hashlib.sha256(
            json.dumps(runtime_schema, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        ).hexdigest(),
        "node_layout_bytes": 12,
        "generated_c_bytes": generated_c_bytes,
        "models": manifest_models,
        "total_estimated_tree_flash_bytes": sum(m["estimated_tree_flash_bytes"] for m in manifest_models),
        "total_estimated_read_only_model_data_bytes_rp2040": sum(
            m["estimated_tree_flash_bytes"] + m["estimated_feature_name_flash_bytes_rp2040"]
            for m in manifest_models
        ),
        "estimated_prediction_ram_bytes": "No dynamic allocation; predictor uses scalar stack state only (exact ABI stack frame not measured)",
        "dynamic_allocation_during_prediction": False,
    }
    (args.output / "batch_model_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
