"""Print embedded-relevant metadata for the joblib models in this directory."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[1]


def xgb_tree_stats(node: dict, depth: int = 0) -> tuple[int, int, int]:
    children = node.get("children", [])
    nodes = 1
    leaves = 1 if "leaf" in node else 0
    max_depth = depth
    for child in children:
        child_nodes, child_leaves, child_depth = xgb_tree_stats(child, depth + 1)
        nodes += child_nodes
        leaves += child_leaves
        max_depth = max(max_depth, child_depth)
    return nodes, leaves, max_depth


def inspect(path: Path) -> dict:
    model = joblib.load(path)
    result: dict = {
        "file": path.name,
        "serialized_bytes": path.stat().st_size,
        "python_type": f"{type(model).__module__}.{type(model).__name__}",
    }

    if isinstance(model, RandomForestClassifier):
        node_counts = [int(tree.tree_.node_count) for tree in model.estimators_]
        depths = [int(tree.tree_.max_depth) for tree in model.estimators_]
        result.update(
            kind="random_forest_classifier",
            trees=len(model.estimators_),
            features=int(model.n_features_in_),
            feature_names=[str(x) for x in model.feature_names_in_],
            classes=np.asarray(model.classes_).tolist(),
            total_nodes=sum(node_counts),
            total_leaves=sum((count + 1) // 2 for count in node_counts),
            maximum_depth=max(depths),
            estimated_packed_bytes=sum(node_counts) * 10,
        )
    elif isinstance(model, XGBClassifier):
        booster = model.get_booster()
        trees = [json.loads(tree) for tree in booster.get_dump(dump_format="json")]
        stats = [xgb_tree_stats(tree) for tree in trees]
        config = json.loads(booster.save_config())
        learner = config["learner"]
        objective = learner["objective"]["name"]
        model_param = learner["learner_model_param"]
        result.update(
            kind="xgboost_classifier",
            trees=len(trees),
            features=int(model.n_features_in_),
            feature_names=booster.feature_names,
            classes=np.asarray(model.classes_).tolist(),
            objective=objective,
            base_score=model_param["base_score"],
            total_nodes=sum(x[0] for x in stats),
            total_leaves=sum(x[1] for x in stats),
            maximum_depth=max(x[2] for x in stats),
            estimated_packed_bytes=sum(x[0] for x in stats) * 10,
        )
    else:
        result["kind"] = "unsupported"

    return result


def main() -> None:
    paths = sorted(ROOT.glob("*.joblib"))
    print(json.dumps([inspect(path) for path in paths], indent=2))


if __name__ == "__main__":
    main()
