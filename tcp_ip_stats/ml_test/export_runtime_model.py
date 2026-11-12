#!/usr/bin/env python3
"""Export a trained logistic-regression bundle to the lightweight runtime JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import joblib


PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = PROJECT_DIR / "model_handoff/syn-window-v1/runtime_model.json"
POLICY_FIELDS = (
    "probability_threshold",
    "minimum_syn_packets",
    "persistence_window_seconds",
    "persistence_required_hits",
    "clear_after_normal_seconds",
    "minimum_valid_window_seconds",
    "maximum_valid_window_seconds",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="將 StandardScaler + LogisticRegression 輸出成 runtime JSON。"
    )
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--base-policy",
        type=Path,
        default=DEFAULT_POLICY,
        help="取得機率門檻與持續性規則的既有 runtime JSON",
    )
    parser.add_argument(
        "--package-name",
        default="syn-window-handshake-experiment",
    )
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def as_float_list(values: Any) -> list[float]:
    return [float(value) for value in values]


def main() -> None:
    args = parse_args()
    if not args.model.is_file():
        raise FileNotFoundError(args.model)
    if not args.base_policy.is_file():
        raise FileNotFoundError(args.base_policy)

    bundle = joblib.load(args.model)
    if bundle.get("model_name") != "logistic_regression":
        raise ValueError("runtime JSON 只支援 logistic_regression")

    features = list(bundle["features"])
    pipeline = bundle["model"]
    imputer = pipeline.named_steps["imputer"]
    scaler = pipeline.named_steps["scaler"]
    classifier = pipeline.named_steps["classifier"]

    if classifier.coef_.shape != (1, len(features)):
        raise ValueError("classifier 不是預期的二元 logistic regression")

    with args.base_policy.open(encoding="utf-8") as handle:
        base_policy = json.load(handle)

    output = {
        "package_name": args.package_name,
        "source_model_sha256": sha256(args.model),
        "model_type": "standard_scaler_logistic_regression",
        "features": features,
        "imputer_median": as_float_list(imputer.statistics_),
        "scaler_mean": as_float_list(scaler.mean_),
        "scaler_scale": as_float_list(scaler.scale_),
        "coefficient": as_float_list(classifier.coef_[0]),
        "intercept": float(classifier.intercept_[0]),
    }
    output.update({field: base_policy[field] for field in POLICY_FIELDS})

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(output, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    print(f"runtime JSON：{args.output.resolve()}")
    print("特徵：" + ", ".join(features))


if __name__ == "__main__":
    main()
