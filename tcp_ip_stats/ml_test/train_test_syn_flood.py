#!/usr/bin/env python3
"""訓練並測試每秒 SYN Flood 偵測模型。

這支程式只使用 eBPF 可以提供的數值特徵，不把 timestamp、
scenario 或 run_id 交給模型，並儘量避免相鄰秒數據同時出現在訓練集與測試集。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


RAW_FEATURES = [
    "tcp_packets",
    "tcp_bytes",
    "syn_only_packets",
]
MODEL_FEATURES = RAW_FEATURES + ["syn_ratio"]
ACTIVE_SOURCE_IPS_FEATURE = "active_source_ips"
ESTABLISHED_CONNECTIONS_FEATURE = "established_connections"
ACTIVE_IPS_PER_ESTABLISHED_FEATURE = "active_ips_per_established_connection"

REQUIRED_COLUMNS = {
    "timestamp",
    "tcp_packets",
    "tcp_bytes",
    "syn_only_packets",
    "run_id",
    "scenario",
    "label",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="用已標籤的 eBPF 每秒統計資料訓練並測試 SYN Flood 模型。"
    )
    parser.add_argument(
        "--input",
        nargs="+",
        type=Path,
        default=[Path("tcp_stats_labeled.csv")],
        help="一個或多個 tcp_stats_labeled.csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ml_test/output"),
        help="模型與測試報告的輸出資料夾",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.25,
        help="測試集比例（預設 0.25）",
    )
    parser.add_argument(
        "--block-size",
        type=int,
        default=10,
        help="只有一個 run_id 時，時間分塊的秒數（預設 10）",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="判定 SYN Flood 的機率門檻（預設 0.5）",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="使測試結果可重現的隨機種子",
    )
    parser.add_argument(
        "--save-model",
        choices=["logistic_regression", "random_forest"],
        default="logistic_regression",
        help=(
            "要儲存的預先指定模型（預設 logistic_regression）；"
            "不會根據測試集分數挑選。"
        ),
    )
    parser.add_argument(
        "--include-active-source-ips",
        action="store_true",
        help=(
            "將每秒實際有流量的不同來源 IP 數 active_source_ips 加入模型；"
            "輸入 CSV 必須包含此欄位"
        ),
    )
    parser.add_argument(
        "--include-established-connections",
        action="store_true",
        help=(
            "將使用者空間估計的 established_connections 加入模型；"
            "此欄位可能低估或漏計，預設不啟用"
        ),
    )
    parser.add_argument(
        "--include-active-ips-per-established",
        action="store_true",
        help=(
            "將 active_source_ips / (established_connections + 1) 加入模型；"
            "輸入 CSV 必須同時包含 active_source_ips 與 established_connections"
        ),
    )
    return parser.parse_args()


def get_model_features(
    include_established_connections: bool = False,
    include_active_source_ips: bool = False,
    include_active_ips_per_established: bool = False,
) -> list[str]:
    """回傳本次訓練使用的特徵順序。

    保留原本四個特徵為預設，避免無意間改變既有模型。
    """
    features = list(MODEL_FEATURES)
    if include_active_source_ips:
        features.append(ACTIVE_SOURCE_IPS_FEATURE)
    if include_established_connections:
        features.append(ESTABLISHED_CONNECTIONS_FEATURE)
    if include_active_ips_per_established:
        features.append(ACTIVE_IPS_PER_ESTABLISHED_FEATURE)
    return features


def validate_args(args: argparse.Namespace) -> None:
    if not 0.05 <= args.test_size <= 0.5:
        raise ValueError("--test-size 必須介於 0.05 和 0.5")
    if args.block_size < 2:
        raise ValueError("--block-size 至少要為 2")
    if not 0.0 < args.threshold < 1.0:
        raise ValueError("--threshold 必須介於 0 和 1")


def load_data(paths: list[Path]) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []

    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"找不到輸入檔：{path}")

        frame = pd.read_csv(path)
        missing = REQUIRED_COLUMNS.difference(frame.columns)
        if missing:
            raise ValueError(
                f"{path} 缺少必要欄位：{', '.join(sorted(missing))}"
            )

        frame = frame.copy()
        frame["source_file"] = str(path)
        frames.append(frame)

    data = pd.concat(frames, ignore_index=True)
    if data.empty:
        raise ValueError("輸入檔沒有任何資料")

    return data


def validate_and_prepare(
    data: pd.DataFrame,
    model_features: list[str] | None = None,
) -> pd.DataFrame:
    prepared = data.copy()
    selected_features = list(model_features or MODEL_FEATURES)
    required_numeric_features = list(RAW_FEATURES)
    ratio_selected = ACTIVE_IPS_PER_ESTABLISHED_FEATURE in selected_features
    if ACTIVE_SOURCE_IPS_FEATURE in selected_features or ratio_selected:
        required_numeric_features.append(ACTIVE_SOURCE_IPS_FEATURE)
    if ESTABLISHED_CONNECTIONS_FEATURE in selected_features or ratio_selected:
        required_numeric_features.append(ESTABLISHED_CONNECTIONS_FEATURE)
    required_numeric_features = list(dict.fromkeys(required_numeric_features))

    missing_features = set(required_numeric_features).difference(prepared.columns)
    if missing_features:
        raise ValueError(
            "輸入檔缺少模型特徵：" + ", ".join(sorted(missing_features))
        )

    prepared["timestamp"] = pd.to_datetime(prepared["timestamp"], errors="raise")
    prepared["run_id"] = prepared["run_id"].astype(str)
    prepared["scenario"] = prepared["scenario"].astype(str)

    for column in required_numeric_features + ["label"]:
        prepared[column] = pd.to_numeric(prepared[column], errors="raise")

    invalid_labels = set(prepared["label"].dropna().unique()).difference({0, 1})
    if invalid_labels:
        raise ValueError(f"label 只能是 0 或 1，但發現：{sorted(invalid_labels)}")

    if prepared[list(REQUIRED_COLUMNS)].isna().any().any():
        missing_counts = prepared[list(REQUIRED_COLUMNS)].isna().sum()
        missing_counts = missing_counts[missing_counts > 0]
        raise ValueError(f"必要欄位包含缺值：\n{missing_counts}")

    if (prepared[required_numeric_features] < 0).any().any():
        raise ValueError("封包數或 bytes 不可為負數")

    if (prepared["syn_only_packets"] > prepared["tcp_packets"]).any():
        raise ValueError("發現 syn_only_packets 大於 tcp_packets 的不合理資料")

    duplicate_mask = prepared.duplicated(subset=["run_id", "timestamp"], keep=False)
    if duplicate_mask.any():
        examples = prepared.loc[duplicate_mask, ["run_id", "timestamp"]].head(5)
        raise ValueError(f"同一 run_id 內有重複 timestamp：\n{examples}")

    prepared["syn_ratio"] = np.divide(
        prepared["syn_only_packets"],
        prepared["tcp_packets"],
        out=np.zeros(len(prepared), dtype=float),
        where=prepared["tcp_packets"].to_numpy() > 0,
    )
    if ratio_selected:
        prepared[ACTIVE_IPS_PER_ESTABLISHED_FEATURE] = np.divide(
            prepared[ACTIVE_SOURCE_IPS_FEATURE],
            prepared[ESTABLISHED_CONNECTIONS_FEATURE] + 1.0,
        )

    feature_matrix = prepared[selected_features].to_numpy(dtype=float)
    if not np.isfinite(feature_matrix).all():
        raise ValueError("模型特徵中出現 NaN 或 Infinity")

    return prepared.sort_values(["run_id", "timestamp"]).reset_index(drop=True)


def find_valid_group_split(
    labels: np.ndarray,
    groups: np.ndarray,
    test_size: float,
    random_state: int,
) -> tuple[np.ndarray, np.ndarray]:
    splitter = GroupShuffleSplit(
        n_splits=200,
        test_size=test_size,
        random_state=random_state,
    )

    best_split: tuple[np.ndarray, np.ndarray] | None = None
    best_difference = float("inf")

    dummy = np.zeros((len(labels), 1))
    for train_indices, test_indices in splitter.split(dummy, labels, groups):
        if set(labels[train_indices]) != {0, 1}:
            continue
        if set(labels[test_indices]) != {0, 1}:
            continue

        actual_test_size = len(test_indices) / len(labels)
        difference = abs(actual_test_size - test_size)
        if difference < best_difference:
            best_split = train_indices, test_indices
            best_difference = difference

    if best_split is None:
        raise ValueError(
            "無法用目前的 run/block 分組同時在訓練集和測試集保留 0、1 兩種 label"
        )

    return best_split


def make_split(
    data: pd.DataFrame,
    test_size: float,
    block_size: int,
    random_state: int,
) -> tuple[pd.DataFrame, np.ndarray, np.ndarray, str, list[str]]:
    prepared = data.copy()
    warnings: list[str] = []
    run_count = prepared["run_id"].nunique()

    if run_count >= 2:
        mode = "holdout_by_run_id"
        prepared["split_group"] = prepared["run_id"]
    else:
        mode = "diagnostic_time_blocks"
        warnings.append(
            "只發現一個 run_id；本次使用各情境的連續時間塊切分，"
            "分數只能驗證程式管線，不能證明模型能泛化到新實驗。"
        )
        block_number = (
            prepared.groupby(["run_id", "scenario"], sort=False).cumcount()
            // block_size
        )
        prepared["split_group"] = (
            prepared["run_id"]
            + "|"
            + prepared["scenario"]
            + "|block_"
            + block_number.astype(str)
        )

    labels = prepared["label"].to_numpy(dtype=int)
    groups = prepared["split_group"].to_numpy()
    train_indices, test_indices = find_valid_group_split(
        labels=labels,
        groups=groups,
        test_size=test_size,
        random_state=random_state,
    )

    return prepared, train_indices, test_indices, mode, warnings


def build_models(random_state: int) -> dict[str, Any]:
    return {
        "logistic_regression": Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        class_weight="balanced",
                        max_iter=2000,
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "random_forest": Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "classifier",
                    RandomForestClassifier(
                        n_estimators=300,
                        min_samples_leaf=3,
                        class_weight="balanced_subsample",
                        random_state=random_state,
                        n_jobs=-1,
                    ),
                ),
            ]
        ),
    }


def evaluate_model(
    model: Any,
    features: pd.DataFrame,
    labels: pd.Series,
    threshold: float,
) -> tuple[dict[str, Any], np.ndarray, np.ndarray]:
    probabilities = model.predict_proba(features)[:, 1]
    predictions = (probabilities >= threshold).astype(int)

    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    report = classification_report(
        labels,
        predictions,
        labels=[0, 1],
        target_names=["normal", "syn_flood"],
        output_dict=True,
        zero_division=0,
    )

    metrics = {
        "threshold": threshold,
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "average_precision": float(average_precision_score(labels, probabilities)),
        "accuracy": float(report["accuracy"]),
        "normal_precision": float(report["normal"]["precision"]),
        "normal_recall": float(report["normal"]["recall"]),
        "normal_f1": float(report["normal"]["f1-score"]),
        "attack_precision": float(report["syn_flood"]["precision"]),
        "attack_recall": float(report["syn_flood"]["recall"]),
        "attack_f1": float(report["syn_flood"]["f1-score"]),
        "confusion_matrix": {
            "true_negative": int(true_negative),
            "false_positive": int(false_positive),
            "false_negative": int(false_negative),
            "true_positive": int(true_positive),
        },
    }
    return metrics, probabilities, predictions


def model_feature_scores(
    name: str,
    model: Any,
    model_features: list[str] | None = None,
) -> pd.DataFrame:
    classifier = model.named_steps["classifier"]
    selected_features = list(model_features or MODEL_FEATURES)

    if name == "random_forest":
        scores = classifier.feature_importances_
        score_name = "feature_importance"
    else:
        scores = classifier.coef_[0]
        score_name = "standardized_coefficient"

    return pd.DataFrame(
        {
            "model": name,
            "feature": selected_features,
            "score_type": score_name,
            "score": scores,
            "absolute_score": np.abs(scores),
        }
    ).sort_values("absolute_score", ascending=False)


def print_model_result(name: str, metrics: dict[str, Any]) -> None:
    matrix = metrics["confusion_matrix"]
    print(f"\n=== {name} ===")
    print(f"ROC-AUC          : {metrics['roc_auc']:.4f}")
    print(f"Average precision: {metrics['average_precision']:.4f}")
    print(f"Accuracy         : {metrics['accuracy']:.4f}")
    print(f"Attack precision : {metrics['attack_precision']:.4f}")
    print(f"Attack recall    : {metrics['attack_recall']:.4f}")
    print(f"Attack F1        : {metrics['attack_f1']:.4f}")
    print(
        "Confusion matrix: "
        f"TN={matrix['true_negative']}, FP={matrix['false_positive']}, "
        f"FN={matrix['false_negative']}, TP={matrix['true_positive']}"
    )


def main() -> None:
    args = parse_args()
    validate_args(args)

    model_features = get_model_features(
        include_established_connections=args.include_established_connections,
        include_active_source_ips=args.include_active_source_ips,
        include_active_ips_per_established=(
            args.include_active_ips_per_established
        ),
    )
    data = validate_and_prepare(load_data(args.input), model_features=model_features)
    data, train_indices, test_indices, split_mode, warnings = make_split(
        data=data,
        test_size=args.test_size,
        block_size=args.block_size,
        random_state=args.random_state,
    )

    train_data = data.iloc[train_indices].copy()
    test_data = data.iloc[test_indices].copy()

    train_features = train_data[model_features]
    train_labels = train_data["label"].astype(int)
    test_features = test_data[model_features]
    test_labels = test_data["label"].astype(int)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    models = build_models(args.random_state)
    model_metrics: dict[str, dict[str, Any]] = {}
    prediction_output = test_data[
        ["timestamp", "run_id", "scenario", "label", "split_group"]
    ].copy()
    feature_score_frames: list[pd.DataFrame] = []

    for name, model in models.items():
        model.fit(train_features, train_labels)
        metrics, probabilities, predictions = evaluate_model(
            model=model,
            features=test_features,
            labels=test_labels,
            threshold=args.threshold,
        )
        model_metrics[name] = metrics
        prediction_output[f"{name}_probability"] = probabilities
        prediction_output[f"{name}_prediction"] = predictions
        feature_score_frames.append(
            model_feature_scores(name, model, model_features=model_features)
        )
        print_model_result(name, metrics)

    # 要儲存的模型由執行前的參數決定，不根據這次測試集
    # 的表現挑選，避免把測試集間接當成模型選擇資料。
    saved_model_name = args.save_model
    saved_model = models[saved_model_name]

    split_summary = {
        "mode": split_mode,
        "train_rows": int(len(train_data)),
        "test_rows": int(len(test_data)),
        "train_label_counts": {
            str(key): int(value)
            for key, value in train_labels.value_counts().sort_index().items()
        },
        "test_label_counts": {
            str(key): int(value)
            for key, value in test_labels.value_counts().sort_index().items()
        },
        "train_groups": sorted(train_data["split_group"].unique().tolist()),
        "test_groups": sorted(test_data["split_group"].unique().tolist()),
    }

    evaluation = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_files": [str(path) for path in args.input],
        "row_count": int(len(data)),
        "run_count": int(data["run_id"].nunique()),
        "features": model_features,
        "split": split_summary,
        "warnings": warnings,
        "models": model_metrics,
        "saved_model": saved_model_name,
    }

    model_bundle = {
        "model": saved_model,
        "model_name": saved_model_name,
        "features": model_features,
        "threshold": args.threshold,
        "created_at_utc": evaluation["created_at_utc"],
        "split_mode": split_mode,
        "metrics": model_metrics[saved_model_name],
        "warnings": warnings,
    }

    joblib.dump(model_bundle, args.output_dir / "selected_model.joblib")

    # 單輪資料的 block split 只用來做管線診斷。完成診斷後，另外以全部
    # 資料重新擬合執行下一輪獨立 holdout 所需的部署候選模型。
    deployment_model = build_models(args.random_state)[saved_model_name]
    deployment_model.fit(
        data[model_features],
        data["label"].astype(int),
    )
    deployment_bundle = {
        "model": deployment_model,
        "model_name": saved_model_name,
        "features": model_features,
        "threshold": args.threshold,
        "created_at_utc": evaluation["created_at_utc"],
        "training_rows": int(len(data)),
        "training_run_ids": sorted(data["run_id"].unique().tolist()),
        "evaluation_mode": "single_run_diagnostic_split_then_full_refit",
        "diagnostic_metrics": model_metrics[saved_model_name],
        "warnings": warnings,
    }
    joblib.dump(
        deployment_bundle,
        args.output_dir / "deployment_model.joblib",
    )
    model_feature_scores(
        saved_model_name,
        deployment_model,
        model_features=model_features,
    ).to_csv(
        args.output_dir / "deployment_feature_scores.csv",
        index=False,
    )
    evaluation["deployment_model"] = saved_model_name
    evaluation["deployment_fit_rows"] = int(len(data))
    prediction_output.sort_values(["run_id", "timestamp"]).to_csv(
        args.output_dir / "test_predictions.csv",
        index=False,
    )
    pd.concat(feature_score_frames, ignore_index=True).to_csv(
        args.output_dir / "feature_scores.csv",
        index=False,
    )
    with (args.output_dir / "evaluation.json").open("w", encoding="utf-8") as handle:
        json.dump(evaluation, handle, ensure_ascii=False, indent=2)

    print("\n=== 資料切分 ===")
    print(f"方式     : {split_mode}")
    print(f"訓練列數 : {len(train_data)}")
    print(f"測試列數 : {len(test_data)}")
    print(f"run_id 數 : {data['run_id'].nunique()}")
    for warning in warnings:
        print(f"警告     : {warning}")

    print("\n=== 輸出 ===")
    print(f"預先指定 : {saved_model_name}")
    print(f"模型     : {args.output_dir / 'selected_model.joblib'}")
    print(f"部署候選 : {args.output_dir / 'deployment_model.joblib'}（全部資料重新擬合）")
    print(f"評估報告 : {args.output_dir / 'evaluation.json'}")
    print(f"測試預測 : {args.output_dir / 'test_predictions.csv'}")
    print(f"特徵分數 : {args.output_dir / 'feature_scores.csv'}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError, KeyError) as error:
        print(f"錯誤：{error}", file=sys.stderr)
        raise SystemExit(2) from error
