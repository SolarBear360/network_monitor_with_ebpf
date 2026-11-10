#!/usr/bin/env python3
"""用多輪 eBPF 每秒統計資料訓練 SYN Flood 模型。

流程包含：
1. 保留原始 CSV，不在原檔上修改資料。
2. 明確排除已確認失敗的實驗情境。
3. 每次保留完整一輪做測試（leave-one-run-out）。
4. 完成評估後，用全部有效資料重新訓練部署模型。
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
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

from train_test_syn_flood import (
    MODEL_FEATURES,
    build_models,
    load_data,
    model_feature_scores,
    validate_and_prepare,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="逐輪交叉驗證，並用全部有效資料訓練 SYN Flood 部署模型。"
    )
    parser.add_argument(
        "--input",
        nargs="+",
        type=Path,
        default=[Path("tcp_stats_labeled_multi.csv")],
        help="一個或多個已標籤 CSV",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ml_test/output_multi_round_final"),
        help="輸出資料夾",
    )
    parser.add_argument(
        "--exclude-run-scenario",
        action="append",
        nargs=2,
        metavar=("RUN_ID", "SCENARIO"),
        default=[],
        help="排除已確認失敗的整段情境；可重複使用",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="判定攻擊的機率門檻（預設 0.5）",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="模型隨機種子",
    )
    parser.add_argument(
        "--final-model",
        choices=["logistic_regression", "random_forest"],
        default="logistic_regression",
        help="最後用全部有效資料重新訓練並儲存的模型",
    )
    return parser.parse_args()


def metrics_from_predictions(
    labels: np.ndarray,
    probabilities: np.ndarray,
    predictions: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    """將機率和 0/1 預測整理成固定格式的評估指標。"""
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

    return {
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


def find_suspicious_attack_groups(data: pd.DataFrame) -> list[dict[str, Any]]:
    """找出有攻擊標籤、但整段完全沒有觀察到純 SYN 的情境。"""
    suspicious: list[dict[str, Any]] = []
    attack_data = data.loc[data["label"].eq(1)]

    for (run_id, scenario), group in attack_data.groupby(
        ["run_id", "scenario"], sort=True, observed=True
    ):
        if int(group["syn_only_packets"].max()) == 0:
            suspicious.append(
                {
                    "run_id": str(run_id),
                    "scenario": str(scenario),
                    "rows": int(len(group)),
                    "reason": "label=1，但整段 syn_only_packets 都是 0",
                }
            )

    return suspicious


def apply_exclusions(
    data: pd.DataFrame,
    requested_exclusions: list[list[str]],
) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    """依 run_id 與 scenario 排除整段資料，並留下可稽核紀錄。"""
    kept = data.copy()
    exclusion_report: list[dict[str, Any]] = []

    for run_id, scenario in requested_exclusions:
        mask = kept["run_id"].eq(run_id) & kept["scenario"].eq(scenario)
        removed_rows = int(mask.sum())
        if removed_rows == 0:
            raise ValueError(
                f"找不到要排除的情境：run_id={run_id}, scenario={scenario}"
            )

        exclusion_report.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "removed_rows": removed_rows,
            }
        )
        kept = kept.loc[~mask].copy()

    if kept.empty:
        raise ValueError("排除後沒有剩餘資料")

    return kept.reset_index(drop=True), exclusion_report


def validate_cross_validation_data(data: pd.DataFrame) -> None:
    """確認每一輪都能各自當成有正常與攻擊樣本的測試集。"""
    if data["run_id"].nunique() < 2:
        raise ValueError("逐輪交叉驗證至少需要兩個 run_id")

    bad_runs: list[str] = []
    for run_id, group in data.groupby("run_id", sort=True):
        if set(group["label"].astype(int).unique()) != {0, 1}:
            bad_runs.append(str(run_id))

    if bad_runs:
        raise ValueError(
            "下列 run_id 沒有同時包含正常與攻擊樣本：" + ", ".join(bad_runs)
        )


def run_leave_one_run_out(
    data: pd.DataFrame,
    threshold: float,
    random_state: int,
) -> tuple[dict[str, Any], pd.DataFrame]:
    """每次保留一整輪測試，回傳模型指標及 out-of-fold 預測。"""
    prediction_output = data[
        ["timestamp", "run_id", "scenario", "label"] + MODEL_FEATURES
    ].copy()
    all_metrics: dict[str, Any] = {}

    for model_name in ("logistic_regression", "random_forest"):
        probabilities = np.full(len(data), np.nan, dtype=float)
        predictions = np.full(len(data), -1, dtype=int)
        per_run: dict[str, Any] = {}

        for run_id in sorted(data["run_id"].unique()):
            test_mask = data["run_id"].eq(run_id).to_numpy()
            train_mask = ~test_mask

            model = build_models(random_state)[model_name]
            model.fit(
                data.loc[train_mask, MODEL_FEATURES],
                data.loc[train_mask, "label"].astype(int),
            )

            fold_probabilities = model.predict_proba(
                data.loc[test_mask, MODEL_FEATURES]
            )[:, 1]
            fold_predictions = (fold_probabilities >= threshold).astype(int)
            probabilities[test_mask] = fold_probabilities
            predictions[test_mask] = fold_predictions

            per_run[str(run_id)] = metrics_from_predictions(
                labels=data.loc[test_mask, "label"].to_numpy(dtype=int),
                probabilities=fold_probabilities,
                predictions=fold_predictions,
                threshold=threshold,
            )

        if not np.isfinite(probabilities).all() or (predictions < 0).any():
            raise RuntimeError(f"{model_name} 有未完成的交叉驗證預測")

        aggregate = metrics_from_predictions(
            labels=data["label"].to_numpy(dtype=int),
            probabilities=probabilities,
            predictions=predictions,
            threshold=threshold,
        )
        all_metrics[model_name] = {
            "aggregate_out_of_fold": aggregate,
            "per_test_run": per_run,
        }
        prediction_output[f"{model_name}_probability"] = probabilities
        prediction_output[f"{model_name}_prediction"] = predictions

    return all_metrics, prediction_output


def print_metrics(name: str, metrics: dict[str, Any]) -> None:
    """用容易閱讀的格式顯示整體交叉驗證結果。"""
    aggregate = metrics["aggregate_out_of_fold"]
    matrix = aggregate["confusion_matrix"]
    print(f"\n=== {name}：逐輪交叉驗證整體結果 ===")
    print(f"ROC-AUC          : {aggregate['roc_auc']:.4f}")
    print(f"Average precision: {aggregate['average_precision']:.4f}")
    print(f"Accuracy         : {aggregate['accuracy']:.4f}")
    print(f"Attack precision : {aggregate['attack_precision']:.4f}")
    print(f"Attack recall    : {aggregate['attack_recall']:.4f}")
    print(f"Attack F1        : {aggregate['attack_f1']:.4f}")
    print(
        "Confusion matrix: "
        f"TN={matrix['true_negative']}, FP={matrix['false_positive']}, "
        f"FN={matrix['false_negative']}, TP={matrix['true_positive']}"
    )


def main() -> None:
    args = parse_args()
    if not 0.0 < args.threshold < 1.0:
        raise ValueError("--threshold 必須介於 0 和 1")

    original = validate_and_prepare(load_data(args.input))
    suspicious_before = find_suspicious_attack_groups(original)
    data, exclusions = apply_exclusions(original, args.exclude_run_scenario)
    suspicious_after = find_suspicious_attack_groups(data)

    if suspicious_after:
        descriptions = [
            f"{item['run_id']} / {item['scenario']} ({item['rows']} rows)"
            for item in suspicious_after
        ]
        raise ValueError(
            "仍有攻擊標籤但整段 SYN=0 的情境，請先確認資料或使用 "
            "--exclude-run-scenario 排除：" + "; ".join(descriptions)
        )

    validate_cross_validation_data(data)
    metrics, predictions = run_leave_one_run_out(
        data=data,
        threshold=args.threshold,
        random_state=args.random_state,
    )

    # 評估完成後重新建立模型，使用全部有效資料訓練部署版本。
    final_models = build_models(args.random_state)
    feature_scores: list[pd.DataFrame] = []
    for name, model in final_models.items():
        model.fit(data[MODEL_FEATURES], data["label"].astype(int))
        feature_scores.append(model_feature_scores(name, model))

    selected_model = final_models[args.final_model]
    created_at = datetime.now(timezone.utc).isoformat()
    quality_report = {
        "input_files": [str(path) for path in args.input],
        "original_rows": int(len(original)),
        "included_rows": int(len(data)),
        "excluded_rows": int(len(original) - len(data)),
        "suspicious_attack_groups_before_exclusion": suspicious_before,
        "applied_exclusions": exclusions,
        "suspicious_attack_groups_after_exclusion": suspicious_after,
    }
    evaluation = {
        "created_at_utc": created_at,
        "evaluation_mode": "leave_one_run_out",
        "row_count": int(len(data)),
        "run_count": int(data["run_id"].nunique()),
        "label_counts": {
            str(key): int(value)
            for key, value in data["label"].value_counts().sort_index().items()
        },
        "features": MODEL_FEATURES,
        "threshold": args.threshold,
        "models": metrics,
        "final_model": args.final_model,
        "final_fit_rows": int(len(data)),
        "quality_report_file": "data_quality_report.json",
    }
    model_bundle = {
        "model": selected_model,
        "model_name": args.final_model,
        "features": MODEL_FEATURES,
        "threshold": args.threshold,
        "created_at_utc": created_at,
        "training_rows": int(len(data)),
        "training_run_ids": sorted(data["run_id"].unique().tolist()),
        "evaluation_mode": "leave_one_run_out",
        "cross_validation_metrics": metrics[args.final_model],
        "data_quality_exclusions": exclusions,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_bundle, args.output_dir / "deployment_model.joblib")
    predictions.sort_values(["run_id", "timestamp"]).to_csv(
        args.output_dir / "oof_predictions.csv", index=False
    )
    pd.concat(feature_scores, ignore_index=True).to_csv(
        args.output_dir / "feature_scores.csv", index=False
    )

    clean_columns = [
        column
        for column in data.columns
        if column not in {"source_file", "split_group"}
    ]
    data[clean_columns].to_csv(
        args.output_dir / "training_data_clean.csv", index=False
    )
    with (args.output_dir / "evaluation.json").open(
        "w", encoding="utf-8"
    ) as handle:
        json.dump(evaluation, handle, ensure_ascii=False, indent=2)
    with (args.output_dir / "data_quality_report.json").open(
        "w", encoding="utf-8"
    ) as handle:
        json.dump(quality_report, handle, ensure_ascii=False, indent=2)

    for name, model_metrics in metrics.items():
        print_metrics(name, model_metrics)

    print("\n=== 最終模型 ===")
    print(f"模型類型 : {args.final_model}")
    print(f"訓練列數 : {len(data)}（全部有效資料）")
    print(f"排除列數 : {len(original) - len(data)}")
    print(f"模型檔案 : {args.output_dir / 'deployment_model.joblib'}")
    print(f"評估報告 : {args.output_dir / 'evaluation.json'}")
    print(f"品質報告 : {args.output_dir / 'data_quality_report.json'}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError, KeyError, RuntimeError) as error:
        print(f"錯誤：{error}", file=sys.stderr)
        raise SystemExit(2) from error
