#!/usr/bin/env python3
"""完整評估 SYN Flood 模型與告警規則。

這支程式不會重新訓練模型，而是使用已經產生的預測機率，同時比較：

1. 模型機率門檻。
2. 每秒最低純 SYN 封包數。
3. 最近 N 秒中至少 K 秒異常的持續性規則。

本機的 leave-one-run-out 預測用來檢查對新實驗輪次的表現；
外部 PCAP 預測只用來做誤報壓力測試與明顯攻擊的 sanity check。
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OOF = (
    SCRIPT_DIR
    / "output_multi_round_final_20261028"
    / "oof_predictions.csv"
)
DEFAULT_EXTERNAL = (
    SCRIPT_DIR
    / "external_pcap_evaluation_hard_normal"
    / "external_pcap_predictions.csv"
)
DEFAULT_OUTPUT = SCRIPT_DIR / "comprehensive_policy_evaluation"


@dataclass(frozen=True)
class Policy:
    """將模型分數轉成實際告警的規則。"""

    probability_threshold: float
    minimum_syn_packets: int
    required_hits: int
    window_seconds: int

    @property
    def name(self) -> str:
        threshold = format(self.probability_threshold, "g").replace(".", "p")
        return (
            f"prob_{threshold}__syn_{self.minimum_syn_packets}__"
            f"{self.required_hits}_of_{self.window_seconds}"
        )


def parse_number_list(raw: str, cast: type, option: str) -> list:
    """解析逗號分隔的數值參數，同時去除重複項目。"""
    try:
        values = [cast(value.strip()) for value in raw.split(",") if value.strip()]
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{option} 包含無效數值") from error
    if not values:
        raise argparse.ArgumentTypeError(f"{option} 不可為空")
    return list(dict.fromkeys(values))


def parse_persistence(raw: str) -> list[tuple[int, int]]:
    """將 1/1,2/3 轉成 (required_hits, window_seconds)。"""
    policies: list[tuple[int, int]] = []
    for value in raw.split(","):
        try:
            required, window = (int(part.strip()) for part in value.split("/", 1))
        except (TypeError, ValueError) as error:
            raise argparse.ArgumentTypeError(
                "--persistence 格式應為 1/1,2/3,3/5"
            ) from error
        if required < 1 or window < 1 or required > window:
            raise argparse.ArgumentTypeError(
                f"無效持續性規則 {required}/{window}：必須滿足 1 <= K <= N"
            )
        policies.append((required, window))
    return list(dict.fromkeys(policies))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="以本機多輪資料與外部 PCAP 完整比較 SYN Flood 告警規則。"
    )
    parser.add_argument("--oof-predictions", type=Path, default=DEFAULT_OOF)
    parser.add_argument("--external-predictions", type=Path, default=DEFAULT_EXTERNAL)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--oof-probability-column",
        default="logistic_regression_probability",
        help="OOF CSV 中的攻擊機率欄位",
    )
    parser.add_argument(
        "--external-probability-column",
        default="attack_probability",
        help="外部 PCAP CSV 中的攻擊機率欄位",
    )
    parser.add_argument(
        "--thresholds",
        default="0.5,0.7,0.9",
        help="要比較的機率門檻（預設 0.5,0.7,0.9）",
    )
    parser.add_argument(
        "--minimum-syn",
        default="0,2,5,10,20",
        help="要比較的每秒最低純 SYN 數（預設 0,2,5,10,20）",
    )
    parser.add_argument(
        "--persistence",
        default="1/1,2/3,3/5",
        help="K/N 持續性規則（預設 1/1,2/3,3/5）",
    )
    parser.add_argument(
        "--provisional-policy",
        default="0.5,5,2,3",
        help="詳細輸出的暫定規則：probability,min_syn,K,N",
    )
    return parser.parse_args()


def _require_columns(data: pd.DataFrame, columns: Iterable[str], path: Path) -> None:
    missing = sorted(set(columns) - set(data.columns))
    if missing:
        raise ValueError(f"{path} 缺少欄位：{', '.join(missing)}")


def _standardize_common(data: pd.DataFrame, path: Path) -> pd.DataFrame:
    """驗證兩種輸入共用的欄位與數值合理性。"""
    numeric_columns = [
        "label",
        "tcp_packets",
        "tcp_bytes",
        "syn_only_packets",
        "syn_ratio",
        "attack_probability",
    ]
    for column in numeric_columns:
        data[column] = pd.to_numeric(data[column], errors="coerce")

    if data[numeric_columns].isna().any().any():
        bad_columns = data[numeric_columns].columns[
            data[numeric_columns].isna().any()
        ].tolist()
        raise ValueError(f"{path} 有無法轉成數字的欄位：{bad_columns}")
    if not np.isfinite(data[numeric_columns].to_numpy(dtype=float)).all():
        raise ValueError(f"{path} 包含 inf 或 -inf")
    if not set(data["label"].astype(int).unique()).issubset({0, 1}):
        raise ValueError(f"{path} label 只能是 0 或 1")
    if (data[["tcp_packets", "tcp_bytes", "syn_only_packets"]] < 0).any().any():
        raise ValueError(f"{path} 封包或 bytes 統計不可為負數")
    if (data["syn_only_packets"] > data["tcp_packets"]).any():
        raise ValueError(f"{path} 存在 syn_only_packets > tcp_packets")
    if ((data["attack_probability"] < 0) | (data["attack_probability"] > 1)).any():
        raise ValueError(f"{path} 預測機率必須介於 0 與 1")

    data["label"] = data["label"].astype(int)
    data["timestamp_parsed"] = pd.to_datetime(
        data["timestamp_parsed"], errors="coerce", utc=True
    )
    if data["timestamp_parsed"].isna().any():
        raise ValueError(f"{path} 含有無法解析的 timestamp")
    if data.duplicated(["dataset", "sequence_id", "timestamp_parsed"]).any():
        raise ValueError(f"{path} 在同一測試序列中有重複秒數")

    return data.sort_values(
        ["dataset", "sequence_id", "timestamp_parsed"]
    ).reset_index(drop=True)


def load_oof(path: Path, probability_column: str) -> pd.DataFrame:
    """載入 leave-one-run-out 預測，確保每列都來自沒看過該輪的模型。"""
    if not path.is_file():
        raise FileNotFoundError(path)
    data = pd.read_csv(path)
    _require_columns(
        data,
        [
            "timestamp",
            "run_id",
            "scenario",
            "label",
            "tcp_packets",
            "tcp_bytes",
            "syn_only_packets",
            "syn_ratio",
            probability_column,
        ],
        path,
    )
    output = data[
        [
            "timestamp",
            "run_id",
            "scenario",
            "label",
            "tcp_packets",
            "tcp_bytes",
            "syn_only_packets",
            "syn_ratio",
            probability_column,
        ]
    ].copy()
    output = output.rename(columns={probability_column: "attack_probability"})
    output["dataset"] = "local_leave_one_run_out"
    output["source"] = output["run_id"].astype(str)
    output["sequence_id"] = (
        "local::"
        + output["run_id"].astype(str)
        + "::"
        + output["scenario"].astype(str)
    )
    output["timestamp_parsed"] = output["timestamp"]
    return _standardize_common(output, path)


def load_external(path: Path, probability_column: str) -> pd.DataFrame:
    """載入從外部 PCAP 整理出來的每秒預測。"""
    if not path.is_file():
        raise FileNotFoundError(path)
    data = pd.read_csv(path)
    _require_columns(
        data,
        [
            "timestamp",
            "source_pcap",
            "target_ip",
            "scenario",
            "label",
            "tcp_packets",
            "tcp_bytes",
            "syn_only_packets",
            "syn_ratio",
            probability_column,
        ],
        path,
    )
    output = data[
        [
            "timestamp",
            "source_pcap",
            "target_ip",
            "scenario",
            "label",
            "tcp_packets",
            "tcp_bytes",
            "syn_only_packets",
            "syn_ratio",
            probability_column,
        ]
    ].copy()
    output = output.rename(columns={probability_column: "attack_probability"})
    output["dataset"] = "external_pcap"
    output["source"] = output["source_pcap"].astype(str)
    output["sequence_id"] = (
        "external::"
        + output["source_pcap"].astype(str)
        + "::"
        + output["target_ip"].astype(str)
        + "::"
        + output["scenario"].astype(str)
    )
    output["timestamp_parsed"] = output["timestamp"]
    return _standardize_common(output, path)


def build_policies(
    thresholds: list[float],
    minimum_syn: list[int],
    persistence: list[tuple[int, int]],
) -> list[Policy]:
    if any(not 0 < value < 1 for value in thresholds):
        raise ValueError("所有機率門檻都必須介於 0 與 1")
    if any(value < 0 for value in minimum_syn):
        raise ValueError("最低 SYN 數不可為負數")
    return [
        Policy(threshold, syn_count, required, window)
        for threshold in thresholds
        for syn_count in minimum_syn
        for required, window in persistence
    ]


def parse_provisional_policy(raw: str) -> Policy:
    try:
        threshold_text, syn_text, required_text, window_text = raw.split(",")
        policy = Policy(
            float(threshold_text),
            int(syn_text),
            int(required_text),
            int(window_text),
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "--provisional-policy 格式應為 probability,min_syn,K,N"
        ) from error
    if not 0 < policy.probability_threshold < 1:
        raise ValueError("暫定規則的機率門檻必須介於 0 與 1")
    if (
        policy.minimum_syn_packets < 0
        or policy.required_hits < 1
        or policy.required_hits > policy.window_seconds
    ):
        raise ValueError("暫定規則的 SYN 下限或 K/N 無效")
    return policy


def apply_policy(data: pd.DataFrame, policy: Policy) -> pd.DataFrame:
    """在各自獨立的情境內套用 K-of-N，不讓前一情境影響下一情境。"""
    output = data.copy()
    output["candidate"] = (
        output["attack_probability"].ge(policy.probability_threshold)
        & output["syn_only_packets"].ge(policy.minimum_syn_packets)
    )
    output["candidate_hits_in_window"] = 0
    output["predicted_label"] = 0

    for _, indexes in output.groupby("sequence_id", sort=False).groups.items():
        ordered_indexes = list(indexes)
        recent_hits: list[int] = []
        previous_timestamp: pd.Timestamp | None = None
        for index in ordered_indexes:
            timestamp = output.at[index, "timestamp_parsed"]
            if (
                previous_timestamp is not None
                and (timestamp - previous_timestamp).total_seconds() > 1.5
            ):
                recent_hits.clear()
            recent_hits.append(int(output.at[index, "candidate"]))
            if len(recent_hits) > policy.window_seconds:
                recent_hits.pop(0)
            hits = sum(recent_hits)
            output.at[index, "candidate_hits_in_window"] = hits
            output.at[index, "predicted_label"] = int(hits >= policy.required_hits)
            previous_timestamp = timestamp

    output["predicted_label"] = output["predicted_label"].astype(int)
    output["policy_name"] = policy.name
    return output


def safe_divide(numerator: int | float, denominator: int | float) -> float | None:
    return float(numerator / denominator) if denominator else None


def _count_episodes(masked: pd.DataFrame) -> int:
    """計算同一序列中連續的事件段數。"""
    episodes = 0
    for _, group in masked.groupby("sequence_id", sort=False):
        previous: pd.Timestamp | None = None
        for timestamp in group.sort_values("timestamp_parsed")["timestamp_parsed"]:
            if previous is None or (timestamp - previous).total_seconds() > 1.5:
                episodes += 1
            previous = timestamp
    return episodes


def attack_event_metrics(data: pd.DataFrame) -> dict[str, Any]:
    """以連續 label=1 視為一次攻擊，計算事件偵測率與延遲。"""
    event_count = 0
    detected_count = 0
    delays: list[float] = []

    for _, sequence in data.groupby("sequence_id", sort=False):
        sequence = sequence.sort_values("timestamp_parsed")
        current_indexes: list[int] = []
        previous_timestamp: pd.Timestamp | None = None

        def finish_event() -> None:
            nonlocal event_count, detected_count
            if not current_indexes:
                return
            event_count += 1
            event = sequence.loc[current_indexes]
            alerted = event.loc[event["predicted_label"].eq(1)]
            if not alerted.empty:
                detected_count += 1
                delay = (
                    alerted.iloc[0]["timestamp_parsed"]
                    - event.iloc[0]["timestamp_parsed"]
                ).total_seconds()
                delays.append(float(delay))

        for index, row in sequence.iterrows():
            timestamp = row["timestamp_parsed"]
            contiguous = (
                previous_timestamp is not None
                and (timestamp - previous_timestamp).total_seconds() <= 1.5
            )
            if int(row["label"]) == 1:
                if current_indexes and not contiguous:
                    finish_event()
                    current_indexes = []
                current_indexes.append(index)
            elif current_indexes:
                finish_event()
                current_indexes = []
            previous_timestamp = timestamp
        finish_event()

    return {
        "attack_events": event_count,
        "detected_attack_events": detected_count,
        "event_detection_rate": safe_divide(detected_count, event_count),
        "mean_detection_delay_seconds": (
            float(np.mean(delays)) if delays else None
        ),
        "max_detection_delay_seconds": (
            float(np.max(delays)) if delays else None
        ),
    }


def evaluate(data: pd.DataFrame, policy: Policy, dataset_name: str) -> dict[str, Any]:
    labels = data["label"].to_numpy(dtype=int)
    predictions = data["predicted_label"].to_numpy(dtype=int)
    true_negative = int(((labels == 0) & (predictions == 0)).sum())
    false_positive = int(((labels == 0) & (predictions == 1)).sum())
    false_negative = int(((labels == 1) & (predictions == 0)).sum())
    true_positive = int(((labels == 1) & (predictions == 1)).sum())

    attack_precision = safe_divide(true_positive, true_positive + false_positive)
    attack_recall = safe_divide(true_positive, true_positive + false_negative)
    attack_f1 = (
        2 * attack_precision * attack_recall / (attack_precision + attack_recall)
        if attack_precision is not None
        and attack_recall is not None
        and attack_precision + attack_recall
        else None
    )
    normal_recall = safe_divide(true_negative, true_negative + false_positive)
    balanced_accuracy = (
        (normal_recall + attack_recall) / 2
        if normal_recall is not None and attack_recall is not None
        else None
    )

    normal = data.loc[data["label"].eq(0)]
    pure_syn_normal = normal.loc[normal["syn_only_packets"].gt(0)]
    low_syn_normal = normal.loc[normal["syn_only_packets"].between(1, 4)]
    false_alert_rows = normal.loc[normal["predicted_label"].eq(1)]
    false_alert_episodes = _count_episodes(false_alert_rows)
    normal_hours = len(normal) / 3600
    event_metrics = attack_event_metrics(data)

    return {
        "dataset": dataset_name,
        "policy_name": policy.name,
        **asdict(policy),
        "seconds": int(len(data)),
        "normal_seconds": int((labels == 0).sum()),
        "attack_seconds": int((labels == 1).sum()),
        "accuracy": safe_divide(true_negative + true_positive, len(data)),
        "balanced_accuracy": balanced_accuracy,
        "attack_precision": attack_precision,
        "attack_recall": attack_recall,
        "attack_f1": attack_f1,
        "false_positive_rate": safe_divide(
            false_positive, false_positive + true_negative
        ),
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_positive": true_positive,
        "normal_pure_syn_seconds": int(len(pure_syn_normal)),
        "normal_pure_syn_false_positives": int(
            pure_syn_normal["predicted_label"].sum()
        ),
        "normal_pure_syn_false_positive_rate": safe_divide(
            int(pure_syn_normal["predicted_label"].sum()), len(pure_syn_normal)
        ),
        "normal_low_syn_1_to_4_seconds": int(len(low_syn_normal)),
        "normal_low_syn_1_to_4_false_positives": int(
            low_syn_normal["predicted_label"].sum()
        ),
        "false_alert_episodes": false_alert_episodes,
        "false_alert_episodes_per_normal_hour": safe_divide(
            false_alert_episodes, normal_hours
        ),
        **event_metrics,
    }


def scenario_breakdown(data: pd.DataFrame, policy: Policy) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for (dataset, scenario, label), group in data.groupby(
        ["dataset", "scenario", "label"], sort=True, observed=True
    ):
        prediction_count = int(group["predicted_label"].sum())
        rows.append(
            {
                "dataset": dataset,
                "policy_name": policy.name,
                "scenario": scenario,
                "label": int(label),
                "seconds": int(len(group)),
                "predicted_attack_seconds": prediction_count,
                "correct_seconds": int(
                    group["predicted_label"].eq(group["label"]).sum()
                ),
                "prediction_rate": safe_divide(prediction_count, len(group)),
            }
        )
    return rows


def quality_summary(data: pd.DataFrame) -> dict[str, Any]:
    return {
        "seconds": int(len(data)),
        "sequences": int(data["sequence_id"].nunique()),
        "label_counts": {
            str(int(label)): int(count)
            for label, count in data["label"].value_counts().sort_index().items()
        },
        "normal_pure_syn_seconds": int(
            (data["label"].eq(0) & data["syn_only_packets"].gt(0)).sum()
        ),
        "normal_low_syn_1_to_4_seconds": int(
            (
                data["label"].eq(0)
                & data["syn_only_packets"].between(1, 4)
            ).sum()
        ),
        "attack_syn_range": (
            {
                "minimum": int(data.loc[data["label"].eq(1), "syn_only_packets"].min()),
                "maximum": int(data.loc[data["label"].eq(1), "syn_only_packets"].max()),
            }
            if data["label"].eq(1).any()
            else None
        ),
    }


def _format_metric(value: Any) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "N/A"
    if isinstance(value, (float, np.floating)):
        return f"{float(value):.4f}"
    return str(value)


def write_markdown_summary(
    path: Path,
    comparison: pd.DataFrame,
    policy_names: list[str],
    quality: dict[str, Any],
    provisional: Policy,
) -> None:
    """產生不必開 JSON 也能閱讀的實驗摘要。"""
    selected = comparison.loc[comparison["policy_name"].isin(policy_names)].copy()
    columns = [
        "dataset",
        "policy_name",
        "false_positive",
        "false_negative",
        "attack_recall",
        "attack_f1",
        "normal_pure_syn_false_positives",
        "false_alert_episodes",
        "event_detection_rate",
        "mean_detection_delay_seconds",
    ]

    lines = [
        "# SYN Flood 完整測試摘要",
        "",
        f"產生時間（UTC）：{datetime.now(timezone.utc).isoformat()}",
        "",
        "## 資料範圍",
        "",
    ]
    for dataset, details in quality.items():
        lines.append(
            f"- `{dataset}`：{details['seconds']} 秒，"
            f"正常 {details['label_counts'].get('0', 0)} 秒，"
            f"攻擊 {details['label_counts'].get('1', 0)} 秒，"
            f"正常但有純 SYN {details['normal_pure_syn_seconds']} 秒。"
        )

    lines.extend(
        [
            "",
            "## 重點規則比較",
            "",
            "| " + " | ".join(columns) + " |",
            "| " + " | ".join(["---"] * len(columns)) + " |",
        ]
    )
    for _, row in selected[columns].iterrows():
        lines.append("| " + " | ".join(_format_metric(row[column]) for column in columns) + " |")

    lines.extend(
        [
            "",
            "## 暫定策略",
            "",
            f"`{provisional.name}` 表示：模型機率至少 "
            f"{provisional.probability_threshold}，且當秒至少 "
            f"{provisional.minimum_syn_packets} 個純 SYN，最近 "
            f"{provisional.window_seconds} 秒中有 {provisional.required_hits} 秒符合才告警。",
            "",
            "這是用來繼續實驗的暫定規則，不是已證明可通用的生產環境門檻。",
            "",
            "## 解讀限制",
            "",
            "- 外部 SYN Flood PCAP 不到 1 秒，只有一個攻擊 bucket，只能驗證明顯攻擊能否被單秒規則抓到。",
            "- `2_of_3` 與 `3_of_5` 必須有連續多秒的外部攻擊資料，才能評估真實偵測率與延遲。",
            "- 外部 PCAP 現在已被用來觀察問題，若根據它調整門檻，就不能再把它當成未看過的最終測試集。",
            "- 尚需補充正常低量 SYN、短暫尖峰、封包丟失與低速 SYN Flood 等獨立情境。",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    thresholds = parse_number_list(args.thresholds, float, "--thresholds")
    minimum_syn = parse_number_list(args.minimum_syn, int, "--minimum-syn")
    persistence = parse_persistence(args.persistence)
    policies = build_policies(thresholds, minimum_syn, persistence)
    provisional = parse_provisional_policy(args.provisional_policy)
    if provisional not in policies:
        policies.append(provisional)

    local = load_oof(args.oof_predictions, args.oof_probability_column)
    external = load_external(
        args.external_predictions, args.external_probability_column
    )
    all_data = pd.concat([local, external], ignore_index=True)
    datasets = {
        "local_leave_one_run_out": local,
        "external_pcap": external,
    }

    comparison_rows: list[dict[str, Any]] = []
    breakdown_rows: list[dict[str, Any]] = []
    provisional_predictions: pd.DataFrame | None = None

    for policy in policies:
        evaluated_all = apply_policy(all_data, policy)
        for dataset_name, indexes in evaluated_all.groupby("dataset").groups.items():
            evaluated_dataset = evaluated_all.loc[list(indexes)].copy()
            comparison_rows.append(evaluate(evaluated_dataset, policy, dataset_name))
        breakdown_rows.extend(scenario_breakdown(evaluated_all, policy))
        if policy == provisional:
            provisional_predictions = evaluated_all.copy()

    comparison = pd.DataFrame(comparison_rows).sort_values(
        ["dataset", "probability_threshold", "minimum_syn_packets", "window_seconds", "required_hits"]
    )
    breakdown = pd.DataFrame(breakdown_rows).sort_values(
        ["dataset", "policy_name", "scenario", "label"]
    )
    if provisional_predictions is None:
        raise RuntimeError("沒有產生暫定策略的預測")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    comparison_path = args.output_dir / "policy_comparison.csv"
    breakdown_path = args.output_dir / "scenario_breakdown.csv"
    predictions_path = args.output_dir / "provisional_policy_predictions.csv"
    report_path = args.output_dir / "comprehensive_evaluation.json"
    summary_path = args.output_dir / "SUMMARY.md"

    comparison.to_csv(comparison_path, index=False)
    breakdown.to_csv(breakdown_path, index=False)
    prediction_columns = [
        "dataset",
        "source",
        "sequence_id",
        "timestamp",
        "scenario",
        "label",
        "tcp_packets",
        "tcp_bytes",
        "syn_only_packets",
        "syn_ratio",
        "attack_probability",
        "candidate",
        "candidate_hits_in_window",
        "predicted_label",
        "policy_name",
    ]
    provisional_predictions[prediction_columns].to_csv(predictions_path, index=False)

    quality = {name: quality_summary(data) for name, data in datasets.items()}
    baseline = Policy(0.5, 0, 1, 1)
    volume_guard = Policy(0.5, 5, 1, 1)
    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "diagnostic policy comparison; no model retraining",
        "inputs": {
            "oof_predictions": str(args.oof_predictions.resolve()),
            "external_predictions": str(args.external_predictions.resolve()),
        },
        "data_quality": quality,
        "policies_tested": len(policies),
        "provisional_policy": asdict(provisional) | {"name": provisional.name},
        "important_policies": {
            "baseline": asdict(baseline) | {"name": baseline.name},
            "single_second_volume_guard": asdict(volume_guard)
            | {"name": volume_guard.name},
            "provisional_sustained_rule": asdict(provisional)
            | {"name": provisional.name},
        },
        "limitations": [
            "The external SYN-Flood capture contributes only one positive second.",
            "Persistence rules cannot be externally validated with a one-second attack capture.",
            "The external PCAP is now diagnostic/development data, not an untouched final test set.",
            "The current local normal data has no normal pure-SYN seconds below 10 packets; more hard normal scenarios are required.",
        ],
        "output_files": {
            "policy_comparison": comparison_path.name,
            "scenario_breakdown": breakdown_path.name,
            "provisional_predictions": predictions_path.name,
            "human_summary": summary_path.name,
        },
    }
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    important_names = [baseline.name, volume_guard.name, provisional.name]
    write_markdown_summary(
        summary_path, comparison, important_names, quality, provisional
    )

    print(f"已測試 {len(policies)} 種告警策略。")
    print(f"策略比較：{comparison_path}")
    print(f"情境分析：{breakdown_path}")
    print(f"暫定規則每秒結果：{predictions_path}")
    print(f"人類可讀摘要：{summary_path}")

    selected = comparison.loc[comparison["policy_name"].isin(important_names)]
    for dataset_name, group in selected.groupby("dataset", sort=True):
        print(f"\n=== {dataset_name} ===")
        for _, row in group.iterrows():
            print(
                f"{row['policy_name']}: "
                f"FP={int(row['false_positive'])}, "
                f"FN={int(row['false_negative'])}, "
                f"attack_recall={_format_metric(row['attack_recall'])}, "
                f"false_alert_episodes={int(row['false_alert_episodes'])}"
            )


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError, KeyError, RuntimeError) as error:
        print(f"錯誤：{error}", file=sys.stderr)
        raise SystemExit(2) from error
