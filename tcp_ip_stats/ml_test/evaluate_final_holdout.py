#!/usr/bin/env python3
"""Evaluate the frozen runtime model on one independent labelled holdout run."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from syn_flood_runtime import LogisticRuntimeModel, SynFloodDetector


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument(
        "--runtime-model",
        type=Path,
        default=PROJECT_DIR / "model_handoff/syn-window-v1/runtime_model.json",
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def safe_divide(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def metrics(rows: list[dict], prediction_field: str) -> dict:
    tn = fp = fn = tp = 0
    for row in rows:
        label = int(row["label"])
        prediction = int(row[prediction_field])
        if label == 0 and prediction == 0:
            tn += 1
        elif label == 0 and prediction == 1:
            fp += 1
        elif label == 1 and prediction == 0:
            fn += 1
        else:
            tp += 1
    return {
        "rows": len(rows),
        "normal_rows": tn + fp,
        "attack_rows": tp + fn,
        "accuracy": safe_divide(tn + tp, len(rows)),
        "attack_precision": safe_divide(tp, tp + fp),
        "attack_recall": safe_divide(tp, tp + fn),
        "attack_f1": safe_divide(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": safe_divide(fp, fp + tn),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def load_rows(path: Path, model_features: list[str]) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    required = {
        "timestamp",
        "tcp_packets",
        "tcp_bytes",
        "syn_only_packets",
        "run_id",
        "scenario",
        "label",
    }
    if "established_connections" in model_features:
        required.add("established_connections")
    if "active_source_ips" in model_features:
        required.add("active_source_ips")
    if "active_ips_per_established_connection" in model_features:
        required.update({"active_source_ips", "established_connections"})
    if not rows:
        raise ValueError("holdout CSV is empty")
    missing = required.difference(rows[0])
    if missing:
        raise ValueError(f"missing columns: {', '.join(sorted(missing))}")

    parsed: list[dict] = []
    for row in rows:
        item = dict(row)
        item["timestamp_parsed"] = datetime.strptime(
            row["timestamp"], "%Y-%m-%d %H:%M:%S"
        )
        numeric_fields = ["tcp_packets", "tcp_bytes", "syn_only_packets", "label"]
        if "established_connections" in row:
            numeric_fields.append("established_connections")
        if "active_source_ips" in row:
            numeric_fields.append("active_source_ips")
        for field in numeric_fields:
            item[field] = int(float(row[field]))
        item.setdefault("established_connections", 0)
        item.setdefault("active_source_ips", 0)
        if item["label"] not in (0, 1):
            raise ValueError("final holdout may contain only label 0 or 1")
        if item["syn_only_packets"] > item["tcp_packets"]:
            raise ValueError("syn_only_packets cannot exceed tcp_packets")
        parsed.append(item)
    return sorted(
        parsed,
        key=lambda row: (row["run_id"], row["scenario"], row["timestamp_parsed"]),
    )


def evaluate(rows: list[dict], model_path: Path) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[(row["run_id"], row["scenario"])].append(row)

    output: list[dict] = []
    for _, scenario_rows in grouped.items():
        detector = SynFloodDetector.load(model_path)
        previous_time: datetime | None = None
        for row in scenario_rows:
            timestamp = row["timestamp_parsed"]
            if previous_time is not None and (timestamp - previous_time).total_seconds() > 1.5:
                detector = SynFloodDetector.load(model_path)
            probability = detector.model.predict_probability(
                tcp_packets=row["tcp_packets"],
                tcp_bytes=row["tcp_bytes"],
                syn_only_packets=row["syn_only_packets"],
                established_connections=row["established_connections"],
                active_source_ips=row["active_source_ips"],
            )
            detection = detector.evaluate(
                tcp_packets=row["tcp_packets"],
                tcp_bytes=row["tcp_bytes"],
                syn_only_packets=row["syn_only_packets"],
                established_connections=row["established_connections"],
                active_source_ips=row["active_source_ips"],
                interval_seconds=1.0,
            )
            enriched = {
                key: value
                for key, value in row.items()
                if key != "timestamp_parsed"
            }
            enriched.update(
                {
                    "attack_probability": probability,
                    "raw_model_prediction": int(
                        probability >= detector.probability_threshold
                    ),
                    "volume_guard_prediction": int(detection.candidate),
                    "runtime_policy_prediction": int(detection.attack_active),
                    "runtime_status": detection.status,
                    "recent_hits": detection.recent_hits,
                    "recent_window_size": detection.recent_window_size,
                }
            )
            output.append(enriched)
            previous_time = timestamp
    return output


def scenario_report(rows: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        groups[(row["run_id"], row["scenario"])].append(row)

    report = []
    for (run_id, scenario), group in groups.items():
        label = int(group[0]["label"])
        policy_hits = sum(int(row["runtime_policy_prediction"]) for row in group)
        first_hit = next(
            (
                index
                for index, row in enumerate(group)
                if int(row["runtime_policy_prediction"]) == 1
            ),
            None,
        )
        report.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "label": label,
                "seconds": len(group),
                "mean_tcp_packets": sum(row["tcp_packets"] for row in group) / len(group),
                "mean_syn_only_packets": sum(
                    row["syn_only_packets"] for row in group
                )
                / len(group),
                "raw_positive_seconds": sum(
                    int(row["raw_model_prediction"]) for row in group
                ),
                "policy_positive_seconds": policy_hits,
                "event_detected": bool(policy_hits) if label == 1 else None,
                "first_policy_hit_offset_seconds": first_hit if label == 1 else None,
            }
        )
    return sorted(report, key=lambda item: (item["run_id"], item["scenario"]))


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    if not args.runtime_model.is_file():
        raise FileNotFoundError(args.runtime_model)
    model = LogisticRuntimeModel.load(args.runtime_model)
    rows = load_rows(args.input, model.features)
    predictions = evaluate(rows, args.runtime_model)
    scenarios = scenario_report(predictions)
    model_config = model.config

    attack_scenarios = [item for item in scenarios if item["label"] == 1]
    summary = {
        "purpose": "independent final holdout; no model retraining",
        "input": str(args.input.resolve()),
        "runtime_model": str(args.runtime_model.resolve()),
        "runtime_policy": {
            key: model_config[key]
            for key in (
                "probability_threshold",
                "minimum_syn_packets",
                "persistence_required_hits",
                "persistence_window_seconds",
                "clear_after_normal_seconds",
            )
        },
        "raw_model": metrics(predictions, "raw_model_prediction"),
        "model_plus_volume_guard": metrics(predictions, "volume_guard_prediction"),
        "full_runtime_policy": metrics(predictions, "runtime_policy_prediction"),
        "attack_event_detection": {
            "attack_scenarios": len(attack_scenarios),
            "detected_scenarios": sum(bool(item["event_detected"]) for item in attack_scenarios),
            "event_detection_rate": safe_divide(
                sum(bool(item["event_detected"]) for item in attack_scenarios),
                len(attack_scenarios),
            ),
        },
        "scenarios": scenarios,
        "limitations": [
            "All traffic is generated on one host and one Docker network.",
            "Spoofed source IPs test packet diversity, not independent physical attackers.",
            "Labels describe the configured traffic scenario, not proven service exhaustion.",
        ],
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "predictions.csv", predictions)
    write_csv(args.output_dir / "scenario_summary.csv", scenarios)
    with (args.output_dir / "evaluation.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    policy = summary["full_runtime_policy"]
    event = summary["attack_event_detection"]
    report = [
        "# 獨立 final holdout 測試結果",
        "",
        "這份資料只用於最後評估，不得重新加入訓練。",
        "",
        f"- 有效秒數：{policy['rows']}",
        f"- Accuracy：{policy['accuracy']:.4f}" if policy["accuracy"] is not None else "- Accuracy：n.a.",
        f"- 攻擊 Precision：{policy['attack_precision']:.4f}" if policy["attack_precision"] is not None else "- 攻擊 Precision：n.a.",
        f"- 攻擊 Recall：{policy['attack_recall']:.4f}" if policy["attack_recall"] is not None else "- 攻擊 Recall：n.a.",
        f"- 攻擊 F1：{policy['attack_f1']:.4f}" if policy["attack_f1"] is not None else "- 攻擊 F1：n.a.",
        f"- Confusion matrix：{policy['confusion_matrix']}",
        f"- 攻擊情境偵測：{event['detected_scenarios']}/{event['attack_scenarios']}",
        "",
        "限制：多來源 IP 是同一台主機的 hping3 Container 所產生，不是多台獨立實體攻擊機。",
    ]
    (args.output_dir / "SUMMARY.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    print(json.dumps({"full_runtime_policy": policy, "attack_event_detection": event}, ensure_ascii=False, indent=2))
    print(f"完整報告：{(args.output_dir / 'evaluation.json').resolve()}")


if __name__ == "__main__":
    main()
