#!/usr/bin/env python3
"""將 Mac 流量產生器的情境時間與 Ubuntu tcp_stats.csv 合併。"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="將 tcp_stats.csv 依情境時間加上 SYN Flood 標籤。"
    )
    parser.add_argument("--stats", required=True, type=Path, help="tcp_stats.csv")
    parser.add_argument(
        "--labels",
        required=True,
        nargs="+",
        type=Path,
        help="一個或多個 run_experiment.sh 產生的 scenario_labels.csv",
    )
    parser.add_argument("--output", required=True, type=Path, help="輸出 CSV")
    parser.add_argument(
        "--boundary-seconds",
        type=int,
        default=3,
        help="排除每個情境頭尾幾秒（預設：3）",
    )
    parser.add_argument(
        "--keep-unlabeled",
        action="store_true",
        help="保留預熱、cooldown 和未對齊的列（label 留空）",
    )
    parser.add_argument(
        "--include-diagnostic",
        action="store_true",
        help=(
            "額外保留 scenario 名稱以 diagnostic_ 開頭的 label=-1 區段；"
            "只供預測觀察，不可直接用來訓練"
        ),
    )
    parser.add_argument(
        "--include-evaluation-only",
        action="store_true",
        help=(
            "使用 include_in_evaluation=1 的 final holdout 區段；"
            "不需要、也不會把 include_in_training 改成 1"
        ),
    )
    parser.add_argument(
        "--exclude-scenario",
        action="append",
        default=[],
        help="排除指定 scenario，可重複使用；原始標籤檔不會被修改",
    )
    return parser.parse_args()


def load_intervals(
    paths: list[Path],
    boundary_seconds: int,
    include_diagnostic: bool = False,
    include_evaluation_only: bool = False,
    excluded_scenarios: set[str] | None = None,
) -> list[dict[str, object]]:
    intervals: list[dict[str, object]] = []
    excluded_scenarios = excluded_scenarios or set()

    for path in paths:
        with path.open(newline="", encoding="utf-8-sig") as label_file:
            reader = csv.DictReader(label_file)
            required = {
                "run_id",
                "scenario",
                "label",
                "include_in_training",
                "start_epoch",
                "end_epoch",
                "command_status",
            }
            missing = required.difference(reader.fieldnames or [])
            if missing:
                raise ValueError(
                    f"{path} 缺少欄位: {', '.join(sorted(missing))}"
                )
            if (
                include_evaluation_only
                and "include_in_evaluation" not in (reader.fieldnames or [])
            ):
                raise ValueError(
                    f"{path} 缺少 include_in_evaluation 欄位"
                )

            for row in reader:
                if row["scenario"] in excluded_scenarios:
                    continue
                successful = row["command_status"] == "0"
                training_interval = row["include_in_training"] == "1"
                evaluation_interval = (
                    include_evaluation_only
                    and row.get("include_in_evaluation") == "1"
                )
                diagnostic_interval = (
                    include_diagnostic
                    and row["scenario"].startswith("diagnostic_")
                    and row["label"] == "-1"
                )
                if not successful or not (
                    training_interval or evaluation_interval or diagnostic_interval
                ):
                    continue

                start = int(row["start_epoch"]) + boundary_seconds
                end = int(row["end_epoch"]) - boundary_seconds
                if start > end:
                    continue

                intervals.append(
                    {
                        "start": start,
                        "end": end,
                        "run_id": row["run_id"],
                        "scenario": row["scenario"],
                        "label": row["label"],
                    }
                )

    intervals.sort(key=lambda item: int(item["start"]))
    return intervals


def timestamp_to_epoch(timestamp: str) -> int:
    # tcpip_stats.py 使用 Ubuntu 的本地時間，因此這裡也用
    # 執行 merge_labels.py 的 Ubuntu 本地時區來解讀。
    return int(datetime.strptime(timestamp, TIMESTAMP_FORMAT).timestamp())


def find_interval(epoch: int, intervals: list[dict[str, object]]) -> dict[str, object] | None:
    matches = [
        interval
        for interval in intervals
        if int(interval["start"]) <= epoch <= int(interval["end"])
    ]

    if len(matches) > 1:
        names = ", ".join(str(item["scenario"]) for item in matches)
        raise ValueError(f"時間 {epoch} 同時落入多個情境: {names}")

    return matches[0] if matches else None


def main() -> None:
    args = parse_args()

    if args.boundary_seconds < 0:
        raise ValueError("--boundary-seconds 不可為負數")
    if not args.stats.is_file():
        raise FileNotFoundError(args.stats)
    missing_labels = [path for path in args.labels if not path.is_file()]
    if missing_labels:
        raise FileNotFoundError(
            "找不到標籤檔: " + ", ".join(str(path) for path in missing_labels)
        )

    intervals = load_intervals(
        args.labels,
        args.boundary_seconds,
        include_diagnostic=args.include_diagnostic,
        include_evaluation_only=args.include_evaluation_only,
        excluded_scenarios=set(args.exclude_scenario),
    )
    if not intervals:
        raise ValueError("標籤檔中沒有可用的成功情境")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter()
    input_rows = 0
    output_rows = 0

    with args.stats.open(newline="", encoding="utf-8-sig") as stats_file:
        reader = csv.DictReader(stats_file)
        if not reader.fieldnames or "timestamp" not in reader.fieldnames:
            raise ValueError("stats CSV 缺少 timestamp 欄位")

        output_fields = list(reader.fieldnames) + ["run_id", "scenario", "label"]
        with args.output.open("w", newline="", encoding="utf-8") as output_file:
            writer = csv.DictWriter(output_file, fieldnames=output_fields)
            writer.writeheader()

            for row in reader:
                input_rows += 1
                epoch = timestamp_to_epoch(row["timestamp"])
                interval = find_interval(epoch, intervals)

                if interval is None:
                    if not args.keep_unlabeled:
                        continue
                    row.update({"run_id": "", "scenario": "", "label": ""})
                    counts["unlabeled"] += 1
                else:
                    row.update(
                        {
                            "run_id": str(interval["run_id"]),
                            "scenario": str(interval["scenario"]),
                            "label": str(interval["label"]),
                        }
                    )
                    counts[str(interval["label"])] += 1

                writer.writerow(row)
                output_rows += 1

    print(f"輸入列數 : {input_rows}")
    print(f"輸出列數 : {output_rows}")
    print(f"正常 label=0 : {counts['0']}")
    print(f"SYN  label=1 : {counts['1']}")
    if args.include_diagnostic:
        print(f"診斷 label=-1: {counts['-1']}（不可直接用來訓練）")
    if args.keep_unlabeled:
        print(f"未標籤      : {counts['unlabeled']}")
    print(f"輸出檔案 : {args.output}")


if __name__ == "__main__":
    main()
