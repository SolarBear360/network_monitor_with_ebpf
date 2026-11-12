#!/usr/bin/env python3
"""syn-window-v1 推論範例。

可以接收單筆一秒 bucket，或讀取包含多筆 bucket 的 CSV。
這支程式不會阻擋封包，只輸出機率與暫定告警結果。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


RAW_FEATURES = ["tcp_packets", "tcp_bytes", "syn_only_packets"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="使用 syn-window-v1 判斷一秒 TCP bucket。")
    parser.add_argument(
        "--model",
        type=Path,
        default=Path(__file__).with_name("model.joblib"),
        help="模型檔案（預設為同資料夾的 model.joblib）",
    )
    parser.add_argument("--input-csv", type=Path, help="批次輸入 CSV")
    parser.add_argument("--output-csv", type=Path, help="批次預測輸出 CSV")
    parser.add_argument("--tcp-packets", type=int, help="一秒內的入站 TCP 封包數")
    parser.add_argument("--tcp-bytes", type=int, help="一秒內的入站 TCP bytes")
    parser.add_argument(
        "--syn-only-packets",
        type=int,
        help="一秒內入站 SYN=1, ACK=0 的封包數",
    )
    parser.add_argument(
        "--minimum-syn",
        type=int,
        default=5,
        help="暫定告警規則的最少純 SYN 數（預設 5）",
    )
    return parser.parse_args()


def prepare_features(data: pd.DataFrame, model_features: list[str]) -> pd.DataFrame:
    """驗證輸入並計算模型需要的 syn_ratio。"""
    missing = sorted(set(RAW_FEATURES) - set(data.columns))
    if missing:
        raise ValueError("缺少輸入欄位：" + ", ".join(missing))

    prepared = data.copy()
    for column in RAW_FEATURES:
        prepared[column] = pd.to_numeric(prepared[column], errors="raise")

    if (prepared[RAW_FEATURES] < 0).any().any():
        raise ValueError("封包數與 bytes 不可為負數")
    if (prepared["syn_only_packets"] > prepared["tcp_packets"]).any():
        raise ValueError("syn_only_packets 不可大於 tcp_packets")

    prepared["syn_ratio"] = np.divide(
        prepared["syn_only_packets"],
        prepared["tcp_packets"],
        out=np.zeros(len(prepared), dtype=float),
        where=prepared["tcp_packets"].to_numpy() > 0,
    )
    return prepared[model_features]


def predict_buckets(
    data: pd.DataFrame,
    bundle: dict,
    minimum_syn: int,
) -> pd.DataFrame:
    """輸出模型機率、模型原始判斷與暫定告警規則。"""
    model_features = list(bundle["features"])
    features = prepare_features(data, model_features)
    probability = bundle["model"].predict_proba(features)[:, 1]
    threshold = float(bundle.get("threshold", 0.5))

    output = data.copy()
    output["syn_ratio"] = features["syn_ratio"].to_numpy()
    output["attack_probability"] = probability
    output["model_positive"] = probability >= threshold
    output["alert"] = output["model_positive"] & (
        output["syn_only_packets"] >= minimum_syn
    )
    output["model_threshold"] = threshold
    output["minimum_syn"] = minimum_syn
    return output


def main() -> None:
    args = parse_args()
    if args.minimum_syn < 0:
        raise ValueError("--minimum-syn 不可為負數")
    if not args.model.is_file():
        raise FileNotFoundError(args.model)

    bundle = joblib.load(args.model)
    if args.input_csv:
        if any(
            value is not None
            for value in (args.tcp_packets, args.tcp_bytes, args.syn_only_packets)
        ):
            raise ValueError("使用 --input-csv 時不可同時傳入單筆欄位")
        if not args.input_csv.is_file():
            raise FileNotFoundError(args.input_csv)
        data = pd.read_csv(args.input_csv)
        output = predict_buckets(data, bundle, args.minimum_syn)
        destination = args.output_csv or Path("predictions.csv")
        output.to_csv(destination, index=False)
        print(f"已輸出 {len(output)} 筆預測：{destination}")
        return

    values = (args.tcp_packets, args.tcp_bytes, args.syn_only_packets)
    if any(value is None for value in values):
        raise ValueError(
            "請使用 --input-csv，或同時提供 --tcp-packets、"
            "--tcp-bytes 與 --syn-only-packets"
        )

    data = pd.DataFrame(
        [
            {
                "tcp_packets": args.tcp_packets,
                "tcp_bytes": args.tcp_bytes,
                "syn_only_packets": args.syn_only_packets,
            }
        ]
    )
    result = predict_buckets(data, bundle, args.minimum_syn).iloc[0]
    print(
        json.dumps(
            {
                "attack_probability": float(result["attack_probability"]),
                "model_positive": bool(result["model_positive"]),
                "alert": bool(result["alert"]),
                "syn_ratio": float(result["syn_ratio"]),
                "model_threshold": float(result["model_threshold"]),
                "minimum_syn": int(result["minimum_syn"]),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
