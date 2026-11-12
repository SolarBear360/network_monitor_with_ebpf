#!/usr/bin/env python3
"""Evaluate four SYN-Flood runtime candidates with a complete PCAP directory.

Every capture file is read.  ``tcpdump`` applies a BPF filter so only TCP
packets to/from the protected host cross the Python process boundary; UDP and
unrelated traffic cannot contribute to any of the candidate model features.

The CICDDoS2019 01-12 capture contains several attack families.  This is a
class-specific evaluation: only the official SYN interval is label 1, while
benign traffic and other non-SYN attack families are label 0.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import socket
import struct
import subprocess
import sys
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from syn_flood_runtime import SynFloodDetector


AST = timezone(timedelta(hours=-4), name="AST")
DATASET_DATE = (2018, 12, 1)
OFFICIAL_SOURCE = "https://www.unb.ca/cic/datasets/ddos-2019.html"


def ast_epoch(hour: int, minute: int, second: int = 0) -> int:
    """Convert a CICDDoS2019 local AST timestamp to Unix seconds."""

    return int(datetime(*DATASET_DATE, hour, minute, second, tzinfo=AST).timestamp())


# Official second-day schedule from UNB.  The names are used for subgroup
# analysis; only ``syn_flood`` is positive for this class-specific detector.
ATTACK_SCHEDULE = (
    ("ntp", ast_epoch(10, 35), ast_epoch(10, 45)),
    ("dns", ast_epoch(10, 52), ast_epoch(11, 5)),
    ("ldap", ast_epoch(11, 22), ast_epoch(11, 32)),
    ("mssql", ast_epoch(11, 36), ast_epoch(11, 45)),
    ("netbios", ast_epoch(11, 50), ast_epoch(12, 0)),
    ("snmp", ast_epoch(12, 12), ast_epoch(12, 23)),
    ("ssdp", ast_epoch(12, 27), ast_epoch(12, 37)),
    ("udp", ast_epoch(12, 45), ast_epoch(13, 9)),
    ("udp_lag", ast_epoch(13, 11), ast_epoch(13, 15)),
    ("web_ddos", ast_epoch(13, 18), ast_epoch(13, 29)),
    ("syn_flood", ast_epoch(13, 29), ast_epoch(13, 34)),
    ("tftp", ast_epoch(13, 35), ast_epoch(17, 15)),
)

SYN_START = ast_epoch(13, 29)
SYN_END = ast_epoch(13, 34)
SYN_CORE_START = ast_epoch(13, 29, 15)
SYN_CORE_END = ast_epoch(13, 33, 45)
SYN_BOUNDARY_EXCLUDE_END = ast_epoch(13, 35)


DEFAULT_MODELS = {
    "baseline_4": (
        PROJECT_DIR
        / "ml_test/output_multisource_training_20261111/baseline_4/runtime_model.json"
    ),
    "plus_handshake_5": (
        PROJECT_DIR
        / "ml_test/output_multisource_training_20261111/plus_handshake_5/runtime_model.json"
    ),
    "plus_active_ip_5": (
        PROJECT_DIR
        / "ml_test/output_multisource_training_20261111/plus_active_ip_5/runtime_model.json"
    ),
    "full_6": (
        PROJECT_DIR
        / "ml_test/output_multisource_training_20261111/full_6/runtime_model.json"
    ),
}


PCAP_LAYOUTS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
}


@dataclass(frozen=True)
class TcpPacket:
    timestamp: float
    original_length: int
    source_ip: int
    destination_ip: int
    source_port: int
    destination_port: int
    syn: bool
    ack: bool
    raw: bytes


@dataclass
class Bucket:
    tcp_packets: int = 0
    tcp_bytes: int = 0
    syn_only_packets: int = 0
    established_connections: int = 0
    source_ips: set[int] | None = None

    def __post_init__(self) -> None:
        if self.source_ips is None:
            self.source_ips = set()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aggregate all PCAP chunks once and compare four SYN-Flood models."
    )
    parser.add_argument("--pcap-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target-ip", default="192.168.50.1")
    parser.add_argument(
        "--dedup-window-us",
        type=int,
        default=5,
        help="Drop byte-identical records repeated within this many microseconds.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        help="Development-only limit; omit for the complete evaluation.",
    )
    parser.add_argument(
        "--reuse-predictions",
        type=Path,
        help=(
            "Reuse a previously generated per-second predictions CSV and only "
            "recalculate model/report output; avoids rereading all PCAP files."
        ),
    )
    return parser.parse_args()


def read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def parse_tcp(timestamp: float, original_length: int, raw: bytes) -> TcpPacket | None:
    """Parse Ethernet/VLAN/IPv4/TCP records used by CICDDoS2019."""

    if len(raw) < 14:
        return None
    offset = 14
    ether_type = struct.unpack("!H", raw[12:14])[0]
    while ether_type in {0x8100, 0x88A8}:
        if len(raw) < offset + 4:
            return None
        ether_type = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
        offset += 4
    if ether_type != 0x0800 or len(raw) < offset + 20:
        return None

    version_ihl = raw[offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(raw) < offset + ip_header_length:
        return None
    if raw[offset + 9] != 6:
        return None
    fragment_bits = struct.unpack("!H", raw[offset + 6 : offset + 8])[0]
    if fragment_bits & 0x1FFF:
        return None

    tcp_offset = offset + ip_header_length
    if len(raw) < tcp_offset + 20:
        return None
    flags = raw[tcp_offset + 13]
    return TcpPacket(
        timestamp=timestamp,
        original_length=original_length,
        source_ip=struct.unpack("!I", raw[offset + 12 : offset + 16])[0],
        destination_ip=struct.unpack("!I", raw[offset + 16 : offset + 20])[0],
        source_port=struct.unpack("!H", raw[tcp_offset : tcp_offset + 2])[0],
        destination_port=struct.unpack("!H", raw[tcp_offset + 2 : tcp_offset + 4])[0],
        syn=bool(flags & 0x02),
        ack=bool(flags & 0x10),
        raw=raw,
    )


def iter_filtered_tcp(path: Path, target_ip: str) -> Iterator[TcpPacket]:
    """Read one complete PCAP through tcpdump's compiled BPF filter."""

    command = [
        "tcpdump",
        "-n",
        "-r",
        str(path),
        "-w",
        "-",
        "tcp",
        "and",
        "host",
        target_ip,
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1024 * 1024,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        header = read_exact(process.stdout, 24)
        if len(header) != 24 or header[:4] not in PCAP_LAYOUTS:
            raise ValueError(f"{path}: tcpdump did not emit a supported classic PCAP")
        endian, timestamp_divisor = PCAP_LAYOUTS[header[:4]]
        link_type = struct.unpack(f"{endian}I", header[20:24])[0]
        if link_type != 1:
            raise ValueError(f"{path}: unsupported link type {link_type}; expected Ethernet")

        while True:
            packet_header = read_exact(process.stdout, 16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError(f"{path}: truncated filtered packet header")
            seconds, fraction, captured_length, original_length = struct.unpack(
                f"{endian}IIII", packet_header
            )
            raw = read_exact(process.stdout, captured_length)
            if len(raw) != captured_length:
                raise ValueError(f"{path}: truncated filtered packet data")
            packet = parse_tcp(
                seconds + fraction / timestamp_divisor,
                original_length,
                raw,
            )
            if packet is not None:
                yield packet
    finally:
        process.stdout.close()
        stderr = process.stderr.read().decode("utf-8", errors="replace")
        return_code = process.wait()
        process.stderr.close()
        if return_code != 0:
            raise RuntimeError(
                f"tcpdump failed for {path} with exit {return_code}: {stderr.strip()}"
            )


def scenario_for_epoch(second: int) -> str:
    for name, start, end in ATTACK_SCHEDULE:
        if start <= second < end:
            return name
    return "benign_or_gap"


def make_row(second: int, bucket: Bucket) -> dict:
    syn_ratio = bucket.syn_only_packets / max(bucket.tcp_packets, 1)
    local_time = datetime.fromtimestamp(second, AST)
    scenario = scenario_for_epoch(second)
    return {
        "timestamp_epoch": second,
        "timestamp_ast": local_time.isoformat(),
        "scenario": scenario,
        "label": int(SYN_START <= second < SYN_END),
        "tcp_packets": bucket.tcp_packets,
        "tcp_bytes": bucket.tcp_bytes,
        "syn_only_packets": bucket.syn_only_packets,
        "syn_ratio": syn_ratio,
        "active_source_ips": len(bucket.source_ips or ()),
        "established_connections": bucket.established_connections,
    }


def aggregate_directory(
    files: list[Path],
    target_ip: str,
    dedup_window_us: int,
) -> tuple[list[dict], dict]:
    """Create continuous one-second features while preserving handshake state."""

    target_ip_int = struct.unpack("!I", socket.inet_aton(target_ip))[0]
    dedup_window_seconds = dedup_window_us / 1_000_000.0
    recent: dict[bytes, float] = {}
    expiry_queue: deque[tuple[float, bytes]] = deque()
    handshake_states: dict[tuple[int, int, int, int], tuple[int, float]] = {}
    handshake_expiry: deque[tuple[float, tuple[int, int, int, int]]] = deque()

    current_second: int | None = None
    current_bucket = Bucket()
    rows: list[dict] = []
    total_tcp_records = 0
    duplicate_tcp_records = 0
    out_of_order_records = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    def advance_to(second: int) -> None:
        nonlocal current_second, current_bucket
        if current_second is None:
            current_second = second
            return
        while current_second < second:
            rows.append(make_row(current_second, current_bucket))
            current_second += 1
            current_bucket = Bucket()

    for file_number, path in enumerate(files, start=1):
        file_records = 0
        for packet in iter_filtered_tcp(path, target_ip):
            total_tcp_records += 1
            file_records += 1
            if first_timestamp is None:
                first_timestamp = packet.timestamp
            last_timestamp = packet.timestamp

            packet_second = math.floor(packet.timestamp)
            if current_second is not None and packet_second < current_second:
                out_of_order_records += 1
                continue
            advance_to(packet_second)

            while expiry_queue and packet.timestamp - expiry_queue[0][0] > dedup_window_seconds:
                old_timestamp, old_digest = expiry_queue.popleft()
                if recent.get(old_digest) == old_timestamp:
                    del recent[old_digest]

            digest = hashlib.blake2b(packet.raw, digest_size=16).digest()
            previous_timestamp = recent.get(digest)
            duplicate = (
                previous_timestamp is not None
                and 0 <= packet.timestamp - previous_timestamp <= dedup_window_seconds
            )
            recent[digest] = packet.timestamp
            expiry_queue.append((packet.timestamp, digest))
            if duplicate:
                duplicate_tcp_records += 1
                continue

            while handshake_expiry and packet.timestamp - handshake_expiry[0][0] > 10.0:
                old_timestamp, old_key = handshake_expiry.popleft()
                if handshake_states.get(old_key, (0, -1.0))[1] == old_timestamp:
                    del handshake_states[old_key]

            if packet.source_ip == target_ip_int:
                if packet.syn and packet.ack:
                    reverse_key = (
                        packet.destination_ip,
                        packet.destination_port,
                        packet.source_ip,
                        packet.source_port,
                    )
                    if handshake_states.get(reverse_key, (0, 0.0))[0] == 1:
                        handshake_states[reverse_key] = (2, packet.timestamp)
                        handshake_expiry.append((packet.timestamp, reverse_key))
                continue

            if packet.destination_ip != target_ip_int:
                continue

            current_bucket.tcp_packets += 1
            current_bucket.tcp_bytes += packet.original_length
            assert current_bucket.source_ips is not None
            current_bucket.source_ips.add(packet.source_ip)

            flow_key = (
                packet.source_ip,
                packet.source_port,
                packet.destination_ip,
                packet.destination_port,
            )
            if packet.syn and not packet.ack:
                current_bucket.syn_only_packets += 1
                handshake_states[flow_key] = (1, packet.timestamp)
                handshake_expiry.append((packet.timestamp, flow_key))
            elif packet.ack and not packet.syn:
                if handshake_states.get(flow_key, (0, 0.0))[0] == 2:
                    current_bucket.established_connections += 1
                    del handshake_states[flow_key]

        if file_number == 1 or file_number % 10 == 0 or file_number == len(files):
            last_text = (
                datetime.fromtimestamp(last_timestamp, AST).isoformat()
                if last_timestamp is not None
                else "no-target-tcp-yet"
            )
            print(
                f"progress {file_number}/{len(files)} files; "
                f"filtered_tcp={total_tcp_records}; rows={len(rows)}; "
                f"last_ast={last_text}; current_file_records={file_records}",
                flush=True,
            )

    if current_second is not None:
        rows.append(make_row(current_second, current_bucket))
    if not rows or first_timestamp is None or last_timestamp is None:
        raise ValueError("No TCP packets for the protected target were found")

    # The first and last seconds are partial capture windows.  Keep them in the
    # CSV for transparency but exclude them from reported metrics.
    rows[0]["complete_window"] = 0
    rows[-1]["complete_window"] = 0
    for row in rows[1:-1]:
        row["complete_window"] = 1

    metadata = {
        "pcap_files": len(files),
        "filtered_tcp_records": total_tcp_records,
        "duplicate_tcp_records_dropped": duplicate_tcp_records,
        "out_of_order_records_dropped": out_of_order_records,
        "first_target_tcp_epoch": first_timestamp,
        "last_target_tcp_epoch": last_timestamp,
        "first_target_tcp_ast": datetime.fromtimestamp(first_timestamp, AST).isoformat(),
        "last_target_tcp_ast": datetime.fromtimestamp(last_timestamp, AST).isoformat(),
        "one_second_rows": len(rows),
    }
    return rows, metadata


def safe_divide(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def classification_metrics(rows: Iterable[dict], prediction_field: str) -> dict:
    tn = fp = fn = tp = 0
    row_count = 0
    for row in rows:
        if not int(row["complete_window"]):
            continue
        row_count += 1
        truth = int(row["label"])
        prediction = int(row[prediction_field])
        if truth == 0 and prediction == 0:
            tn += 1
        elif truth == 0 and prediction == 1:
            fp += 1
        elif truth == 1 and prediction == 0:
            fn += 1
        else:
            tp += 1

    accuracy = safe_divide(tn + tp, row_count)
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    specificity = safe_divide(tn, tn + fp)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    balanced_accuracy = (
        (recall + specificity) / 2
        if recall is not None and specificity is not None
        else None
    )
    return {
        "row_count": row_count,
        "accuracy": accuracy,
        "balanced_accuracy": balanced_accuracy,
        "attack_precision": precision,
        "attack_recall": recall,
        "attack_f1": f1,
        "specificity": specificity,
        "false_positive_rate": safe_divide(fp, fp + tn),
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
    }


def subgroup_metrics(rows: list[dict], prediction_field: str) -> dict:
    result: dict[str, dict] = {}
    for scenario in sorted({str(row["scenario"]) for row in rows}):
        selected = [
            row
            for row in rows
            if row["scenario"] == scenario and int(row["complete_window"])
        ]
        result[scenario] = {
            "seconds": len(selected),
            "tcp_active_seconds": sum(int(row["tcp_packets"]) > 0 for row in selected),
            "predicted_attack_seconds": sum(int(row[prediction_field]) for row in selected),
            "mean_syn_packets": (
                sum(int(row["syn_only_packets"]) for row in selected) / len(selected)
                if selected
                else None
            ),
        }
    return result


def evaluate_models(rows: list[dict], model_paths: dict[str, Path]) -> dict:
    evaluations: dict[str, dict] = {}
    for name, path in model_paths.items():
        if not path.is_file():
            raise FileNotFoundError(path)
        detector = SynFloodDetector.load(path)
        raw_field = f"{name}_raw_prediction"
        runtime_field = f"{name}_runtime_prediction"
        probability_field = f"{name}_probability"

        for row in rows:
            result = detector.evaluate(
                tcp_packets=int(row["tcp_packets"]),
                tcp_bytes=int(row["tcp_bytes"]),
                syn_only_packets=int(row["syn_only_packets"]),
                established_connections=int(row["established_connections"]),
                active_source_ips=int(row["active_source_ips"]),
                interval_seconds=1.0,
            )
            row[probability_field] = result.attack_probability
            row[raw_field] = int(result.model_positive)
            row[runtime_field] = int(result.attack_active)

        official_rows = rows
        core_rows = [
            row
            for row in rows
            if not (
                SYN_START <= int(row["timestamp_epoch"]) < SYN_CORE_START
                or SYN_CORE_END
                <= int(row["timestamp_epoch"])
                < SYN_BOUNDARY_EXCLUDE_END
            )
        ]
        evaluations[name] = {
            "runtime_model": str(path.resolve()),
            "features": detector.model.features,
            "probability_threshold": detector.probability_threshold,
            "minimum_syn_packets": detector.minimum_syn_packets,
            "persistence_window_seconds": detector.persistence_window_seconds,
            "persistence_required_hits": detector.persistence_required_hits,
            "official_window": {
                "raw_model": classification_metrics(official_rows, raw_field),
                "runtime_policy": classification_metrics(official_rows, runtime_field),
                "runtime_subgroups": subgroup_metrics(official_rows, runtime_field),
            },
            "trimmed_core_window": {
                "excluded_boundary_seconds": 90,
                "excluded_ranges_ast": [
                    "2018-12-01 13:29:00–13:29:15 AST",
                    "2018-12-01 13:33:45–13:35:00 AST",
                ],
                "raw_model": classification_metrics(core_rows, raw_field),
                "runtime_policy": classification_metrics(core_rows, runtime_field),
            },
        }
    return evaluations


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError("No rows to write")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def percentage(value: float | None) -> str:
    return "N/A" if value is None else f"{100 * value:.2f}%"


def write_markdown(path: Path, report: dict) -> None:
    lines = [
        "# CICDDoS2019 完整 PCAP：四模型比較",
        "",
        f"- PCAP 分段：{report['capture']['pcap_files']}",
        f"- 每秒窗口：{report['capture']['one_second_rows']}",
        f"- 受保護主機：`{report['target_ip']}`",
        f"- SYN Flood 官方時段：{report['label_definition']['official_syn_window_ast']}",
        "- 標籤：SYN Flood 時段為 1；其他攻擊類型及背景流量為 0。",
        "",
        "## Runtime 政策結果（官方 5 分鐘 SYN 時段）",
        "",
        "| 模型 | 特徵 | Accuracy | Balanced accuracy | Precision | Recall | F1 | FP | FN |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, evaluation in report["models"].items():
        metrics = evaluation["official_window"]["runtime_policy"]
        matrix = metrics["confusion_matrix"]
        lines.append(
            f"| `{name}` | {', '.join(evaluation['features'])} | "
            f"{percentage(metrics['accuracy'])} | "
            f"{percentage(metrics['balanced_accuracy'])} | "
            f"{percentage(metrics['attack_precision'])} | "
            f"{percentage(metrics['attack_recall'])} | "
            f"{percentage(metrics['attack_f1'])} | "
            f"{matrix['false_positive']} | {matrix['false_negative']} |"
        )
    lines.extend(
        [
            "",
            "Accuracy 會受大量非 SYN 時段影響，因此選模型時應同時看 Balanced accuracy、Recall、F1、FP 與 FN。",
            "",
            "## 排除不確定邊界後的 Runtime 結果",
            "",
            "排除 13:29:00–13:29:15 與 13:33:45–13:35:00，共 90 秒。後一段在官方 13:34 結束時間後仍觀察到大量純 SYN，且包含 Runtime 解除告警時間。",
            "",
            "| 模型 | Accuracy | Balanced accuracy | Precision | Recall | F1 | FP | FN |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, evaluation in report["models"].items():
        metrics = evaluation["trimmed_core_window"]["runtime_policy"]
        matrix = metrics["confusion_matrix"]
        lines.append(
            f"| `{name}` | {percentage(metrics['accuracy'])} | "
            f"{percentage(metrics['balanced_accuracy'])} | "
            f"{percentage(metrics['attack_precision'])} | "
            f"{percentage(metrics['attack_recall'])} | "
            f"{percentage(metrics['attack_f1'])} | "
            f"{matrix['false_positive']} | {matrix['false_negative']} |"
        )
    lines.extend(
        [
            "",
            "## 限制",
            "",
            "- `active_source_ips` 由 PCAP 中每秒入站 TCP 的不同來源 IP 重建，與 eBPF map 的實作可能有些微差異。",
            "- `established_connections` 由觀察到的 SYN、SYN-ACK、最終 ACK 重建；遺失封包時會低估。",
            "- 官方時程只有分鐘精度，因此另提供排除 90 秒不確定開始、結束與告警冷卻區間的 trimmed-core 結果。",
            "- 這是跨環境外部測試，不取代實驗室的獨立 holdout。",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    if args.dedup_window_us < 0:
        raise ValueError("--dedup-window-us cannot be negative")
    if not args.pcap_dir.is_dir():
        raise NotADirectoryError(args.pcap_dir)
    socket.inet_aton(args.target_ip)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.output_dir / "full_pcap_four_model_predictions.csv"
    json_path = args.output_dir / "full_pcap_four_model_evaluation.json"
    markdown_path = args.output_dir / "FULL_PCAP_FOUR_MODEL_SUMMARY.md"

    if args.reuse_predictions is not None:
        if not args.reuse_predictions.is_file():
            raise FileNotFoundError(args.reuse_predictions)
        with args.reuse_predictions.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        if not rows:
            raise ValueError("The reused predictions CSV is empty")
        if json_path.is_file():
            previous_report = json.loads(json_path.read_text(encoding="utf-8"))
            capture_metadata = previous_report["capture"]
        else:
            capture_metadata = {
                "pcap_files": None,
                "one_second_rows": len(rows),
                "reconstructed_from_predictions_csv": True,
            }
        print(
            f"Reusing {len(rows)} one-second rows from {args.reuse_predictions}",
            flush=True,
        )
    else:
        files = sorted(
            path
            for path in args.pcap_dir.iterdir()
            if path.is_file() and path.name.startswith("SAT-01-12-2018_")
        )
        if args.max_files is not None:
            if args.max_files < 1:
                raise ValueError("--max-files must be positive")
            files = files[: args.max_files]
        if not files:
            raise FileNotFoundError(f"No CICDDoS2019 PCAP chunks in {args.pcap_dir}")
        if args.max_files is None and len(files) != 250:
            raise ValueError(
                f"Expected 250 PCAP chunks for a complete run, found {len(files)}"
            )

        print(f"Reading {len(files)} PCAP files from {args.pcap_dir}", flush=True)
        rows, capture_metadata = aggregate_directory(
            files,
            args.target_ip,
            args.dedup_window_us,
        )

    evaluations = evaluate_models(rows, DEFAULT_MODELS)

    report = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_directory": str(args.pcap_dir.resolve()),
        "official_schedule_source": OFFICIAL_SOURCE,
        "target_ip": args.target_ip,
        "dedup_window_us": args.dedup_window_us,
        "capture": capture_metadata,
        "label_definition": {
            "positive_class": "syn_flood",
            "negative_class": "benign_or_non_syn_attack",
            "official_syn_window_epoch": [SYN_START, SYN_END],
            "official_syn_window_ast": "2018-12-01 13:29:00–13:34:00 AST",
            "trimmed_core_window_epoch": [SYN_CORE_START, SYN_CORE_END],
            "trimmed_core_window_ast": "2018-12-01 13:29:15–13:33:45 AST",
            "boundary_exclusions_ast": [
                "2018-12-01 13:29:00–13:29:15 AST",
                "2018-12-01 13:33:45–13:35:00 AST",
            ],
        },
        "feature_notes": {
            "active_source_ips": "Distinct inbound TCP source IPs observed in each second.",
            "established_connections": "Completed handshakes reconstructed from SYN/SYN-ACK/final ACK within 10 seconds.",
        },
        "models": evaluations,
    }
    write_csv(csv_path, rows)
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_markdown(markdown_path, report)

    print("\nRuntime policy comparison (official SYN interval):", flush=True)
    for name, evaluation in evaluations.items():
        metrics = evaluation["official_window"]["runtime_policy"]
        matrix = metrics["confusion_matrix"]
        print(
            f"{name}: accuracy={percentage(metrics['accuracy'])}, "
            f"balanced_accuracy={percentage(metrics['balanced_accuracy'])}, "
            f"precision={percentage(metrics['attack_precision'])}, "
            f"recall={percentage(metrics['attack_recall'])}, "
            f"f1={percentage(metrics['attack_f1'])}, "
            f"TN={matrix['true_negative']} FP={matrix['false_positive']} "
            f"FN={matrix['false_negative']} TP={matrix['true_positive']}",
            flush=True,
        )
    print(f"Predictions: {csv_path}", flush=True)
    print(f"Evaluation: {json_path}", flush=True)
    print(f"Summary: {markdown_path}", flush=True)


if __name__ == "__main__":
    main()
