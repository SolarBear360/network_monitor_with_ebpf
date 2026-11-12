#!/usr/bin/env python3
"""Evaluate the one-second SYN Flood model with external PCAP captures.

The script intentionally uses a small, streaming PCAP reader instead of Scapy so
large captures do not need to be loaded into memory.  It currently supports the
Ethernet/IPv4/TCP packets used by CICDDoS2019-derived captures.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import socket
import struct
import sys
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import joblib
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from syn_flood_runtime import SynFloodDetector


DEFAULT_MODEL = (
    Path(__file__).resolve().parent
    / "output_multi_round_final_20261028"
    / "deployment_model.joblib"
)


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    original_length: int
    raw: bytes


@dataclass(frozen=True)
class TcpPacket:
    timestamp: float
    original_length: int
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    syn: bool
    ack: bool


class PcapFormatError(ValueError):
    """Raised when a capture is unsupported or truncated."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert benign/SYN-Flood PCAPs into one-second model features and evaluate them."
    )
    parser.add_argument("--benign-pcap", type=Path, required=True)
    parser.add_argument("--attack-pcap", type=Path, required=True)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument(
        "--runtime-model",
        type=Path,
        help="Optional runtime_model.json for persistence and volume-guard evaluation.",
    )
    parser.add_argument(
        "--benign-target",
        help="Protected IPv4 in the benign PCAP. Default: private destination with most TCP packets.",
    )
    parser.add_argument(
        "--attack-target",
        help="Protected IPv4 in the attack PCAP. Default: private destination with most pure SYN packets.",
    )
    parser.add_argument(
        "--dedup-window-us",
        type=int,
        default=5,
        help="Drop byte-identical packets repeated within this many microseconds (default: 5).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        help="Override the probability threshold stored in the model artifact.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "external_pcap_evaluation",
    )
    return parser.parse_args()


def _pcap_layout(header: bytes) -> tuple[str, float, int]:
    if len(header) != 24:
        raise PcapFormatError("PCAP global header is incomplete")

    magic = header[:4]
    layouts = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    if magic not in layouts:
        raise PcapFormatError(
            "Unsupported capture format. Convert PCAPNG to PCAP before running this script."
        )

    endian, timestamp_divisor = layouts[magic]
    link_type = struct.unpack(f"{endian}I", header[20:24])[0]
    return endian, timestamp_divisor, link_type


def iter_pcap(path: Path) -> Iterator[PacketRecord]:
    with path.open("rb") as capture:
        endian, timestamp_divisor, link_type = _pcap_layout(capture.read(24))
        if link_type != 1:
            raise PcapFormatError(
                f"{path}: link type {link_type} is unsupported; Ethernet (1) is required"
            )

        packet_number = 0
        while True:
            packet_header = capture.read(16)
            if not packet_header:
                break
            packet_number += 1
            if len(packet_header) != 16:
                raise PcapFormatError(f"{path}: truncated packet header at record {packet_number}")

            seconds, fraction, captured_length, original_length = struct.unpack(
                f"{endian}IIII", packet_header
            )
            raw = capture.read(captured_length)
            if len(raw) != captured_length:
                raise PcapFormatError(f"{path}: truncated packet data at record {packet_number}")

            yield PacketRecord(
                timestamp=seconds + fraction / timestamp_divisor,
                original_length=original_length,
                raw=raw,
            )


def parse_tcp(record: PacketRecord) -> TcpPacket | None:
    raw = record.raw
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
        timestamp=record.timestamp,
        original_length=record.original_length,
        source_ip=socket.inet_ntoa(raw[offset + 12 : offset + 16]),
        destination_ip=socket.inet_ntoa(raw[offset + 16 : offset + 20]),
        source_port=struct.unpack("!H", raw[tcp_offset : tcp_offset + 2])[0],
        destination_port=struct.unpack("!H", raw[tcp_offset + 2 : tcp_offset + 4])[0],
        syn=bool(flags & 0x02),
        ack=bool(flags & 0x10),
    )


def iter_unique_tcp(path: Path, dedup_window_us: int) -> Iterator[tuple[TcpPacket, bool]]:
    """Yield TCP packets and whether each packet is a near-instant duplicate."""

    dedup_window_seconds = dedup_window_us / 1_000_000.0
    recent: dict[bytes, float] = {}
    expiry_queue: deque[tuple[float, bytes]] = deque()

    for record in iter_pcap(path):
        while expiry_queue and record.timestamp - expiry_queue[0][0] > dedup_window_seconds:
            old_timestamp, old_digest = expiry_queue.popleft()
            if recent.get(old_digest) == old_timestamp:
                del recent[old_digest]

        digest = hashlib.blake2b(record.raw, digest_size=16).digest()
        previous_timestamp = recent.get(digest)
        duplicate = (
            previous_timestamp is not None
            and 0 <= record.timestamp - previous_timestamp <= dedup_window_seconds
        )

        recent[digest] = record.timestamp
        expiry_queue.append((record.timestamp, digest))

        tcp_packet = parse_tcp(record)
        if tcp_packet is not None:
            yield tcp_packet, duplicate


def is_private_ipv4(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.version == 4 and address.is_private


def inspect_capture(path: Path, dedup_window_us: int) -> dict:
    tcp_destinations: Counter[str] = Counter()
    pure_syn_destinations: Counter[str] = Counter()
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    tcp_records = 0
    duplicate_tcp_records = 0

    for packet, duplicate in iter_unique_tcp(path, dedup_window_us):
        if first_timestamp is None:
            first_timestamp = packet.timestamp
        last_timestamp = packet.timestamp
        tcp_records += 1
        if duplicate:
            duplicate_tcp_records += 1
            continue

        tcp_destinations[packet.destination_ip] += 1
        if packet.syn and not packet.ack:
            pure_syn_destinations[packet.destination_ip] += 1

    return {
        "path": str(path.resolve()),
        "tcp_records": tcp_records,
        "duplicate_tcp_records_dropped": duplicate_tcp_records,
        "unique_tcp_records": tcp_records - duplicate_tcp_records,
        "first_timestamp_epoch": first_timestamp,
        "last_timestamp_epoch": last_timestamp,
        "duration_seconds": (
            last_timestamp - first_timestamp
            if first_timestamp is not None and last_timestamp is not None
            else 0.0
        ),
        "top_tcp_destinations": tcp_destinations.most_common(10),
        "top_pure_syn_destinations": pure_syn_destinations.most_common(10),
        "_tcp_destinations": tcp_destinations,
        "_pure_syn_destinations": pure_syn_destinations,
    }


def select_target(report: dict, requested: str | None, prefer_pure_syn: bool) -> str:
    if requested:
        ipaddress.IPv4Address(requested)
        return requested

    counter_name = "_pure_syn_destinations" if prefer_pure_syn else "_tcp_destinations"
    candidates: Counter[str] = report[counter_name]
    private_candidates = [(count, address) for address, count in candidates.items() if is_private_ipv4(address)]
    if not private_candidates:
        raise ValueError(f"Could not automatically select a private target from {report['path']}")
    return max(private_candidates)[1]


def aggregate_capture(
    path: Path,
    target_ip: str,
    label: int,
    scenario: str,
    dedup_window_us: int,
    first_timestamp: float,
    last_timestamp: float,
) -> list[dict]:
    first_second = math.floor(first_timestamp)
    last_second = math.floor(last_timestamp)
    buckets: dict[int, dict[str, int]] = {}
    # Normal handshakes complete quickly.  Expiring incomplete state after ten
    # seconds prevents a SYN Flood PCAP from growing this dictionary without
    # bound while retaining ample time for ordinary three-way handshakes.
    handshake_states: dict[tuple[str, int, str, int], tuple[int, float]] = {}
    handshake_expiry: deque[tuple[float, tuple[str, int, str, int]]] = deque()

    for packet, duplicate in iter_unique_tcp(path, dedup_window_us):
        if duplicate:
            continue

        while handshake_expiry and packet.timestamp - handshake_expiry[0][0] > 10.0:
            old_timestamp, old_key = handshake_expiry.popleft()
            if handshake_states.get(old_key, (0, -1.0))[1] == old_timestamp:
                del handshake_states[old_key]

        if packet.source_ip == target_ip and packet.syn and packet.ack:
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

        if packet.destination_ip != target_ip:
            continue

        second = math.floor(packet.timestamp)
        bucket = buckets.setdefault(
            second,
            {
                "tcp_packets": 0,
                "tcp_bytes": 0,
                "syn_only_packets": 0,
                "established_connections": 0,
            },
        )
        bucket["tcp_packets"] += 1
        bucket["tcp_bytes"] += packet.original_length
        if packet.syn and not packet.ack:
            bucket["syn_only_packets"] += 1
            flow_key = (
                packet.source_ip,
                packet.source_port,
                packet.destination_ip,
                packet.destination_port,
            )
            handshake_states[flow_key] = (1, packet.timestamp)
            handshake_expiry.append((packet.timestamp, flow_key))
        elif packet.ack and not packet.syn:
            flow_key = (
                packet.source_ip,
                packet.source_port,
                packet.destination_ip,
                packet.destination_port,
            )
            if handshake_states.get(flow_key, (0, 0.0))[0] == 2:
                bucket["established_connections"] += 1
                del handshake_states[flow_key]

    rows: list[dict] = []
    for second in range(first_second, last_second + 1):
        bucket = buckets.get(
            second,
            {
                "tcp_packets": 0,
                "tcp_bytes": 0,
                "syn_only_packets": 0,
                "established_connections": 0,
            },
        )
        packet_count = bucket["tcp_packets"]
        syn_count = bucket["syn_only_packets"]
        rows.append(
            {
                "timestamp": datetime.fromtimestamp(second, timezone.utc).isoformat(),
                "timestamp_epoch": second,
                "source_pcap": path.name,
                "target_ip": target_ip,
                "scenario": scenario,
                "label": label,
                "tcp_packets": packet_count,
                "tcp_bytes": bucket["tcp_bytes"],
                "syn_only_packets": syn_count,
                "syn_ratio": syn_count / max(packet_count, 1),
                "established_connections": bucket["established_connections"],
            }
        )
    return rows


def safe_divide(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def evaluate_predictions(
    rows: list[dict],
    threshold: float,
    prediction_field: str = "predicted_label",
) -> dict:
    true_negative = false_positive = false_negative = true_positive = 0
    for row in rows:
        truth = int(row["label"])
        predicted = int(row[prediction_field])
        if truth == 0 and predicted == 0:
            true_negative += 1
        elif truth == 0 and predicted == 1:
            false_positive += 1
        elif truth == 1 and predicted == 0:
            false_negative += 1
        else:
            true_positive += 1

    total = len(rows)
    precision = safe_divide(true_positive, true_positive + false_positive)
    recall = safe_divide(true_positive, true_positive + false_negative)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "threshold": threshold,
        "row_count": total,
        "accuracy": safe_divide(true_positive + true_negative, total),
        "attack_precision": precision,
        "attack_recall": recall,
        "attack_f1": f1,
        "false_positive_rate": safe_divide(false_positive, false_positive + true_negative),
        "confusion_matrix": {
            "true_negative": true_negative,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "true_positive": true_positive,
        },
        "subgroups": {
            "normal": {
                "seconds": sum(int(row["label"]) == 0 for row in rows),
                "active_tcp_seconds": sum(
                    int(row["label"]) == 0 and int(row["tcp_packets"]) > 0 for row in rows
                ),
                "pure_syn_seconds": sum(
                    int(row["label"]) == 0 and int(row["syn_only_packets"]) > 0
                    for row in rows
                ),
                "predicted_attack_seconds": false_positive,
            },
            "attack": {
                "seconds": sum(int(row["label"]) == 1 for row in rows),
                "detected_seconds": true_positive,
            },
        },
    }


def serializable_report(report: dict) -> dict:
    return {key: value for key, value in report.items() if not key.startswith("_")}


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError("No output rows were generated")
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    required_paths = [args.benign_pcap, args.attack_pcap, args.model]
    if args.runtime_model is not None:
        required_paths.append(args.runtime_model)
    for required_path in required_paths:
        if not required_path.is_file():
            raise FileNotFoundError(required_path)
    if args.dedup_window_us < 0:
        raise ValueError("--dedup-window-us cannot be negative")

    benign_report = inspect_capture(args.benign_pcap, args.dedup_window_us)
    attack_report = inspect_capture(args.attack_pcap, args.dedup_window_us)
    benign_target = select_target(benign_report, args.benign_target, prefer_pure_syn=False)
    attack_target = select_target(attack_report, args.attack_target, prefer_pure_syn=True)

    benign_rows = aggregate_capture(
        args.benign_pcap,
        benign_target,
        label=0,
        scenario="external_benign",
        dedup_window_us=args.dedup_window_us,
        first_timestamp=benign_report["first_timestamp_epoch"],
        last_timestamp=benign_report["last_timestamp_epoch"],
    )
    attack_rows = aggregate_capture(
        args.attack_pcap,
        attack_target,
        label=1,
        scenario="external_syn_flood",
        dedup_window_us=args.dedup_window_us,
        first_timestamp=attack_report["first_timestamp_epoch"],
        last_timestamp=attack_report["last_timestamp_epoch"],
    )
    rows = benign_rows + attack_rows

    artifact = joblib.load(args.model)
    if not isinstance(artifact, dict) or "model" not in artifact or "features" not in artifact:
        raise ValueError("Expected a deployment_model.joblib artifact containing model and features")
    feature_names = list(artifact["features"])
    threshold = (
        float(args.threshold)
        if args.threshold is not None
        else float(artifact.get("threshold", 0.5))
    )
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("--threshold must be between 0 and 1")
    available_features = set(rows[0])
    missing_features = [name for name in feature_names if name not in available_features]
    if missing_features:
        raise ValueError(
            "PCAP conversion cannot provide model features: "
            + ", ".join(missing_features)
        )
    feature_matrix = pd.DataFrame(
        [[float(row[name]) for name in feature_names] for row in rows],
        columns=feature_names,
        dtype=float,
    )
    probabilities = artifact["model"].predict_proba(feature_matrix)[:, 1]
    for row, probability in zip(rows, probabilities):
        row["attack_probability"] = float(probability)
        row["predicted_label"] = int(probability >= threshold)

    runtime_evaluation = None
    if args.runtime_model is not None:
        for scenario in ("external_benign", "external_syn_flood"):
            detector = SynFloodDetector.load(args.runtime_model)
            for row in (item for item in rows if item["scenario"] == scenario):
                detection = detector.evaluate(
                    tcp_packets=int(row["tcp_packets"]),
                    tcp_bytes=int(row["tcp_bytes"]),
                    syn_only_packets=int(row["syn_only_packets"]),
                    established_connections=int(row["established_connections"]),
                    interval_seconds=1.0,
                )
                row["runtime_policy_prediction"] = int(detection.attack_active)
                row["runtime_status"] = detection.status
                row["runtime_recent_hits"] = detection.recent_hits
        runtime_evaluation = evaluate_predictions(
            rows,
            threshold,
            prediction_field="runtime_policy_prediction",
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    prediction_path = args.output_dir / "external_pcap_predictions.csv"
    report_path = args.output_dir / "external_pcap_evaluation.json"
    write_csv(prediction_path, rows)

    evaluation = evaluate_predictions(rows, threshold)
    evaluation.update(
        {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "model_path": str(args.model.resolve()),
            "model_name": artifact.get("model_name"),
            "features": feature_names,
            "benign_target": benign_target,
            "attack_target": attack_target,
            "label_counts": {
                "normal": len(benign_rows),
                "attack": len(attack_rows),
            },
            "capture_inspection": {
                "benign": serializable_report(benign_report),
                "attack": serializable_report(attack_report),
            },
            "limitations": [
                "The benign and attack captures monitor different private hosts and do not represent one continuous server workload.",
                "Near-instant byte-identical packets were removed as duplicate capture artifacts.",
                "Completed handshakes are reconstructed from observed SYN, SYN-ACK, and final ACK packets and may be undercounted if capture packets are missing.",
                "This external-PCAP evaluation measures transfer to a different environment; it does not replace the independent lab holdout.",
            ],
        }
    )
    if runtime_evaluation is not None:
        evaluation["runtime_model_path"] = str(args.runtime_model.resolve())
        evaluation["runtime_policy"] = runtime_evaluation
    report_path.write_text(json.dumps(evaluation, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    matrix = evaluation["confusion_matrix"]
    print(f"Benign target: {benign_target} ({len(benign_rows)} one-second windows)")
    print(f"Attack target: {attack_target} ({len(attack_rows)} one-second windows)")
    print(
        "Confusion matrix: "
        f"TN={matrix['true_negative']} FP={matrix['false_positive']} "
        f"FN={matrix['false_negative']} TP={matrix['true_positive']}"
    )
    print(f"Accuracy: {evaluation['accuracy']:.4f}")
    if evaluation["attack_recall"] is not None:
        print(f"Attack recall: {evaluation['attack_recall']:.4f}")
    if runtime_evaluation is not None:
        runtime_matrix = runtime_evaluation["confusion_matrix"]
        print(
            "Runtime policy confusion matrix: "
            f"TN={runtime_matrix['true_negative']} "
            f"FP={runtime_matrix['false_positive']} "
            f"FN={runtime_matrix['false_negative']} "
            f"TP={runtime_matrix['true_positive']}"
        )
        print(f"Runtime policy accuracy: {runtime_evaluation['accuracy']:.4f}")
        if runtime_evaluation["attack_recall"] is not None:
            print(
                "Runtime policy attack recall: "
                f"{runtime_evaluation['attack_recall']:.4f}"
            )
    print(f"Predictions: {prediction_path}")
    print(f"Evaluation: {report_path}")


if __name__ == "__main__":
    main()
