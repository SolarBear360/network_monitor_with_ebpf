#!/usr/bin/env python3
"""以固定速率建立真正完成握手的正常 TCP/HTTP 連線。

這個工具是為了補齊「每秒只有 1、2、5 個新連線」這類困難正常樣本。
它只允許對私有或本機 IPv4 執行，並有速率與時間上限。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass


ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "127.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
    )
)


@dataclass
class AttemptResult:
    success: bool
    latency_ms: float
    error: str | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="以可控速率建立正常 HTTP 新連線。"
    )
    parser.add_argument("--host", required=True, help="只允許私有 IPv4")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--rate", type=int, required=True, help="每秒連線數（1–200）")
    parser.add_argument("--duration", type=int, required=True, help="秒數（5–300）")
    parser.add_argument(
        "--source-ips",
        default="",
        help="以逗號分隔的本機來源 IPv4；每次連線會依序輪流使用",
    )
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument(
        "--minimum-success-ratio",
        type=float,
        default=0.90,
        help="成功率低於此值時以失敗結束（預設 0.90）",
    )
    return parser.parse_args()


def parse_source_ips(raw: str) -> list[str]:
    """檢查並正規化可選的來源 IP 清單。"""
    if not raw.strip():
        return []

    addresses: list[str] = []
    seen: set[str] = set()
    for value in raw.split(","):
        value = value.strip()
        try:
            address = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as error:
            raise ValueError(f"無效的來源 IPv4：{value}") from error
        if not any(address in network for network in ALLOWED_NETWORKS):
            raise ValueError(f"來源 IP 只允許私有 IPv4：{address}")
        normalized = str(address)
        if normalized in seen:
            raise ValueError(f"來源 IP 重複：{normalized}")
        seen.add(normalized)
        addresses.append(normalized)

    if len(addresses) > 64:
        raise ValueError("來源 IP 最多 64 個")
    return addresses


def validate_args(
    args: argparse.Namespace,
) -> tuple[ipaddress.IPv4Address, list[str]]:
    try:
        address = ipaddress.IPv4Address(args.host)
    except ipaddress.AddressValueError as error:
        raise ValueError("--host 必須是 IPv4") from error
    if not any(address in network for network in ALLOWED_NETWORKS):
        raise ValueError("為避免測試公網主機，--host 只允許私有 IPv4")
    if not 1 <= args.port <= 65535:
        raise ValueError("--port 必須介於 1 與 65535")
    if not 1 <= args.rate <= 200:
        raise ValueError("--rate 必須介於 1 與 200")
    if not 5 <= args.duration <= 300:
        raise ValueError("--duration 必須介於 5 與 300 秒")
    if not 0.1 <= args.timeout <= 10:
        raise ValueError("--timeout 必須介於 0.1 與 10 秒")
    if not 0 <= args.minimum_success_ratio <= 1:
        raise ValueError("--minimum-success-ratio 必須介於 0 與 1")
    return address, parse_source_ips(args.source_ips)


def make_request(
    host: str,
    port: int,
    timeout: float,
    source_ip: str | None = None,
) -> AttemptResult:
    started = time.perf_counter()
    try:
        source_address = (source_ip, 0) if source_ip is not None else None
        with socket.create_connection(
            (host, port),
            timeout=timeout,
            source_address=source_address,
        ) as connection:
            request = (
                f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                "Connection: close\r\nUser-Agent: syn-flood-lab-normal-client\r\n\r\n"
            )
            connection.sendall(request.encode("ascii"))
            connection.settimeout(timeout)
            response = connection.recv(256)
            if not response.startswith(b"HTTP/"):
                raise RuntimeError("伺服器沒有回傳 HTTP response")
        return AttemptResult(True, (time.perf_counter() - started) * 1000)
    except (OSError, RuntimeError) as error:
        return AttemptResult(
            False,
            (time.perf_counter() - started) * 1000,
            f"{type(error).__name__}: {error}",
        )


def main() -> int:
    args = parse_args()
    address, source_ips = validate_args(args)
    total_attempts = args.rate * args.duration
    workers = min(128, max(8, args.rate * 2))
    started_wall = time.time()
    started = time.perf_counter()
    futures = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for attempt in range(total_attempts):
            target_time = started + attempt / args.rate
            remaining = target_time - time.perf_counter()
            if remaining > 0:
                time.sleep(remaining)
            source_ip = source_ips[attempt % len(source_ips)] if source_ips else None
            futures.append(
                executor.submit(
                    make_request,
                    str(address),
                    args.port,
                    args.timeout,
                    source_ip,
                )
            )

        results = [future.result() for future in as_completed(futures)]

    successes = [result for result in results if result.success]
    failures = [result for result in results if not result.success]
    success_ratio = len(successes) / total_attempts if total_attempts else 0.0
    latencies = [result.latency_ms for result in successes]
    error_counts: dict[str, int] = {}
    for result in failures:
        message = result.error or "unknown"
        error_counts[message] = error_counts.get(message, 0) + 1

    summary = {
        "host": str(address),
        "port": args.port,
        "configured_rate_per_second": args.rate,
        "configured_duration_seconds": args.duration,
        "configured_source_ips": source_ips,
        "configured_source_count": len(source_ips) if source_ips else 1,
        "attempted_connections": total_attempts,
        "successful_connections": len(successes),
        "failed_connections": len(failures),
        "success_ratio": success_ratio,
        "actual_elapsed_seconds": time.perf_counter() - started,
        "started_epoch": started_wall,
        "mean_success_latency_ms": (
            sum(latencies) / len(latencies) if latencies else None
        ),
        "maximum_success_latency_ms": max(latencies) if latencies else None,
        "errors": error_counts,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if success_ratio < args.minimum_success_ratio:
        print(
            f"錯誤：連線成功率 {success_ratio:.1%} 低於要求 "
            f"{args.minimum_success_ratio:.1%}，不建議將此段當成正常訓練資料。",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"錯誤：{error}", file=sys.stderr)
        raise SystemExit(2) from error
