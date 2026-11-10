#!/usr/bin/env python3
"""Generate bounded normal HTTP keep-alive traffic without k6."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import random
import statistics
import threading
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--vus", required=True, type=int)
    parser.add_argument("--duration", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--minimum-success-ratio", type=float, default=0.90)
    return parser.parse_args()


def validate(args: argparse.Namespace) -> None:
    address = ipaddress.ip_address(args.host)
    if address.version != 4 or not (address.is_private or address.is_loopback):
        raise ValueError("--host must be a private IPv4 address")
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be in 1..65535")
    if not 1 <= args.vus <= 200:
        raise ValueError("--vus must be in 1..200")
    if not 5 <= args.duration <= 300:
        raise ValueError("--duration must be in 5..300 seconds")
    if not 0.0 <= args.minimum_success_ratio <= 1.0:
        raise ValueError("--minimum-success-ratio must be in 0..1")


def main() -> None:
    args = parse_args()
    validate(args)
    deadline = time.monotonic() + args.duration
    lock = threading.Lock()
    totals = {"requests": 0, "successes": 0, "failures": 0}
    latencies: list[float] = []

    def worker(worker_id: int) -> None:
        connection: http.client.HTTPConnection | None = None
        rng = random.Random(20261109 + worker_id)
        while time.monotonic() < deadline:
            started = time.perf_counter()
            try:
                if connection is None:
                    connection = http.client.HTTPConnection(
                        args.host, args.port, timeout=args.timeout
                    )
                connection.request(
                    "GET",
                    "/",
                    headers={
                        "Host": args.host,
                        "Connection": "keep-alive",
                        "User-Agent": "syn-flood-final-holdout-normal-client",
                    },
                )
                response = connection.getresponse()
                response.read()
                ok = response.status < 400
                latency = (time.perf_counter() - started) * 1000
            except (OSError, http.client.HTTPException):
                ok = False
                latency = None
                if connection is not None:
                    connection.close()
                connection = None

            with lock:
                totals["requests"] += 1
                if ok:
                    totals["successes"] += 1
                    if latency is not None:
                        latencies.append(latency)
                else:
                    totals["failures"] += 1
            time.sleep(0.2 + rng.random() * 0.8)

        if connection is not None:
            connection.close()

    started_epoch = time.time()
    started_monotonic = time.monotonic()
    threads = [
        threading.Thread(target=worker, args=(index,), daemon=True)
        for index in range(args.vus)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    summary = {
        "host": args.host,
        "port": args.port,
        "vus": args.vus,
        "configured_duration_seconds": args.duration,
        "actual_elapsed_seconds": time.monotonic() - started_monotonic,
        "started_epoch": started_epoch,
        **totals,
        "success_ratio": (
            totals["successes"] / totals["requests"] if totals["requests"] else 0.0
        ),
        "mean_latency_ms": statistics.fmean(latencies) if latencies else None,
        "maximum_latency_ms": max(latencies) if latencies else None,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if summary["success_ratio"] < args.minimum_success_ratio:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
