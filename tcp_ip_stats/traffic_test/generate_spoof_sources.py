#!/usr/bin/env python3
"""Choose deterministic unused-looking source IPs inside one Docker subnet."""

from __future__ import annotations

import argparse
import ipaddress


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subnet", required=True)
    parser.add_argument("--count", required=True, type=int)
    parser.add_argument("--exclude", action="append", default=[])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    network = ipaddress.ip_network(args.subnet, strict=False)
    if network.version != 4 or not network.is_private:
        raise ValueError("spoof sources must come from a private IPv4 Docker subnet")
    if not 1 <= args.count <= 128:
        raise ValueError("--count must be in 1..128")

    excluded = {ipaddress.ip_address(value) for value in args.exclude if value}
    selected: list[str] = []

    # Work backward from the end of the subnet. Docker normally allocates real
    # container addresses from the beginning, reducing collision risk.
    candidate_value = int(network.broadcast_address) - 1
    minimum_value = int(network.network_address) + 1
    while candidate_value >= minimum_value and len(selected) < args.count:
        candidate = ipaddress.ip_address(candidate_value)
        if candidate not in excluded:
            selected.append(str(candidate))
        candidate_value -= 1

    if len(selected) != args.count:
        raise ValueError("Docker subnet does not contain enough safe spoof addresses")
    print(",".join(selected))


if __name__ == "__main__":
    main()
