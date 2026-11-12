#!/usr/bin/env python3
"""替隔離實驗中的單一正常 Client 挑選多個未使用私有 IPv4。"""

from __future__ import annotations

import argparse
import ipaddress


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subnet", required=True, help="私有 IPv4 CIDR")
    parser.add_argument("--count", required=True, type=int)
    parser.add_argument(
        "--exclude",
        default="",
        help="以逗號分隔、已被 Docker 使用的位址",
    )
    return parser.parse_args()


def allocate_addresses(
    subnet: str,
    count: int,
    excluded_values: list[str] | None = None,
) -> list[str]:
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
        raise ValueError("--subnet 必須是 IPv4 CIDR") from error
    if not network.is_private:
        raise ValueError("--subnet 必須是私有網段")
    if not 1 <= count <= 64:
        raise ValueError("--count 必須介於 1 到 64")

    excluded: set[ipaddress.IPv4Address] = set()
    for value in excluded_values or []:
        if not value.strip():
            continue
        address = ipaddress.IPv4Address(value.strip())
        if address not in network:
            raise ValueError(f"排除位址不在網段內：{address}")
        excluded.add(address)

    selected: list[ipaddress.IPv4Address] = []
    candidate_value = int(network.broadcast_address) - 1
    minimum_value = int(network.network_address) + 1
    while candidate_value >= minimum_value and len(selected) < count:
        candidate = ipaddress.IPv4Address(candidate_value)
        if candidate not in excluded:
            selected.append(candidate)
        candidate_value -= 1

    if len(selected) != count:
        raise ValueError(f"網段 {network} 沒有 {count} 個可用位址")
    return [str(address) for address in reversed(selected)]


def main() -> None:
    args = parse_args()
    excluded = [value for value in args.exclude.split(",") if value.strip()]
    print(",".join(allocate_addresses(args.subnet, args.count, excluded)))


if __name__ == "__main__":
    main()

