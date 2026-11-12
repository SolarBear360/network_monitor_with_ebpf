#!/usr/bin/env python3
"""Stream selected timestamp windows from PCAP members inside a ZIP archive.

The CICDDoS2019 archives expand to tens of gigabytes.  This utility reads only
the requested archive members and writes packets in the half-open interval
``start_epoch <= timestamp < end_epoch`` to one ordinary PCAP file.
"""

from __future__ import annotations

import argparse
import json
import struct
import zipfile
from pathlib import Path


PCAP_LAYOUTS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a timestamp window from selected PCAP members in a ZIP."
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument(
        "--entry",
        action="append",
        required=True,
        help="ZIP member name; repeat for consecutive capture chunks",
    )
    parser.add_argument("--start-epoch", type=float, required=True)
    parser.add_argument("--end-epoch", type=float, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def pcap_layout(header: bytes) -> tuple[str, float, int]:
    if len(header) != 24 or header[:4] not in PCAP_LAYOUTS:
        raise ValueError("ZIP member is not a supported classic PCAP file")
    endian, divisor = PCAP_LAYOUTS[header[:4]]
    link_type = struct.unpack(f"{endian}I", header[20:24])[0]
    return endian, divisor, link_type


def main() -> None:
    args = parse_args()
    if not args.archive.is_file():
        raise FileNotFoundError(args.archive)
    if args.start_epoch >= args.end_epoch:
        raise ValueError("--start-epoch must be less than --end-epoch")
    if args.output.exists():
        raise FileExistsError(f"Refusing to overwrite existing output: {args.output}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    packet_count = 0
    byte_count = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    reference_header: bytes | None = None
    reference_layout: tuple[str, float, int] | None = None

    with zipfile.ZipFile(args.archive) as archive, args.output.open("wb") as output:
        missing = [entry for entry in args.entry if entry not in archive.namelist()]
        if missing:
            raise FileNotFoundError(f"Missing ZIP members: {', '.join(missing)}")

        for entry in args.entry:
            with archive.open(entry) as capture:
                global_header = capture.read(24)
                layout = pcap_layout(global_header)
                if reference_header is None:
                    reference_header = global_header
                    reference_layout = layout
                    output.write(global_header)
                elif layout != reference_layout:
                    raise ValueError(f"PCAP layout differs in ZIP member {entry}")

                endian, timestamp_divisor, _ = layout
                while True:
                    packet_header = capture.read(16)
                    if not packet_header:
                        break
                    if len(packet_header) != 16:
                        raise ValueError(f"Truncated packet header in ZIP member {entry}")
                    seconds, fraction, captured_length, _ = struct.unpack(
                        f"{endian}IIII", packet_header
                    )
                    raw = capture.read(captured_length)
                    if len(raw) != captured_length:
                        raise ValueError(f"Truncated packet data in ZIP member {entry}")
                    timestamp = seconds + fraction / timestamp_divisor
                    if args.start_epoch <= timestamp < args.end_epoch:
                        output.write(packet_header)
                        output.write(raw)
                        packet_count += 1
                        byte_count += 16 + captured_length
                        if first_timestamp is None:
                            first_timestamp = timestamp
                        last_timestamp = timestamp

    if packet_count == 0:
        args.output.unlink()
        raise ValueError("No packets fell inside the requested timestamp window")

    print(
        json.dumps(
            {
                "archive": str(args.archive.resolve()),
                "entries": args.entry,
                "output": str(args.output.resolve()),
                "start_epoch": args.start_epoch,
                "end_epoch": args.end_epoch,
                "first_packet_epoch": first_timestamp,
                "last_packet_epoch": last_timestamp,
                "packets": packet_count,
                "pcap_bytes": 24 + byte_count,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
