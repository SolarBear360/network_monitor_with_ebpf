
import subprocess
import json
import csv
import time
import os
from datetime import datetime

MAP_PATHS = [
    "/sys/fs/bpf/ip/globals/tcp_flow_map",
    "/sys/fs/bpf/ip/globals/tcp_bucket_maps",
]

OUTPUT_FILE = "bpf_memory_usage.csv"
INTERVAL = 1


def get_map_info(map_path):
    """取得指定 BPF Map 的資訊"""

    result = subprocess.run(
        [
            "sudo",
            "bpftool",
            "-j",
            "map",
            "show",
            "pinned",
            map_path
        ],
        capture_output=True,
        text=True,
        check=True
    )

    data = json.loads(result.stdout)

    # 不同版本或查詢方式可能回傳物件或陣列
    if isinstance(data, list):
        if not data:
            raise ValueError(f"找不到 Map: {map_path}")
        data = data[0]

    return data


def record_memory_usage():
    timestamp = datetime.now().isoformat(
        timespec="seconds"
    )

    records = []
    total_memory = 0
    total_known_maps = 0

    for map_path in MAP_PATHS:
        try:
            info = get_map_info(map_path)

            # bpftool JSON 欄位
            memory = info.get("bytes_memlock")

            if memory is not None:
                total_memory += memory
                total_known_maps += 1

            records.append({
                "timestamp": timestamp,
                "map_name": info.get("name", ""),
                "map_id": info.get("id", ""),
                "map_type": info.get("type", ""),
                "key_size": info.get("bytes_key", ""),
                "value_size": info.get("bytes_value", ""),
                "max_entries": info.get("max_entries", ""),
                "used_entries": info.get("used_entries", ""),
                "memory_bytes": memory,
                "memory_kb": (
                    round(memory / 1024, 2)
                    if memory is not None else ""
                ),
                "map_path": map_path,
            })

        except (subprocess.CalledProcessError,
                json.JSONDecodeError,
                OSError,
                ValueError) as e:

            print(f"[ERROR] {map_path}: {e}")

    # 總記憶體使用量
    records.append({
        "timestamp": timestamp,
        "map_name": "TOTAL",
        "map_id": "",
        "map_type": "",
        "key_size": "",
        "value_size": "",
        "max_entries": "",
        "used_entries": "",
        "memory_bytes": (
            total_memory if total_known_maps == len(MAP_PATHS)
            else ""
        ),
        "memory_kb": (
            round(total_memory / 1024, 2)
            if total_known_maps == len(MAP_PATHS)
            else ""
        ),
        "map_path": "",
    })

    return records


def main():
    fieldnames = [
        "timestamp",
        "map_name",
        "map_id",
        "map_type",
        "key_size",
        "value_size",
        "max_entries",
        "used_entries",
        "memory_bytes",
        "memory_kb",
        "map_path",
    ]

    file_exists = os.path.exists(OUTPUT_FILE)

    with open(
        OUTPUT_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        if not file_exists:
            writer.writeheader()

        print("開始記錄 BPF Map 記憶體使用量...")

        while True:
            start = time.monotonic()

            records = record_memory_usage()

            writer.writerows(records)
            file.flush()

            for record in records:
                print(
                    record["timestamp"],
                    record["map_name"],
                    record["memory_kb"],
                    "KB"
                )

            elapsed = time.monotonic() - start
            time.sleep(max(0, INTERVAL - elapsed))


if __name__ == "__main__":
    main()
