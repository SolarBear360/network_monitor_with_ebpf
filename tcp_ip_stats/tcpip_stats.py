#!/usr/bin/env python3
"""Read per-flow eBPF counters once per second and detect SYN Flood traffic."""

from __future__ import annotations

import argparse
import csv
import ctypes
import os
import time
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path

from syn_flood_runtime import SynFloodDetector


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_STATS_CSV = SCRIPT_DIR / "tcp_stats.csv"
DEFAULT_PREDICTION_CSV = SCRIPT_DIR / "syn_flood_predictions.csv"
DEFAULT_RUNTIME_MODEL = (
    SCRIPT_DIR
    / "model_handoff"
    / "syn-window-full6-v1"
    / "runtime_model.json"
)

STATS_CSV_FIELDS = [
    "timestamp",
    "tcp_packets",
    "tcp_bytes",
    "syn_only_packets",
    "syn_ack_packets",
    "active_source_ips",
    "syn_source_ips",
    "syn_flows",
    "established_connections",
]

PREDICTION_CSV_FIELDS = [
    "timestamp",
    "interval_seconds",
    "tcp_packets",
    "tcp_bytes",
    "syn_only_packets",
    "active_source_ips",
    "established_connections",
    "attack_probability",
    "model_positive",
    "candidate",
    "attack_active",
    "status",
    "recent_hits",
    "recent_window_size",
    "normal_streak",
    "data_quality_ok",
    "data_quality_reason",
]

# ========= 基本設定 =========

STATS_MAP_PATH = "/sys/fs/bpf/ip/globals/tcp_flow_map"
SYS_BPF = 321  # x86_64

BPF_OBJ_GET = 7
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_GET_NEXT_KEY = 4

TCP_STATE_ESTABLISHED = 3

libc = ctypes.CDLL("libc.so.6", use_errno=True)


# ========= struct 定義（要和 eBPF 完全一致） =========

class FlowKey(ctypes.Structure):
    """Must stay byte-for-byte compatible with struct tcp_flow_key in eBPF."""

    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]


class FlowStats(ctypes.Structure):
    """Must stay byte-for-byte compatible with struct tcp_flow_stats in eBPF."""

    _fields_ = [
        ("packets", ctypes.c_uint64),
        ("bytes", ctypes.c_uint64),
        ("syn", ctypes.c_uint64),
        ("ack", ctypes.c_uint64),
        ("connection_state", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 7),
        ("first_seen", ctypes.c_uint64),
        ("last_seen", ctypes.c_uint64),
    ]


# PERCPU map 的每個 key 都會有一份「每 CPU 的 value」，所以讀取時要先
# 建立可容納所有 CPU value 的陣列，之後再將它們加總。
NCPU = os.cpu_count() or 1
StatsArray = FlowStats * NCPU


# ========= bpf_attr：傳給 bpf() system call 的參數格式 =========

class BPFAttrObjGet(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("map_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


class BPFAttrLookup(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


class BPFAttrGetNextKey(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("next_key", ctypes.c_uint64),
    ]


# ========= syscall wrapper =========

def bpf_syscall(command, attribute):
    result = libc.syscall(
        SYS_BPF, command, ctypes.byref(attribute), ctypes.sizeof(attribute)
    )
    if result < 0:
        error_number = ctypes.get_errno()
        if error_number == 2:  # ENOENT
            return None
        raise OSError(error_number, os.strerror(error_number))
    return result


# ========= 打開及讀取 pinned BPF map =========

def get_map_fd(path):
    path_buffer = ctypes.create_string_buffer(path.encode())
    attribute = BPFAttrObjGet()
    attribute.pathname = ctypes.addressof(path_buffer)
    return bpf_syscall(BPF_OBJ_GET, attribute)


def lookup_percpu(map_fd, key):
    values = StatsArray()
    attribute = BPFAttrLookup()
    attribute.map_fd = map_fd
    attribute.key = ctypes.addressof(key)
    attribute.value = ctypes.addressof(values)
    result = bpf_syscall(BPF_MAP_LOOKUP_ELEM, attribute)
    return None if result is None else values


def aggregate(values):
    """整合同一個 flow key 在每個 CPU 上的統計值。"""
    result = FlowStats()
    first = True
    for value in values:
        result.packets += value.packets
        result.bytes += value.bytes
        result.syn += value.syn
        result.ack += value.ack

        # first_seen 取所有 CPU 中最早的時間。
        if first or value.first_seen < result.first_seen:
            result.first_seen = value.first_seen
        # last_seen 取所有 CPU 中最新的時間。
        if first or value.last_seen > result.last_seen:
            result.last_seen = value.last_seen
        # connection_state 理論上各 CPU 相同，沿用原版作法取第一份。
        if first:
            result.connection_state = value.connection_state
        first = False
    return result


def iterate_keys(map_fd):
    """逐一取得 map 中的 key，並複製成不會被下一輪覆蓋的物件。"""
    keys = []
    next_key = FlowKey()
    key_pointer = 0  # 第一次傳 NULL，要求取得 map 的第一個 key。

    while True:
        attribute = BPFAttrGetNextKey()
        attribute.map_fd = map_fd
        attribute.key = key_pointer
        attribute.next_key = ctypes.addressof(next_key)
        result = bpf_syscall(BPF_MAP_GET_NEXT_KEY, attribute)
        if result is None:
            break

        # 複製 key，避免 next_key 在下一輪 bpf() 呼叫時被覆蓋。
        copied_key = FlowKey()
        ctypes.memmove(
            ctypes.byref(copied_key), ctypes.byref(next_key), ctypes.sizeof(FlowKey)
        )
        keys.append(copied_key)
        key_pointer = ctypes.addressof(next_key)

    return keys


def counter_delta(current, previous):
    """計算累積值差；若下降則視為計數器重置或 flow key 被重用。"""
    return current - previous if current >= previous else current


def collect_snapshot(
    map_fd,
    previous_flow_stats,
    previous_syn_ips,
    previous_established_flows,
):
    """讀取一次 map，回傳本輪新增量與下一輪計算差值所需的狀態。"""

    # ========================================
    # 每一輪（一個 userspace 取樣窗口）的統計資料
    # ========================================
    interval = {
        "tcp_packets": 0,
        "tcp_bytes": 0,
        "syn_only_packets": 0,
        "syn_ack_packets": 0,
        "active_source_ips": 0,
        "syn_source_ips": 0,
        "syn_flows": 0,
        "established_connections": 0,
    }
    current_flow_stats = {}
    active_source_ips = set()
    syn_source_ips = set()
    current_syn_ips = set()
    syn_flows = set()
    current_established_flows = set()

    # ========================================
    # 取得目前所有 flow，保存累積值並與上一輪比較
    # ========================================
    for key in iterate_keys(map_fd):
        values = lookup_percpu(map_fd, key)
        if values is None:
            # 過期清理程式可能在掃描期間刪除 Map 項目。
            continue

        result = aggregate(values)
        flow_key = bytes(key)
        current = (result.packets, result.bytes, result.syn, result.ack)
        current_flow_stats[flow_key] = current

        # BPF map 內是累積值；userspace 必須用「本輪 - 上輪」得到這個
        # 取樣窗口真正新增的封包與 bytes。新 flow 則以目前值當新增量。
        previous = previous_flow_stats.get(flow_key)
        if previous is None:
            delta_packets, delta_bytes, delta_syn, delta_ack = current
        else:
            delta_packets = counter_delta(current[0], previous[0])
            delta_bytes = counter_delta(current[1], previous[1])
            delta_syn = counter_delta(current[2], previous[2])
            delta_ack = counter_delta(current[3], previous[3])

        interval["tcp_packets"] += delta_packets
        interval["tcp_bytes"] += delta_bytes

        # 只要某來源的任一 flow 在本輪有新增封包，就把它算成本輪活動來源。
        # 同一 IP 在同一輪只算一次；下一輪仍有送封包時會再次計入。
        if delta_packets > 0:
            active_source_ips.add(key.src_ip)

        # 純 SYN = SYN 計數 - SYN/ACK 計數。max(0, ...) 可避免讀取多 CPU
        # value 時短暫不一致而產生負數。
        delta_syn_only = max(0, delta_syn - delta_ack)
        interval["syn_only_packets"] += delta_syn_only
        interval["syn_ack_packets"] += delta_ack

        # 本輪收到純 SYN 的每個來源 IP／TCP 5-tuple 各只計一次。
        # 同輪重傳會增加 syn_only_packets，但不會增加不同 IP 或 5-tuple；
        # 下一輪又收到時，則會在新一輪重新計入。
        if delta_syn_only > 0:
            syn_source_ips.add(key.src_ip)
            syn_flows.add(flow_key)

        cumulative_syn_only = max(0, result.syn - result.ack)
        if cumulative_syn_only > 0:
            current_syn_ips.add(key.src_ip)

        # 只有第一次觀察到 flow 進入 ESTABLISHED 時，才算一筆完成連線。
        if result.connection_state == TCP_STATE_ESTABLISHED:
            current_established_flows.add(flow_key)
            if flow_key not in previous_established_flows:
                interval["established_connections"] += 1

    interval["active_source_ips"] = len(active_source_ips)
    interval["syn_source_ips"] = len(syn_source_ips)
    interval["syn_flows"] = len(syn_flows)
    return (
        interval,
        current_flow_stats,
        current_syn_ips,
        current_established_flows,
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="每秒讀取 eBPF TCP 統計，寫入 CSV 並進行 SYN Flood 推論。"
    )
    parser.add_argument("--stats-csv", type=Path, default=DEFAULT_STATS_CSV)
    parser.add_argument("--prediction-csv", type=Path, default=DEFAULT_PREDICTION_CSV)
    parser.add_argument("--model-runtime", type=Path, default=DEFAULT_RUNTIME_MODEL)
    parser.add_argument(
        "--no-model", action="store_true", help="只收集統計，不執行模型"
    )
    parser.add_argument(
        "--probability-threshold", type=float, default=None,
        help="覆寫模型機率門檻（預設 0.5）",
    )
    parser.add_argument(
        "--minimum-syn", type=int, default=None,
        help="覆寫當秒最少純 SYN 數（預設 5）",
    )
    parser.add_argument(
        "--alert-window", type=int, default=None,
        help="持續性規則的最近秒數（預設 3）",
    )
    parser.add_argument(
        "--alert-hits", type=int, default=None,
        help="最近窗口中至少幾秒異常（預設 2）",
    )
    parser.add_argument(
        "--clear-seconds", type=int, default=None,
        help="連續幾秒正常後解除攻擊狀態（預設 3）",
    )
    return parser.parse_args()


def build_detector(args):
    if args.no_model:
        return None
    if not args.model_runtime.is_file():
        raise FileNotFoundError(f"找不到模型 JSON：{args.model_runtime}")
    return SynFloodDetector.load(
        args.model_runtime,
        probability_threshold=args.probability_threshold,
        minimum_syn_packets=args.minimum_syn,
        persistence_window_seconds=args.alert_window,
        persistence_required_hits=args.alert_hits,
        clear_after_normal_seconds=args.clear_seconds,
    )


def open_csv_writer(stack, path, expected_fields):
    """Open an append-only CSV without mixing incompatible schemas."""
    output_file = stack.enter_context(
        path.open("a+", newline="", encoding="utf-8")
    )
    output_file.seek(0)
    existing_header = next(csv.reader(output_file), None)
    if existing_header is None:
        writer = csv.writer(output_file)
        writer.writerow(expected_fields)
        output_file.flush()
    elif existing_header != expected_fields:
        raise ValueError(
            f"CSV 欄位格式已更新，不能繼續附加到舊檔：{path}\n"
            "請先備份或改名舊檔，或使用 --stats-csv / --prediction-csv "
            "指定新的輸出檔。"
        )

    output_file.seek(0, os.SEEK_END)
    return output_file, csv.writer(output_file)


def open_prediction_writer(stack, path):
    return open_csv_writer(stack, path, PREDICTION_CSV_FIELDS)


def print_interval(interval_seconds, interval):
    print("----------------------------------------")
    print(f"時間窗口                      : {interval_seconds:.3f} 秒")
    print(f"TCP 封包數量                    : {interval['tcp_packets']}")
    print(f"TCP bytes                       : {interval['tcp_bytes']}")
    print(f"SYN=1 ACK=0 封包數量            : {interval['syn_only_packets']}")
    print(f"SYN=1 ACK=1 封包數量            : {interval['syn_ack_packets']}")
    print(f"本輪活動來源 IP 數量             : {interval['active_source_ips']}")
    print(f"本輪純 SYN 來源 IP 數量          : {interval['syn_source_ips']}")
    print(f"本輪純 SYN 5-tuple 數量          : {interval['syn_flows']}")
    print(f"本輪新觀察到的完成連線數          : {interval['established_connections']}")


def main():
    # ========= 主程式：初始化 map、模型與 CSV =========
    args = parse_args()
    detector = build_detector(args)
    stats_fd = get_map_fd(STATS_MAP_PATH)
    if stats_fd is None:
        raise FileNotFoundError(
            f"找不到 pinned BPF map：{STATS_MAP_PATH}，請先執行 init.sh"
        )

    args.stats_csv.parent.mkdir(parents=True, exist_ok=True)
    if detector is not None:
        args.prediction_csv.parent.mkdir(parents=True, exist_ok=True)

    print(f"統計 CSV：{args.stats_csv}")
    if detector is None:
        print("模型：已停用（只收集統計）")
    else:
        print(f"模型：{args.model_runtime}")
        print(
            "攻擊標準："
            f"機率 >= {detector.probability_threshold:g}、"
            f"純 SYN >= {detector.minimum_syn_packets}，"
            f"最近 {detector.persistence_window_seconds} 秒至少 "
            f"{detector.persistence_required_hits} 秒異常；"
            f"連續 {detector.clear_after_normal_seconds} 秒正常後解除。"
        )
        print(f"預測 CSV：{args.prediction_csv}")

    # 上一輪每個 flow 的累積數據：
    # key = bytes(FlowKey)，value = (packets, bytes, syn, ack)。
    previous_flow_stats = {}
    # 上一輪已觀察到 ESTABLISHED 的 flow，避免同一連線重複計數。
    previous_established_flows = set()
    # 保留原版的歷史 SYN IP 狀態，供 collect_snapshot 回傳／後續擴充使用。
    previous_syn_ips = set()
    previous_sample_started = None
    first_iteration = True

    with ExitStack() as stack:
        stats_file, stats_writer = open_csv_writer(
            stack, args.stats_csv, STATS_CSV_FIELDS
        )

        prediction_file = None
        prediction_writer = None
        if detector is not None:
            prediction_file, prediction_writer = open_prediction_writer(
                stack, args.prediction_csv
            )

        try:
            while True:
                sample_started = time.monotonic()
                interval_seconds = (
                    None
                    if previous_sample_started is None
                    else sample_started - previous_sample_started
                )
                is_first_iteration = first_iteration

                (
                    interval,
                    previous_flow_stats,
                    previous_syn_ips,
                    previous_established_flows,
                ) = collect_snapshot(
                    stats_fd,
                    previous_flow_stats,
                    previous_syn_ips,
                    previous_established_flows,
                )

                previous_sample_started = sample_started
                first_iteration = False

                if is_first_iteration:
                    # 第一次掃描只建立累積值基準；Map 裡原本存在的資料並非
                    # 完整的一秒窗口，因此不寫 CSV，也不交給模型。
                    print("已建立 BPF map 基準快照，下一秒開始預測。")
                else:
                    # ========================================
                    # 時間、終端輸出與統計 CSV
                    # ========================================
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print_interval(interval_seconds, interval)

                    stats_writer.writerow([
                        timestamp,
                        interval["tcp_packets"],
                        interval["tcp_bytes"],
                        interval["syn_only_packets"],
                        interval["syn_ack_packets"],
                        interval["active_source_ips"],
                        interval["syn_source_ips"],
                        interval["syn_flows"],
                        interval["established_connections"],
                    ])
                    stats_file.flush()

                    if detector is not None:
                        # ========================================
                        # full_6 模型推論與預測 CSV
                        # ========================================
                        detection = detector.evaluate(
                            tcp_packets=interval["tcp_packets"],
                            tcp_bytes=interval["tcp_bytes"],
                            syn_only_packets=interval["syn_only_packets"],
                            active_source_ips=interval["active_source_ips"],
                            established_connections=interval[
                                "established_connections"
                            ],
                            interval_seconds=interval_seconds,
                        )
                        probability_text = (
                            "N/A"
                            if detection.attack_probability is None
                            else f"{detection.attack_probability:.4f}"
                        )
                        print(f"攻擊機率                      : {probability_text}")
                        print(
                            f"當前判斷                      : {detection.status} "
                            f"(近期 {detection.recent_hits}/"
                            f"{detection.recent_window_size} 秒異常)"
                        )
                        if not detection.data_quality_ok:
                            print(f"資料品質                      : {detection.data_quality_reason}")

                        prediction_writer.writerow([
                            timestamp,
                            f"{interval_seconds:.6f}",
                            interval["tcp_packets"],
                            interval["tcp_bytes"],
                            interval["syn_only_packets"],
                            interval["active_source_ips"],
                            interval["established_connections"],
                            "" if detection.attack_probability is None else (
                                f"{detection.attack_probability:.12f}"
                            ),
                            int(detection.model_positive),
                            int(detection.candidate),
                            int(detection.attack_active),
                            detection.status,
                            detection.recent_hits,
                            detection.recent_window_size,
                            detection.normal_streak,
                            int(detection.data_quality_ok),
                            detection.data_quality_reason,
                        ])
                        prediction_file.flush()

                # 扣掉本輪處理時間，使兩次快照的開始時間盡量相隔一秒。
                remaining = 1.0 - (time.monotonic() - sample_started)
                if remaining > 0:
                    time.sleep(remaining)
        except KeyboardInterrupt:
            print("\n已停止 TCP 統計與 SYN Flood 偵測。")


if __name__ == "__main__":
    main()
