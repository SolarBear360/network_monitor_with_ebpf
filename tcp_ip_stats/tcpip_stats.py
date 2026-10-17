import ctypes
import os
import socket
import struct
import time
from collections import defaultdict

import csv
import time
from datetime import datetime


CSV_FILE = "tcp_stats.csv"

# ========= 基本設定 =========
STATS_MAP_PATH = "/sys/fs/bpf/ip/globals/tcp_flow_map"
SYS_BPF = 321  # x86_64

BPF_OBJ_GET = 7
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_GET_NEXT_KEY = 4
BPF_MAP_DELETE_ELEM = 2

TCP_STATE_UNKNOWN = 0
TCP_STATE_SYN_SENT = 1
TCP_STATE_SYN_RECEIVED = 2
TCP_STATE_ESTABLISHED = 3

AF_INET = 2
AF_INET6 = 10

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# ========= struct 定義（要和 eBPF 完全一致） =========

class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),

        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),

        ("protocol", ctypes.c_uint8),

        # C struct alignment / padding
        ("pad", ctypes.c_uint8 * 3),
    ]

class FlowStats(ctypes.Structure):
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

# PERCPU array
NCPU = os.cpu_count()
StatsArray = FlowStats * NCPU

# ========= bpf_attr =========

class BPFAttrObjGet(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
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

def bpf_syscall(cmd, attr):
    ret = libc.syscall(SYS_BPF, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        err = ctypes.get_errno()
        if err == 2:  # ENOENT
            return None
        raise OSError(err, os.strerror(err))
    return ret

# ========= 打開 map =========

def get_map_fd(path):
    path_buf = ctypes.create_string_buffer(path.encode())

    attr = BPFAttrObjGet()
    attr.pathname = ctypes.addressof(path_buf)

    return bpf_syscall(BPF_OBJ_GET, attr)

def lookup_percpu(fd, key):
    values = StatsArray()

    attr = BPFAttrLookup()
    attr.map_fd = fd
    attr.key = ctypes.addressof(key)
    attr.value = ctypes.addressof(values)

    bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)
    return values

def aggregate(values):
    #整合每個cpu內的值
    result = FlowStats()

    result.packets = 0
    result.bytes = 0
    result.syn = 0
    result.ack = 0

    result.first_seen = 0
    result.last_seen = 0
    result.connection_state = 0

    first = True

    for v in values:
        result.packets += v.packets
        result.bytes += v.bytes

        result.syn += v.syn
        result.ack += v.ack

        # first_seen：取最早
        if first or v.first_seen < result.first_seen:
            result.first_seen = v.first_seen

        # last_seen：取最新
        if first or v.last_seen > result.last_seen:
            result.last_seen = v.last_seen

        # state：假設每個 CPU 相同，取第一個
        if first:
            result.connection_state = v.connection_state

        first = False

    return result

def iterate_keys(fd):
    keys = []

    next_key = FlowKey()
    key_ptr = 0  # 第一次傳 NULL

    while True:
        attr = BPFAttrGetNextKey()
        attr.map_fd = fd
        attr.key = key_ptr
        attr.next_key = ctypes.addressof(next_key)

        ret = bpf_syscall(BPF_MAP_GET_NEXT_KEY, attr)
        if ret is None:
            break

        # copy key（避免被覆蓋）
        k = FlowKey()
        ctypes.memmove(ctypes.byref(k), ctypes.byref(next_key), ctypes.sizeof(FlowKey))
        keys.append(k)

        key_ptr = ctypes.addressof(next_key)

    return keys


# ========= 主程式 =========


def main():
    stats_fd = get_map_fd(STATS_MAP_PATH)

    # 上一輪每個 flow 的累積數據
    # key: bytes(key)
    # value: (packets, bytes, syn, ack)
    previous_flow_stats = {}

    # 上一輪已完成 TCP handshake 的 flow
    previous_established_flows = set()

    # 上一輪符合 syn_only > 0 的來源 IP
    previous_syn_ips = set()

    with open(CSV_FILE, "a", newline="") as csv_file:
        writer = csv.writer(csv_file)

        if csv_file.tell() == 0:
            writer.writerow([
                "timestamp",
                "tcp_packets",
                "tcp_bytes",
                "syn_only_packets",
                "syn_ack_packets",
                "syn_source_ips",
                "syn_flows",
                "established_connections"
            ])
            csv_file.flush()

        first_iteration = True

        while True:
            # ========================================
            # 每一輪統計資料
            # ========================================

            interval_packets = 0
            interval_bytes = 0
            interval_syn_only = 0
            interval_syn_ack = 0

            current_syn_ips = set()
            new_syn_source_ips = set()
            syn_flows = set()

            established_connections = 0
            current_established_flows = set()

            # 保存本輪所有 flow 的累積數據
            current_flow_stats = {}

            # ========================================
            # 取得目前所有 flow
            # ========================================

            keys = iterate_keys(stats_fd)

            for key in keys:
                values = lookup_percpu(stats_fd, key)

                if values is None:
                    # Map 項目可能在掃描期間被刪除
                    continue

                result = aggregate(values)
                flow_key = bytes(key)

                # ====================================
                # 1. 計算這個 flow 的累積數據差值
                # ====================================

                current_packets = result.packets
                current_bytes = result.bytes
                current_syn = result.syn
                current_ack = result.ack

                # 保存本輪累積值，供下一輪使用
                current_flow_stats[flow_key] = (
                    current_packets,
                    current_bytes,
                    current_syn,
                    current_ack
                )

                if flow_key not in previous_flow_stats:
                    # 新 flow：目前累積值視為本輪新增量
                    delta_packets = current_packets
                    delta_bytes = current_bytes
                    delta_syn = current_syn
                    delta_ack = current_ack

                else:
                    # 舊 flow：與同一個 flow 的上一輪數值比較
                    prev = previous_flow_stats[flow_key]

                    # 若計數器下降，視為計數器重置或 flow key 重用
                    # 使用目前數值，避免產生負數
                    delta_packets = (
                        current_packets - prev[0]
                        if current_packets >= prev[0]
                        else current_packets
                    )

                    delta_bytes = (
                        current_bytes - prev[1]
                        if current_bytes >= prev[1]
                        else current_bytes
                    )

                    delta_syn = (
                        current_syn - prev[2]
                        if current_syn >= prev[2]
                        else current_syn
                    )

                    delta_ack = (
                        current_ack - prev[3]
                        if current_ack >= prev[3]
                        else current_ack
                    )

                # ====================================
                # 2. 累加本輪新增的封包與 bytes
                # ====================================

                interval_packets += delta_packets
                interval_bytes += delta_bytes

                # SYN-only = SYN - SYN/ACK
                interval_syn_only += delta_syn - delta_ack

                # SYN/ACK
                interval_syn_ack += delta_ack

                # ====================================
                # 3. 偵測本輪新出現的 SYN 來源 IP
                # ====================================

                syn_only = current_syn - current_ack

                if syn_only > 0:
                    src_ip = key.src_ip

                    current_syn_ips.add(src_ip)

                    if src_ip not in previous_syn_ips:
                        new_syn_source_ips.add(src_ip)
                        syn_flows.add(flow_key)

                # ====================================
                # 4. 偵測本輪新觀察到的已完成連線
                # ====================================

                if result.connection_state == TCP_STATE_ESTABLISHED:
                    current_established_flows.add(flow_key)

                    if flow_key not in previous_established_flows:
                        established_connections += 1

            # ========================================
            # 5. 第一次執行時的處理
            # ========================================

            # 第一次掃描時，所有仍在 Map 中的累積值
            # 都會被視為本輪數據。
            first_iteration = False

            # ========================================
            # 6. 更新歷史資料
            # ========================================

            # 用本輪快照取代上一輪快照。
            # 已從 Map 消失的 flow 不會保留在字典中。
            previous_flow_stats = current_flow_stats

            previous_syn_ips = current_syn_ips

            previous_established_flows = (
                current_established_flows
            )

            # ========================================
            # 7. 時間
            # ========================================

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            # ========================================
            # 8. 終端輸出
            # ========================================

            print("----------------------------------------")
            print(f"TCP 封包數量                    : {interval_packets}")
            print(f"TCP bytes                       : {interval_bytes}")
            print(f"SYN=1 ACK=0 封包數量            : {interval_syn_only}")
            print(f"SYN=1 ACK=1 封包數量            : {interval_syn_ack}")
            print(f"本輪新 SYN 來源 IP 數量          : {len(new_syn_source_ips)}")
            print(f"本輪新 SYN Flow 數量             : {len(syn_flows)}")
            print(f"本輪新觀察到的完成連線數          : {established_connections}")

            # ========================================
            # 9. 寫入 CSV
            # ========================================

            writer.writerow([
                timestamp,
                interval_packets,
                interval_bytes,
                interval_syn_only,
                interval_syn_ack,
                len(new_syn_source_ips),
                len(syn_flows),
                established_connections
            ])

            csv_file.flush()

            time.sleep(1)


    



if __name__ == "__main__":
    main()