import ctypes
import os
import socket
import struct
import time
from collections import defaultdict

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

BUCKET_NS = 10_000_000_000
TIMEOUT_BUCKETS = 3   # 超過 3 個 bucket 就刪

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

AF_INET = 2
AF_INET6 = 10

# ========= 主程式 =========


def main():
    stats_fd = get_map_fd(STATS_MAP_PATH)

    while True:

        # ========================================
        # 每一秒重新統計
        # ========================================

        total_packets = 0

        # SYN=1 ACK=0 的封包數量
        syn_only_packets = 0

        # SYN=1 ACK=1 的封包數量
        syn_ack_packets = 0

        # 傳送 SYN=1 ACK=0 的不同來源 IP
        syn_source_ips = set()

        # SYN=1 ACK=0 的不同 flow key 數量
        syn_flows = set()

        # 完成 TCP handshake 的連線數
        established_connections = 0


        # ========================================
        # 取得目前所有 flow
        # ========================================

        keys = iterate_keys(stats_fd)


        for key in keys:

            # ------------------------------------
            # 取得 PERCPU value
            # ------------------------------------

            values = lookup_percpu(stats_fd, key)

            result = aggregate(values)


            # ====================================
            # 1. TCP 封包數量
            # ====================================

            total_packets += result.packets


            # ====================================
            # 2. SYN=1 ACK=0 封包數量
            #
            # syn = SYN + SYN/ACK
            # ack = SYN/ACK
            #
            # 所以：
            #
            # SYN only = syn - ack
            # ====================================

            syn_only = result.syn - result.ack

            syn_only_packets += syn_only


            # ====================================
            # 3. SYN=1 ACK=1 封包數量
            # ====================================

            syn_ack_packets += result.ack


            # ====================================
            # 4. 傳送 SYN=1 ACK=0 的不同來源 IP
            # ====================================

            if syn_only > 0:

                src_ip = key.src_ip

                syn_source_ips.add(src_ip)


                # =================================
                # 5. SYN=1 ACK=0 不同 key 數量
                # =================================

                syn_flows.add(bytes(key))


            # ====================================
            # 6. 完成 TCP handshake 的連線數
            # ====================================

            if result.connection_state == TCP_STATE_ESTABLISHED:
                established_connections += 1


        # ========================================
        # 輸出
        # ========================================

        print("----------------------------------------")
        print(f"TCP 封包數量                    : {total_packets}")
        print(f"SYN=1 ACK=0 封包數量            : {syn_only_packets}")
        print(f"SYN=1 ACK=1 封包數量            : {syn_ack_packets}")
        print(f"SYN來源 IP 數量                  : {len(syn_source_ips)}")
        print(f"SYN 不同 Flow 數量               : {len(syn_flows)}")
        print(f"完成 TCP handshake 連線數        : {established_connections}")


        # ========================================
        # 每秒更新一次
        # ========================================

        time.sleep(1)


    



if __name__ == "__main__":
    main()