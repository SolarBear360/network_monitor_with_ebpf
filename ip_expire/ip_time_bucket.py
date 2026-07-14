import ctypes
import os
import socket
import struct
import time
from collections import defaultdict

# ========= 基本設定 =========
STATS_MAP_PATH = "/sys/fs/bpf/ip/globals/ip_stats_map"
TIME_MAP_PATH = "/sys/fs/bpf/ip/globals/ip_time_map"
SYS_BPF = 321  # x86_64

BPF_OBJ_GET = 7
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_GET_NEXT_KEY = 4
BPF_MAP_DELETE_ELEM = 3

BUCKET_NS = 10_000_000_000
TIMEOUT_BUCKETS = 3   # 超過 3 個 bucket 就刪

BPF_ATTR_SIZE = 120

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# ========= struct 定義（要和 eBPF 完全一致） =========

class IPKey(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_uint32),
        ("ip", ctypes.c_uint32 * 4),  # 統一用 4 個 u32（IPv4 只用第 0 個）
    ]

class Stats(ctypes.Structure):
    _fields_ = [
        ("packets", ctypes.c_uint64),
        ("bytes", ctypes.c_uint64),
    ]

# PERCPU array
NCPU = os.cpu_count()
StatsArray = Stats * NCPU

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

class BPFAttrDelete(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
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

# ========= 刪除 key =========

def delete_elem(fd, key):
    attr = BPFAttrDelete()
    attr.map_fd = fd
    attr.key = ctypes.addressof(key)

    bpf_syscall(BPF_MAP_DELETE_ELEM, attr)

def lookup_percpu(fd, key):
    values = StatsArray()

    attr = BPFAttrLookup()
    attr.map_fd = fd
    attr.key = ctypes.addressof(key)
    attr.value = ctypes.addressof(values)

    bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)
    return values

def lookup_time(fd, key):
    value = ctypes.c_uint64()

    attr = BPFAttrLookup()
    attr.map_fd = fd
    attr.key = ctypes.addressof(key)
    attr.value = ctypes.addressof(value)

    ret = bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)
    if ret is None:
        return None

    return value.value

def aggregate(values):
    total_packets = 0
    total_bytes = 0

    for v in values:
        total_packets += v.packets
        total_bytes += v.bytes

    return total_packets, total_bytes

def iterate_keys(fd):

    keys = []

    current_key = None

    while True:

        next_key = IPKey()

        attr = BPFAttrGetNextKey()
        attr.map_fd = fd

        if current_key is None:
            attr.key = 0
        else:
            attr.key = ctypes.addressof(current_key)

        attr.next_key = ctypes.addressof(next_key)

        ret = bpf_syscall(
            BPF_MAP_GET_NEXT_KEY,
            attr
        )

        if ret is None:
            break


        keys.append(next_key)

        current_key = next_key


    return keys

def current_bucket():
    return time.monotonic_ns() // BUCKET_NS

# ========= IP 轉字串 =========

AF_INET = 2
AF_INET6 = 10

def ip_to_str(key: IPKey):
    if key.family == AF_INET:
        return socket.inet_ntoa(struct.pack("!I", key.ip[0]))
    elif key.family == AF_INET6:
        raw = struct.pack("!IIII", *key.ip)
        return socket.inet_ntop(socket.AF_INET6, raw)
    else:
        return "UNKNOWN"

# ========= 主程式 =========

def main():
    stats_fd = get_map_fd(STATS_MAP_PATH)
    time_fd = get_map_fd(TIME_MAP_PATH)

    while True:
        now_bucket = current_bucket()

        keys = iterate_keys(time_fd)

        for key in keys:
            last_bucket = lookup_time(time_fd, key)

            if last_bucket is None:
                continue

            # 判斷是否過期
            if now_bucket - last_bucket > TIMEOUT_BUCKETS:
                print(f"[DELETE] {ip_to_str(key)}")

                delete_elem(time_fd, key)
                delete_elem(stats_fd, key)

        time.sleep(1)
    



if __name__ == "__main__":
    main()

"""
def main():
    stats_fd = get_map_fd(STATS_MAP_PATH)
    time_fd = get_map_fd(TIME_MAP_PATH)

    bucket_table = defaultdict(set)

    while True:
        now_bucket = current_bucket()

        keys = iterate_keys(time_fd)

        # ========= 建立 bucket grouping =========
        bucket_table.clear()

        for key in keys:
            last_bucket = lookup_time(time_fd, key)

            if last_bucket is None:
                continue

            bucket_table[last_bucket].add(key)

        # ========= 批次刪除過期 bucket =========
        expire_before = now_bucket - TIMEOUT_BUCKETS

        for bucket in list(bucket_table.keys()):
            if bucket <= expire_before:

                for key in bucket_table[bucket]:
                    print(f"[DELETE] {ip_to_str(key)} (bucket={bucket})")

                    delete_elem(time_fd, key)
                    delete_elem(stats_fd, key)

                # 刪掉整個 bucket
                del bucket_table[bucket]

        time.sleep(1)
"""