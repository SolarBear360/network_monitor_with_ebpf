import ctypes
import os
import socket
import struct
import time
from collections import defaultdict

# ========= 基本設定 =========
STATS_MAP_PATH = "/sys/fs/bpf/ip/globals/tcp_flow_map"
BUCKET_MAP_PATH = "/sys/fs/bpf/ip/globals/tcp_bucket_maps"
CURRENT_BUCKET_PATH = "/sys/fs/bpf/ip/globals/tcp_current_bucket"

SYS_BPF = 321  # x86_64

BPF_OBJ_GET = 7
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_GET_NEXT_KEY = 4
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_CREATE = 0

BPF_MAP_GET_FD_BY_ID = 14

BPF_MAP_TYPE_HASH = 1


NUM_BUCKETS = 64

BUCKET_NS = 10_000_000_00 # 1秒
TIMEOUT_BUCKETS = 3   # 超過 3 個 bucket 就刪


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

class BPFAttrDelete(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
    ]

class BPFAttrUpdate(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]

class BPFAttrCreate(ctypes.Structure):
    _fields_ = [
        ("map_type", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
        ("inner_map_fd", ctypes.c_uint32),
        ("numa_node", ctypes.c_uint32),
        ("map_name", ctypes.c_char * 16),
        ("map_ifindex", ctypes.c_uint32),
        ("btf_fd", ctypes.c_uint32),
        ("btf_key_type_id", ctypes.c_uint32),
        ("btf_value_type_id", ctypes.c_uint32),
        ("btf_vmlinux_value_type_id", ctypes.c_uint32),
    ]

class BPFAttrGetFDByID(ctypes.Structure):
    _fields_ = [
        ("map_id", ctypes.c_uint32),
    ]
# ========= syscall wrapper =========

def bpf_syscall(cmd, attr):
    attr_size = ctypes.sizeof(attr)

    ret = libc.syscall(
        SYS_BPF,
        cmd,
        ctypes.byref(attr),
        attr_size
    )

    if ret < 0:
        err = ctypes.get_errno()

        if err == 2:
            return None

        try:
            err_name = os.strerror(err)
        except Exception:
            err_name = "Unknown error"

        print("\n========== BPF SYSCALL ERROR ==========")
        print(f"command      : {cmd}")
        print(f"attr type    : {type(attr).__name__}")
        print(f"attr size    : {attr_size}")
        print(f"errno        : {err}")
        print(f"error        : {err_name}")

        if hasattr(attr, "map_fd"):
            print(f"map_fd       : {attr.map_fd}")

        if hasattr(attr, "key"):
            print(f"key pointer  : {hex(attr.key)}")

        if hasattr(attr, "value"):
            print(f"value pointer: {hex(attr.value)}")

        if hasattr(attr, "next_key"):
            print(f"next_key ptr : {hex(attr.next_key)}")

        print("========================================\n")

        raise OSError(
            err,
            f"BPF syscall failed: {err_name} "
            f"(errno={err}, cmd={cmd})"
        )

    return ret

def get_map_fd_by_id(map_id):
    attr = BPFAttrGetFDByID()
    attr.map_id = map_id

    return bpf_syscall(BPF_MAP_GET_FD_BY_ID, attr)

def get_map_fd(path):
    path_buf = ctypes.create_string_buffer(path.encode())

    attr = BPFAttrObjGet()
    attr.pathname = ctypes.addressof(path_buf)

    return bpf_syscall(BPF_OBJ_GET, attr)

def delete_elem(fd, key):
    attr = BPFAttrDelete()
    attr.map_fd = fd
    attr.key = ctypes.addressof(key)

    bpf_syscall(BPF_MAP_DELETE_ELEM, attr)

def update_elem(map_fd, key_ptr, value_ptr, flags=0):
    attr = BPFAttrUpdate()

    attr.map_fd = map_fd
    attr.key = ctypes.addressof(key_ptr.contents)
    attr.value = ctypes.addressof(value_ptr.contents)
    attr.flags = flags

    ret = libc.syscall(SYS_BPF,
                       BPF_MAP_UPDATE_ELEM,
                       ctypes.byref(attr),
                       ctypes.sizeof(attr))

    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"bpf_map_update_elem failed: {os.strerror(err)}")

    return 0

# ============= utility ==================
def ip_to_str(key: FlowKey):
    print(key.src_ip, " -> ", key.dst_ip)

# ============= map 查詢動作 ==================

def lookup_percpu(fd, key):
    values = StatsArray()

    attr = BPFAttrLookup()
    attr.map_fd = fd
    attr.key = ctypes.addressof(key)
    attr.value = ctypes.addressof(values)

    bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)
    return values

# lookup_time本來是要用做讀取ebpf的 tcp_current_bucket 這個map
# 但因為也可以直接由python讀取系統時間，所以沒有使用到這函式
# ebpf中的 tcp_current_bucket map沒有拿掉

# def lookup_time(fd, key):
#     value = ctypes.c_uint64()

#     attr = BPFAttrLookup()
#     attr.map_fd = fd
#     attr.key = ctypes.addressof(key)
#     attr.value = ctypes.addressof(value)

#     ret = bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)
#     if ret is None:
#         return None

#     return value.value

def lookup_inner_map_fd(outer_fd, index):
    value = ctypes.c_uint32()
    key = ctypes.c_uint32(index)

    attr = BPFAttrLookup()
    attr.map_fd = outer_fd
    attr.key = ctypes.addressof(key)
    attr.value = ctypes.addressof(value)

    ret = bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)

    if ret is None:
        return None

    inner_map_id = value.value

    print(
        f"[DEBUG] bucket={index}, "
        f"inner_map_id={inner_map_id}"
    )

    inner_fd = get_map_fd_by_id(inner_map_id)

    print(
        f"[DEBUG] inner_map_id={inner_map_id} "
        f"-> inner_fd={inner_fd}"
    )

    return inner_fd

#============== bucket 相關動作 function ===================
def current_bucket():
    return time.monotonic_ns() // BUCKET_NS

def map_key_exists(fd, key):
    value = ctypes.c_uint8()

    attr = BPFAttrLookup()
    attr.map_fd = fd
    attr.key = ctypes.addressof(key)
    attr.value = ctypes.addressof(value)

    ret = bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)

    return ret is not None

def exists_in_other_buckets(bucket_fd, expired_idx, key):
    for i in range(NUM_BUCKETS):
        if i == expired_idx:
            continue

        inner_fd = lookup_inner_map_fd(bucket_fd, i)

        if inner_fd is None:
            continue

        try:
            if map_key_exists(inner_fd, key):
                return True
        finally:
            os.close(inner_fd)

    return False

def clear_bucket(stats_fd, bucket_fd, expired_idx, inner_fd):
    while True:
        next_key = FlowKey()

        attr = BPFAttrGetNextKey()
        attr.map_fd = inner_fd
        attr.key = 0
        attr.next_key = ctypes.addressof(next_key)

        ret = bpf_syscall(
            BPF_MAP_GET_NEXT_KEY,
            attr
        )

        # ENOENT = 這個 bucket 已經沒有 key
        if ret is None:
            break

        # ------------------------------------------------
        # 先確認這個 IP 是否還存在於其他 bucket
        # ------------------------------------------------
        still_exists = exists_in_other_buckets(
            bucket_fd,
            expired_idx,
            next_key
        )

        if not still_exists:
            print(f"[EXPIRE] remove IP from stats: ")
            print(next_key.src_ip, " -> ", next_key.dst_ip)

            delete_elem(stats_fd, next_key)

        else:
            print(f"[KEEP] IP still exists in another bucket: ")
            print(next_key.src_ip, " -> ", next_key.dst_ip)

        # ------------------------------------------------
        # 最後刪除 expired bucket 裡面的 key
        # ------------------------------------------------
        delete_elem(inner_fd, next_key)
        
def cleanup_buckets(stats_fd, bucket_fd):
    now_bucket = current_bucket()

    expired_bucket = now_bucket - TIMEOUT_BUCKETS

    expired_bucket = expired_bucket if expired_bucket >= 0 else expired_bucket + 64

    idx = expired_bucket % NUM_BUCKETS

    inner_fd = lookup_inner_map_fd(bucket_fd, idx)

    if inner_fd is None:
        print(f"[ERROR] bucket {idx}: inner map not found")
        return

    try:
        print(
            f"[CLEAN] bucket={idx}, "
            f"inner_fd={inner_fd}"
        )

        clear_bucket(
            stats_fd,
            bucket_fd,
            idx,
            inner_fd
        )

    finally:
        os.close(inner_fd)


#=========== init inner maps ============
def create_inner_map():
    attr = BPFAttrCreate()

    attr.map_type = BPF_MAP_TYPE_HASH
    attr.key_size = ctypes.sizeof(FlowKey)
    attr.value_size = ctypes.sizeof(ctypes.c_uint8)
    attr.max_entries = 4096
    attr.map_flags = 0

    return bpf_syscall(BPF_MAP_CREATE, attr)


def update_outer(outer_fd, index, inner_fd):
    key = ctypes.c_uint32(index)
    value = ctypes.c_uint32(inner_fd)

    attr = BPFAttrUpdate()
    attr.map_fd = outer_fd
    attr.key = ctypes.addressof(key)
    attr.value = ctypes.addressof(value)
    attr.flags = 0

    bpf_syscall(BPF_MAP_UPDATE_ELEM, attr)

def init_buckets(bucket_fd):
    for i in range(NUM_BUCKETS):
        inner_fd = create_inner_map()

        if inner_fd < 0:
            raise RuntimeError(
                f"create inner map {i} failed"
            )

        print(
            f"[INIT] bucket={i}, "
            f"inner_fd={inner_fd}"
        )

        update_outer(bucket_fd, i, inner_fd)

        os.close(inner_fd)

# ========= 主程式 =========

def main():
    stats_fd = get_map_fd(STATS_MAP_PATH)
    bucket_fd = get_map_fd(BUCKET_MAP_PATH)
    current_bucket_fd = get_map_fd(CURRENT_BUCKET_PATH)

    init_buckets(bucket_fd)

    print("Start cleanup loop...")

    while True:
        try:
            cleanup_buckets(
                stats_fd,
                bucket_fd
            )

            time.sleep(1)

        except KeyboardInterrupt:
            break



if __name__ == "__main__":
    main()
