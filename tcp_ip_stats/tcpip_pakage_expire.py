import ctypes
import os
import socket
import struct
import time
import sys
import ipaddress
from collections import defaultdict
import json
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler


# ========= BPF Map error logger =========

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "bpf_errors.jsonl")
os.makedirs(LOG_DIR, exist_ok=True)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "timestamp": datetime.now().astimezone().isoformat(
                timespec="microseconds"
            ),
            "level": record.levelname,
            "map_name": getattr(record, "map_name", None),
            "operation": getattr(record, "operation", None),
            "map_fd": getattr(record, "map_fd", None),
            "errno": getattr(record, "errno", None),
            "error": getattr(record, "error", None),
            "key": getattr(record, "key", None),
            "message": record.getMessage(),
        }

        if record.exc_info:
            data["exception"] = self.formatException(record.exc_info)

        return json.dumps(data, ensure_ascii=False)


logger = logging.getLogger("bpf_map")
logger.setLevel(logging.ERROR)
logger.propagate = False

if not logger.handlers:
    handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)


def log_map_error(map_name, operation, error, map_fd=None, key=None):
    logger.error(
        "BPF Map operation failed",
        extra={
            "map_name": map_name,
            "operation": operation,
            "map_fd": map_fd,
            "errno": getattr(error, "errno", None),
            "error": str(error),
            "key": key,
        },
        exc_info=(type(error), error, error.__traceback__)
    )

# ========= 基本設定 =========
STATS_MAP_PATH = "/sys/fs/bpf/ip/globals/tcp_flow_map"
BUCKET_MAP_PATH = "/sys/fs/bpf/ip/globals/tcp_bucket_maps"
CURRENT_BUCKET_PATH = "/sys/fs/bpf/ip/globals/tcp_current_bucket"
TARGET_IP_MAP_PATH = "/sys/fs/bpf/ip/globals/target_ip_map"

SYS_BPF = 321  # x86_64

BPF_OBJ_GET = 7
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_GET_NEXT_KEY = 4
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_CREATE = 0
BPF_ANY = 0

BPF_MAP_GET_FD_BY_ID = 14

BPF_MAP_TYPE_HASH = 1


NUM_BUCKETS = 64

#---------------------------------------------------
BUCKET_NS = 10_000_000_00 # 1秒
TIMEOUT_BUCKETS = 30   # 超過 30 個 bucket 就刪

TIMEOUT_SECONDS = 30
TIMEOUT_NS = TIMEOUT_SECONDS * 1_000_000_000
#---------------------------------------------------

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

def bpf_syscall(cmd, attr, enoent_is_none=False):
    attr_size = ctypes.sizeof(attr)

    ret = libc.syscall(
        SYS_BPF,
        cmd,
        ctypes.byref(attr),
        attr_size
    )

    if ret < 0:
        err = ctypes.get_errno()

        if err == 2 and enoent_is_none:
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

def flow_key_to_str(key):
    src_ip = ipaddress.IPv4Address(
        key.src_ip.to_bytes(4, byteorder="little")
    )
    dst_ip = ipaddress.IPv4Address(
        key.dst_ip.to_bytes(4, byteorder="little")
    )

    return (
        f"{src_ip}:{key.src_port} -> "
        f"{dst_ip}:{key.dst_port}, protocol={key.protocol}"
    )


def delete_elem(
    fd,
    key,
    map_name="unknown",
    key_description=None,
    ignore_missing=True
):
    attr = BPFAttrDelete()
    attr.map_fd = fd
    attr.key = ctypes.addressof(key)

    try:
        ret = bpf_syscall(
            BPF_MAP_DELETE_ELEM,
            attr,
            enoent_is_none=ignore_missing
        )

        if ret is None:
            return False

        return True

    except OSError as error:
        log_map_error(
            map_name=map_name,
            operation="DELETE",
            error=error,
            map_fd=fd,
            key=key_description
        )
        raise


def update_elem(
    map_fd,
    key_ptr,
    value_ptr,
    flags=0,
    map_name="unknown",
    key_description=None
):
    attr = BPFAttrUpdate()

    attr.map_fd = map_fd
    attr.key = ctypes.addressof(key_ptr.contents)
    attr.value = ctypes.addressof(value_ptr.contents)
    attr.flags = flags

    try:
        return bpf_syscall(BPF_MAP_UPDATE_ELEM, attr)

    except OSError as error:
        log_map_error(
            map_name=map_name,
            operation="UPDATE",
            error=error,
            map_fd=map_fd,
            key=key_description
        )
        raise


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

    bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr, enoent_is_none=True)
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

    ret = bpf_syscall(
        BPF_MAP_LOOKUP_ELEM, attr, enoent_is_none=True
    )

    if ret is None:
        return None

    inner_map_id = value.value

    # print(
    #     f"[DEBUG] bucket={index}, "
    #     f"inner_map_id={inner_map_id}"
    # )

    inner_fd = get_map_fd_by_id(inner_map_id)

    # print(
    #     f"[DEBUG] inner_map_id={inner_map_id} "
    #     f"-> inner_fd={inner_fd}"
    # )

    return inner_fd

def iterate_keys(fd):
    keys = []

    next_key = FlowKey()
    key_ptr = 0  # 第一次傳 NULL

    while True:
        attr = BPFAttrGetNextKey()
        attr.map_fd = fd
        attr.key = key_ptr
        attr.next_key = ctypes.addressof(next_key)

        ret = bpf_syscall(
            BPF_MAP_GET_NEXT_KEY, attr, enoent_is_none=True
        )
        if ret is None:
            break

        # copy key（避免被覆蓋）
        k = FlowKey()
        ctypes.memmove(ctypes.byref(k), ctypes.byref(next_key), ctypes.sizeof(FlowKey))
        keys.append(k)

        key_ptr = ctypes.addressof(next_key)

    return keys
#============== bucket 相關動作 function ===================
def current_bucket():
    return time.monotonic_ns() // BUCKET_NS

def clear_bucket(stats_fd, bucket_fd, expired_idx, inner_fd):
    now_ns = time.monotonic_ns()

    keys = iterate_keys(inner_fd)

    print(f"{len(keys)} keys in current bucket \n")

    for key in keys:
        stats_values = lookup_percpu(stats_fd, key)

        # 找出各 CPU 中最新的 last_seen
        last_seen_ns = max(
            (value.last_seen for value in stats_values),
            default=0
        )

        # 判斷是否逾期超過 30 秒
        expired = (
            last_seen_ns == 0 or
            now_ns - last_seen_ns > TIMEOUT_NS
        )

        key_info = flow_key_to_str(key)

        if expired:
            print(
                f"[EXPIRE] remove FlowKey from stats: "
                f"{key_info}, "
                f"last_seen={last_seen_ns}, "
                f"idle={(now_ns - last_seen_ns) / 1e9:.2f}s"
            )

            # 從 stats_map 刪除統計紀錄
            delete_elem(
                stats_fd,
                key,
                map_name="tcp_flow_map",
                key_description=key_info
            )

            # 無論是否逾期，都刪除目前 bucket 的 key
            delete_elem(
                inner_fd,
                key,
                map_name=f"tcp_bucket_inner_{expired_idx}",
                key_description=key_info
            )

        else:
            print(
                f"[KEEP] FlowKey still active: "
                f"{key_info}, "
                f"idle={(now_ns - last_seen_ns) / 1e9:.2f}s"
            )


def cleanup_buckets(stats_fd, bucket_fd, inner_fd_list):
    now_bucket = current_bucket()

    expired_bucket = now_bucket - TIMEOUT_BUCKETS

    expired_bucket = expired_bucket if expired_bucket >= 0 else expired_bucket + 64

    idx = expired_bucket % NUM_BUCKETS

    #inner_fd = lookup_inner_map_fd(bucket_fd, idx)
    inner_fd = inner_fd_list[idx]

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
        #os.close(inner_fd)
        pass


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

    try:
        return bpf_syscall(BPF_MAP_UPDATE_ELEM, attr)

    except OSError as error:
        log_map_error(
            map_name="tcp_bucket_maps",
            operation="UPDATE",
            error=error,
            map_fd=outer_fd,
            key=f"bucket_index={index}, inner_fd={inner_fd}"
        )
        raise


def init_buckets(bucket_fd):
    inner_map_fd_list = []

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

        try:
            update_outer(bucket_fd, i, inner_fd)
        except Exception:
            os.close(inner_fd)
            raise

        inner_map_fd_list.append(inner_fd)

    return inner_map_fd_list

def struct_ip_to_u32(ip):
    packed = socket.inet_aton(ip)
    return int.from_bytes(packed, byteorder="little")

def set_target_ip(map_fd, ip):
    # key = 0，因為 ARRAY map 只有一個 entry
    key = ctypes.c_uint32(0)

    # 將 IPv4 字串轉成 network byte order
    ip_value = struct_ip_to_u32(ip)

    value = ctypes.c_uint32(ip_value)

    attr = BPFAttrUpdate()
    attr.map_fd = map_fd
    attr.key = ctypes.addressof(key)
    attr.value = ctypes.addressof(value)
    attr.flags = BPF_ANY

    try:
        return bpf_syscall(BPF_MAP_UPDATE_ELEM, attr)

    except OSError as error:
        log_map_error(
            map_name="target_ip_map",
            operation="UPDATE",
            error=error,
            map_fd=map_fd,
            key=f"target_ip={ip}"
        )
        raise



# ========= 主程式 =========

def main():
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <IP>")
        print(f"Example: sudo python3 {sys.argv[0]} 8.8.8.8")
        sys.exit(1)

    ip = sys.argv[1]

    # 確認是不是合法 IPv4
    try:
        socket.inet_aton(ip)
    except OSError:
        print(f"Invalid IPv4 address: {ip}")
        sys.exit(1)

    map_fd = get_map_fd(TARGET_IP_MAP_PATH)

    set_target_ip(map_fd, ip)
    
    stats_fd = get_map_fd(STATS_MAP_PATH)
    bucket_fd = get_map_fd(BUCKET_MAP_PATH)
    current_bucket_fd = get_map_fd(CURRENT_BUCKET_PATH)

    inner_fd_list = init_buckets(bucket_fd)

    print("Start cleanup loop...")

    while True:
        try:
            cleanup_buckets(
                stats_fd,
                bucket_fd,
                inner_fd_list
            )

            time.sleep(1)

        except KeyboardInterrupt:
            for inner_map_file_directory in inner_fd_list:
                os.close(inner_map_file_directory)
            break



if __name__ == "__main__":
    main()
