#此程式讀取創建好的bpf map，並根據tc_network_flow.c所定義的資料結構來讀取map
#這段程式僅限用於x86_64 linux

import ctypes
import os
import time

#===========================================================================
#===========================================================================
#      以下程式碼片段與讀取map有關，不建議更改(如果你只想修改分析流量的程式部分)
#===========================================================================
#===========================================================================
# === 定義 struct ===
class Stats(ctypes.Structure):
    _fields_ = [
        ("packets", ctypes.c_uint32),
        ("bytes", ctypes.c_uint32),
    ]

# === syscall number（x86_64）===
SYS_BPF = 321

# === bpf command ===
BPF_OBJ_GET = 7
BPF_MAP_LOOKUP_ELEM = 1

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# === bpf_attr structs ===
class BPFAttrObjGet(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]

class BPFAttrMapLookup(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]

def bpf_syscall(cmd, attr):
    ret = libc.syscall(SYS_BPF, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret

# === 打開 pinned map ===
def get_map_fd(path):
    path_bytes = path.encode()
    path_buf = ctypes.create_string_buffer(path_bytes)

    attr = BPFAttrObjGet()
    attr.pathname = ctypes.addressof(path_buf)
    attr.bpf_fd = 0
    attr.file_flags = 0

    return bpf_syscall(BPF_OBJ_GET, attr)

# === lookup ===
def lookup_elem(fd, key):
    key_c = ctypes.c_uint32(key)
    value = Stats()

    attr = BPFAttrMapLookup()
    attr.map_fd = fd
    attr.key = ctypes.addressof(key_c)
    attr.value = ctypes.addressof(value)
    attr.flags = 0

    bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)
    return value
#===========================================================================
#===========================================================================
#                                到這裡結束
#===========================================================================
#===========================================================================

# === main ===
if __name__ == "__main__":
    MAP_PATH = "/sys/fs/bpf/ip/globals/pkt_stats_map"

    fd = get_map_fd(MAP_PATH)

    print("Reading map... Ctrl+C to stop")

    try:
        while True:
#----------------------------------
#----------------------------------
#在這裡讀取map資料並作分析
#因為分成ingress(進入網卡的封包)和egress(離開網卡的封包)，所以分兩個map，i = 0以及i = 1
#讀取的結構在上面定義的Stats
            for i in range(2):
                val = lookup_elem(fd, i)

                direction = "Ingress" if i == 0 else "Egress"
                print(f"{direction}: packets={val.packets}, bytes={val.bytes}")

            print("-" * 30)
            time.sleep(1)
#----------------------------------
#----------------------------------
    except KeyboardInterrupt:
        print("Stopped")
