#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TC_PROG="$SCRIPT_DIR/tc_tcpip_stats.c"
CONTAINER_NAME="ebpf-test-container"
DOCKER_CONTEXT="default"
SHOW_TRACE=0

PIN_ROOT="/sys/fs/bpf"
PYTHON_PIN_DIR="$PIN_ROOT/ip/globals"
MAP_NAMES=(
    tcp_flow_map
    tcp_bucket_maps
    tcp_current_bucket
    target_ip_map
)

HOST_INTERFACE=""
ATTACHED=0

show_help() {
    cat <<EOF
使用方式：
  ./init.sh [選項]

選項：
  -t, --tc-prog FILE.c       eBPF 原始碼（預設：tc_tcpip_stats.c）
  -c, --container NAME       要監測的 Docker 容器（預設：ebpf-test-container）
      --docker-context NAME  Docker context（預設：default）
      --trace                顯示 bpf_printk 訊息；會明顯增加輸出量
  -h, --help                 顯示說明

範例：
  ./init.sh
  ./init.sh --container ebpf-web-test
  ./init.sh --container ebpf-web-test --trace
EOF
}

require_value() {
    if [[ $# -lt 2 || -z "${2:-}" ]]; then
        echo "錯誤：$1 後面需要一個值。" >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--tc-prog)
            require_value "$@"
            TC_PROG="$2"
            shift 2
            ;;
        -c|--container)
            require_value "$@"
            CONTAINER_NAME="$2"
            shift 2
            ;;
        --docker-context)
            require_value "$@"
            DOCKER_CONTEXT="$2"
            shift 2
            ;;
        --trace)
            SHOW_TRACE=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "錯誤：未知參數 $1" >&2
            show_help >&2
            exit 2
            ;;
    esac
done

if [[ "$TC_PROG" != /* ]]; then
    TC_PROG="$SCRIPT_DIR/$TC_PROG"
fi

if [[ ! -f "$TC_PROG" ]]; then
    echo "錯誤：找不到 eBPF 原始碼：$TC_PROG" >&2
    exit 1
fi

OBJ_FILE="${TC_PROG%.c}.o"

for command_name in clang docker ip tc bpftool mountpoint mount python3 awk; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "錯誤：找不到必要指令 '$command_name'。" >&2
        exit 1
    fi
done

echo "[1/7] 編譯 eBPF 程式..."
CLANG_FLAGS=(-g -O2 -target bpf -I"$SCRIPT_DIR")
if [[ $SHOW_TRACE -eq 1 ]]; then
    CLANG_FLAGS+=(-DENABLE_TRACE=1)
fi
clang "${CLANG_FLAGS[@]}" -c "$TC_PROG" -o "$OBJ_FILE"

if [[ $EUID -eq 0 ]]; then
    PRIVILEGED=()
else
    if ! command -v sudo >/dev/null 2>&1; then
        echo "錯誤：掛載 eBPF 需要 root 權限，但系統沒有 sudo。" >&2
        exit 1
    fi
    echo "接下來需要 sudo 權限來操作 Docker、TC 與 BPF map。"
    sudo -v
    PRIVILEGED=(sudo)
fi

remove_map_pins() {
    local map_name

    for map_name in "${MAP_NAMES[@]}"; do
        "${PRIVILEGED[@]}" rm -f -- \
            "$PIN_ROOT/$map_name" \
            "$PIN_ROOT/tc/globals/$map_name" \
            "$PYTHON_PIN_DIR/$map_name" 2>/dev/null || true
    done
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM HUP

    if [[ $ATTACHED -eq 1 && -n "$HOST_INTERFACE" ]]; then
        echo
        echo "正在卸載 $HOST_INTERFACE 上的 TC/eBPF 程式..."
        "${PRIVILEGED[@]}" tc qdisc del dev "$HOST_INTERFACE" clsact 2>/dev/null || true
        remove_map_pins
    fi

    exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP

echo "[2/7] 檢查 bpffs..."
if ! mountpoint -q "$PIN_ROOT"; then
    "${PRIVILEGED[@]}" mount -t bpf bpf "$PIN_ROOT"
fi

echo "[3/7] 檢查 Docker 與目標容器..."
if ! "${PRIVILEGED[@]}" docker --context "$DOCKER_CONTEXT" info >/dev/null 2>&1; then
    echo "錯誤：無法連線到 Docker context '$DOCKER_CONTEXT'。" >&2
    echo "若使用原生 Docker，可先執行：sudo systemctl start docker" >&2
    exit 1
fi

if [[ "$("${PRIVILEGED[@]}" docker --context "$DOCKER_CONTEXT" inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || true)" != "true" ]]; then
    echo "錯誤：容器 '$CONTAINER_NAME' 不存在或尚未執行。" >&2
    echo "可使用以下指令查看：sudo docker --context $DOCKER_CONTEXT ps -a" >&2
    exit 1
fi

echo "[4/7] 尋找 Container 對應的主機 veth..."
IFINDEX="$("${PRIVILEGED[@]}" docker --context "$DOCKER_CONTEXT" exec "$CONTAINER_NAME" cat /sys/class/net/eth0/iflink | tr -d '\r\n')"
HOST_INTERFACE="$(ip -o link show | awk -F': ' -v if_idx="$IFINDEX" '$1 == if_idx {split($2, names, "@"); print names[1]; exit}')"

if [[ -z "$HOST_INTERFACE" ]]; then
    echo "錯誤：找不到 ifindex=$IFINDEX 對應的主機 veth。" >&2
    exit 1
fi

CONTAINER_IP="$(
    "${PRIVILEGED[@]}" docker --context "$DOCKER_CONTEXT" inspect \
        -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
        "$CONTAINER_NAME" | awk '{print $1}'
)"

if [[ -z "$CONTAINER_IP" ]]; then
    echo "錯誤：無法取得容器 '$CONTAINER_NAME' 的 IPv4 位址。" >&2
    exit 1
fi

echo "容器：$CONTAINER_NAME ($CONTAINER_IP)"
echo "主機 veth：$HOST_INTERFACE"

echo "[5/7] 清除本程式先前留下的掛載與 map..."
# 此腳本假設目標 veth 是專題測試 Container 專用；重建 clsact 可避免 filter 重複累積。
"${PRIVILEGED[@]}" tc qdisc del dev "$HOST_INTERFACE" clsact 2>/dev/null || true
remove_map_pins
"${PRIVILEGED[@]}" tc qdisc add dev "$HOST_INTERFACE" clsact
ATTACHED=1

echo "[6/7] 掛載 ingress 與 egress TC filter..."
"${PRIVILEGED[@]}" tc filter add dev "$HOST_INTERFACE" ingress \
    pref 10 handle 1 bpf da obj "$OBJ_FILE" sec tc
"${PRIVILEGED[@]}" tc filter add dev "$HOST_INTERFACE" egress \
    pref 10 handle 1 bpf da obj "$OBJ_FILE" sec tc

# Python 程式仍使用 /sys/fs/bpf/ip/globals/*。如果 libbpf 將 map pin 在
# /sys/fs/bpf/* 或 /sys/fs/bpf/tc/globals/*，就在舊路徑增加另一個 pin。
echo "[7/7] 準備 Python 程式使用的 pinned map 路徑..."
"${PRIVILEGED[@]}" mkdir -p -- "$PYTHON_PIN_DIR"

for map_name in "${MAP_NAMES[@]}"; do
    expected_path="$PYTHON_PIN_DIR/$map_name"

    if "${PRIVILEGED[@]}" test -e "$expected_path"; then
        continue
    fi

    source_path=""
    for candidate in "$PIN_ROOT/$map_name" "$PIN_ROOT/tc/globals/$map_name"; do
        if "${PRIVILEGED[@]}" test -e "$candidate"; then
            source_path="$candidate"
            break
        fi
    done

    if [[ -z "$source_path" ]]; then
        echo "錯誤：eBPF 已掛載，但找不到 map '$map_name' 的 pinned path。" >&2
        exit 1
    fi

    "${PRIVILEGED[@]}" bpftool map pin pinned "$source_path" "$expected_path"
done

# 先由 init.sh 寫入目標 IPv4，避免等待清理程式啟動期間把 Container
# 發出的封包也混進「收到的封包」統計。tcpip_pakage_expire.py 之後會再寫一次相同值。
IFS=. read -r ip_octet_1 ip_octet_2 ip_octet_3 ip_octet_4 <<< "$CONTAINER_IP"
"${PRIVILEGED[@]}" bpftool map update pinned "$PYTHON_PIN_DIR/target_ip_map" \
    key hex 00 00 00 00 \
    value hex \
    "$(printf '%02x' "$ip_octet_1")" \
    "$(printf '%02x' "$ip_octet_2")" \
    "$(printf '%02x' "$ip_octet_3")" \
    "$(printf '%02x' "$ip_octet_4")"

echo
echo "eBPF 已掛載完成。請保留這個終端執行。"
echo "在第二個終端啟動 bucket／過期清理："
echo "  cd \"$SCRIPT_DIR\""
echo "  sudo python3 tcpip_pakage_expire.py \"$CONTAINER_IP\""
echo
echo "在第三個終端輸出統計與 CSV："
echo "  cd \"$SCRIPT_DIR\""
echo "  sudo python3 tcpip_stats.py"
echo "  # 模型結果會同時寫入 syn_flood_predictions.csv"
echo
echo "按 Ctrl+C 會卸載本腳本掛上的 TC filter 與 map。"

if [[ $SHOW_TRACE -eq 1 ]]; then
    TRACE_PIPE=""
    for candidate in /sys/kernel/tracing/trace_pipe /sys/kernel/debug/tracing/trace_pipe; do
        if "${PRIVILEGED[@]}" test -e "$candidate"; then
            TRACE_PIPE="$candidate"
            break
        fi
    done

    if [[ -z "$TRACE_PIPE" ]]; then
        echo "錯誤：找不到 trace_pipe；改為安靜等待。" >&2
    else
        "${PRIVILEGED[@]}" cat "$TRACE_PIPE"
        exit 0
    fi
fi

while true; do
    sleep 3600 &
    wait $!
done
