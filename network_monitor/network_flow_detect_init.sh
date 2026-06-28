#!/bin/bash

# 預設值（如果使用者沒有指定參數，就會使用這些預設值）
TC_PROG="tc_log.c"
CONTAINER_NAME="ebpf-test-container"

# Help 說明函式
show_help() {
    echo "使用說明:"
    echo "  $0 [選項]"
    echo ""
    echo "選項:"
    echo "  -t, --tc-prog <file.c>       指定要編譯與掛載的 eBPF C 語言原始碼檔案 (預設: tc_log.c)"
    echo "  -c, --container <name>       指定要監測的 Docker 容器名稱或 ID (預設: ebpf-test-container)"
    echo "  -h, --help                   顯示此說明訊息"
    echo ""
    echo "範例:"
    echo "  $0 --tc-prog my_filter.c --container web_server"
    exit 0
}

# 解析參數 (支援 -t/--tc-prog, -c/--container, -h/--help)
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--tc-prog)
            TC_PROG="$2"
            shift 2
            ;;
        -c|--container)
            CONTAINER_NAME="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "錯誤: 未知的參數 $1"
            show_help
            ;;
    esac
done

# 自動將 .c 結尾替換成 .o 作為編譯輸出名稱
OBJ_FILE="${TC_PROG%.c}.o"

echo "=== 開始執行 eBPF/TC 監控腳本 ==="
echo "目標程式: $TC_PROG (編譯輸出: $OBJ_FILE)"
echo "目標容器: $CONTAINER_NAME"
echo "--------------------------------"

# 1. 編譯 eBPF 程式 (加上 -g 以防 BTF 遺失錯誤)
echo "[1/6] 正在編譯 eBPF 程式..."
clang -g -O2 -target bpf -c "$TC_PROG" -o "$OBJ_FILE"
if [ $? -ne 0 ]; then
    echo "錯誤: 編譯失敗，請檢查 $TC_PROG 是否存在或語法正確。"
    exit 1
fi

# 2. 獲取 Docker 在主機端對應的網路介面索引值
echo "[2/6] 正在獲取容器網路介面..."
IFINDEX=$(sudo docker exec "$CONTAINER_NAME" cat /sys/class/net/eth0/iflink 2>/dev/null | tr -d '\r')

if [ -z "$IFINDEX" ]; then
    echo "錯誤: 找不到容器 '$CONTAINER_NAME' 或無法讀取網路介面。請確認容器是否正在執行。"
    exit 1
fi

# 3. 找出主機端對應的 veth 網卡名稱
HOST_INTERFACE=$(ip link | grep "^${IFINDEX}:" | cut -d' ' -f2 | cut -d'@' -f1)
echo "找到主機對應網卡: $HOST_INTERFACE"

# ========================================================
# 修正後的步驟：強力清理所有可能殘留的舊 Map 檔案與目錄
# ========================================================
echo "[3.5] 正在清理舊的 Pinned Map 檔案以利重建..."

# 1. 定義所有可能出現 pkt_stats_map 的路徑
MAP_PATHS=(
    "/sys/fs/bpf/ip/globals/pkt_stats_map"
    "/sys/fs/bpf/tc/globals/pkt_stats_map"
)
echo "DEBUG in networkflow_detect_init.sh ${MAP_PATHS[@]}"
# 2. 循環檢查並強制刪除
for PATH_TO_CHECK in "${MAP_PATHS[@]}"; do
    echo "DEBUG in networkflow_detect_init.sh : PATH_TO_CHECK = ${PATH_TO_CHECK}"
    if [ -f "$PATH_TO_CHECK" ]; then
        echo "偵測到舊的 Map，正在強制移除: $PATH_TO_CHECK"
        sudo rm -f "$PATH_TO_CHECK"
    fi 
done
# ========================================================

# 4. 建立 clsact 佇列與掛載 eBPF 程式
echo "[3/6] 正在建立 clsact qdisc..."
sudo tc qdisc add dev "$HOST_INTERFACE" clsact 2>/dev/null || echo "clsact 已存在，跳過建立。"

echo "[4/6] 正在掛載 Ingress 與 Egress 過濾器..."
#sudo tc filter add dev "$HOST_INTERFACE" ingress bpf da obj "$OBJ_FILE" sec tc
#sudo tc filter add dev "$HOST_INTERFACE" egress bpf da obj "$OBJ_FILE" sec tc
sudo tc filter add dev $HOST_INTERFACE ingress bpf da obj "$OBJ_FILE" sec tc_ingress
sudo tc filter add dev $HOST_INTERFACE egress bpf da obj "$OBJ_FILE" sec tc_egress

# 5. 掛載 BPF 檔案系統 (避免 Map pinning 失敗)
echo "[5/6] 檢查並掛載 BPF 檔案系統..."
if ! mountpoint -q /sys/fs/bpf; then
    sudo mount -t bpf bpf /sys/fs/bpf/
fi

# 6. 開始監聽日誌
echo "[6/6] 開始監聽核心核心日誌 (按下 Ctrl+C 結束監聽並卸載)..."
echo "=========================================================="

# 利用 trap 機制，確保使用者按下 Ctrl+C 結束時，一定會執行清理網卡的動作
trap 'echo ""; echo "正在卸載 eBPF 程式並清理網卡..."; sudo tc qdisc del dev "$HOST_INTERFACE" clsact; exit 0' INT

sudo cat /sys/kernel/debug/tracing/trace_pipe
