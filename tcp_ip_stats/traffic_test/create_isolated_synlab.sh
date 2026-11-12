#!/usr/bin/env bash

# Create a disposable web target whose only network is a Docker --internal
# bridge. No host port is published, so spoofed SYN-ACK replies cannot leave
# the dedicated lab network.

set -Eeuo pipefail

NETWORK_NAME="synlab-internal"
SUBNET="172.30.0.0/24"
TARGET_CONTAINER="ebpf-final-target"
TARGET_IMAGE="nginx:alpine"
DOCKER=()

show_help() {
    cat <<'EOF'
使用方式：
  ./traffic_test/create_isolated_synlab.sh [選項]

選項：
  --network NAME       內部 Docker 網路名稱（預設 synlab-internal）
  --subnet CIDR        私有子網（預設 172.30.0.0/24）
  --container NAME     受測 Container（預設 ebpf-final-target）
  --image IMAGE        受測 image（預設 nginx:alpine）
  -h, --help           顯示說明

腳本不會刪除或取代現有 Container，也不會發布 Host port。
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
        --network) require_value "$@"; NETWORK_NAME="$2"; shift 2 ;;
        --subnet) require_value "$@"; SUBNET="$2"; shift 2 ;;
        --container) require_value "$@"; TARGET_CONTAINER="$2"; shift 2 ;;
        --image) require_value "$@"; TARGET_IMAGE="$2"; shift 2 ;;
        -h|--help) show_help; exit 0 ;;
        *) echo "錯誤：未知參數 $1" >&2; show_help >&2; exit 2 ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "錯誤：找不到 Docker。" >&2
    exit 1
fi

if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
else
    if ! command -v sudo >/dev/null 2>&1; then
        echo "錯誤：無法連線 Docker，也沒有 sudo。" >&2
        exit 1
    fi
    sudo -v
    DOCKER=(sudo docker)
fi

if "${DOCKER[@]}" inspect "$TARGET_CONTAINER" >/dev/null 2>&1; then
    echo "錯誤：Container '$TARGET_CONTAINER' 已經存在，腳本不會自動刪除它。" >&2
    echo "請改用 --container 另一個名稱，或確認舊 Container 不再需要後自行移除。" >&2
    exit 1
fi

# Pull before starting the isolated target. The target itself will never have
# access to an external Docker network.
if ! "${DOCKER[@]}" image inspect "$TARGET_IMAGE" >/dev/null 2>&1; then
    echo "本機還沒有 $TARGET_IMAGE，先下載 image..."
    "${DOCKER[@]}" pull "$TARGET_IMAGE"
fi

if "${DOCKER[@]}" network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    network_internal="$("${DOCKER[@]}" network inspect -f '{{.Internal}}' "$NETWORK_NAME")"
    if [[ "$network_internal" != "true" ]]; then
        echo "錯誤：同名網路 '$NETWORK_NAME' 已存在，但不是 --internal 網路。" >&2
        echo "請使用 --network 指定新名稱。" >&2
        exit 1
    fi
else
    echo "建立隔離網路 $NETWORK_NAME ($SUBNET)..."
    "${DOCKER[@]}" network create --driver bridge --internal \
        --subnet "$SUBNET" "$NETWORK_NAME" >/dev/null
fi

echo "建立受測 Container $TARGET_CONTAINER..."
"${DOCKER[@]}" run -d --name "$TARGET_CONTAINER" \
    --network "$NETWORK_NAME" "$TARGET_IMAGE" >/dev/null

TARGET_IP="$("${DOCKER[@]}" inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK_NAME\").IPAddress}}" "$TARGET_CONTAINER")"
PORT_BINDINGS="$("${DOCKER[@]}" inspect -f '{{json .HostConfig.PortBindings}}' "$TARGET_CONTAINER")"

if [[ -z "$TARGET_IP" || ( "$PORT_BINDINGS" != "null" && "$PORT_BINDINGS" != "{}" ) ]]; then
    echo "錯誤：建立後的隔離狀態不如預期，請先停止實驗並檢查。" >&2
    exit 1
fi

cat <<EOF

隔離的受測 Container 已建立。
  Container : $TARGET_CONTAINER
  內部網路  : $NETWORK_NAME
  Container IP: $TARGET_IP
  Host port : 無

下一步：
  1. ./init.sh --container $TARGET_CONTAINER
  2. sudo python3 tcpip_pakage_expire.py $TARGET_IP
  3. sudo python3 tcpip_stats.py
  4. ./traffic_test/run_final_holdout_experiment.sh --target-container $TARGET_CONTAINER
EOF
