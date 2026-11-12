#!/usr/bin/env bash

# Controlled training-capture or independent-holdout experiment.  The traffic
# generators are short-lived containers on the protected container's isolated
# Docker network.  One run may be training or holdout, never both.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
HPING_DOCKERFILE="$SCRIPT_DIR/hping3.Dockerfile"
HPING_IMAGE="synlab-hping-final:latest"
NORMAL_CLIENT_DOCKERFILE="$SCRIPT_DIR/normal_client.Dockerfile"
NORMAL_CLIENT_IMAGE="synlab-normal-client:latest"
SOURCE_IP_ALLOCATOR="$SCRIPT_DIR/allocate_normal_source_ips.py"
NORMAL_CONNECTION_SCRIPT="$SCRIPT_DIR/normal_tcp_connections.py"
NORMAL_KEEPALIVE_SCRIPT="$SCRIPT_DIR/normal_http_keepalive.py"
MERGE_SCRIPT="$SCRIPT_DIR/merge_labels.py"
EVALUATOR="$PROJECT_DIR/ml_test/evaluate_final_holdout.py"

TARGET_CONTAINER="ebpf-final-target"
TARGET_PORT=80
PHASE_SECONDS=90
ATTACK_SECONDS=120
SHORT_ATTACK_SECONDS=8
COOLDOWN_SECONDS=20
NORMAL_MULTI_WARMUP_SECONDS=15
BOUNDARY_SECONDS=3
STATS_CSV="$PROJECT_DIR/tcp_stats.csv"
RUNTIME_MODEL="$PROJECT_DIR/model_handoff/syn-window-v1/runtime_model.json"
OUTPUT_DIR=""
DATASET_ROLE="holdout"
DRY_RUN=0
ASSUME_YES=0
KEEP_ATTACKER=0

NORMAL_CONNECTION_SPEC="1,10,30,70"
NORMAL_VUS_SPEC="10,30,70"
NORMAL_MULTI_SOURCE_SPEC="5:30,10:70,20:150"
BENIGN_SYN_SPEC="1,2"
DIAGNOSTIC_SYN_SPEC="5,10,20"
SINGLE_ATTACK_SPEC="30,70,150,250"
RAND_ATTACK_SPEC="30,70,150,250"
MIXED_SINGLE_SPEC="10:30,30:70,70:150"
MIXED_RAND_SPEC="10:30,30:70,70:150"

ACTIVE_PID=""
ATTACKER_CONTAINER=""
ATTACKER_CREATED=0
NORMAL_CLIENT_CONTAINER=""
NORMAL_CLIENT_CREATED=0
NORMAL_SOURCE_IPS=""
MAX_NORMAL_SOURCES=0
SUDO_KEEPALIVE_PID=""
CURRENT_SCENARIO=""
EXCLUDED_PHASES=0
DOCKER=()

show_help() {
    cat <<'EOF'
使用方式（在 Ubuntu 的專題資料夾執行）：
  ./traffic_test/run_final_holdout_experiment.sh [選項]

主要選項：
  --target-container NAME       受測 Container（預設 ebpf-final-target）
  --target-port PORT            Container 內的 HTTP port（預設 80）
  --phase-seconds SEC           正常與診斷情境時間（預設 90）
  --attack-seconds SEC          主要攻擊時間（預設 120）
  --cooldown SEC                每段間的恢復時間（預設 20）
  --normal-multi-warmup-seconds SEC
                                多 IP 正常流量正式量測前的暖機時間（預設 15）
  --normal-multi-source-profiles LIST
                                正常來源數:總連線率，例如 5:30,10:70,20:150
  --dataset-role ROLE           training 或 holdout（預設 holdout）
  --stats-csv FILE              tcpip_stats.py 正在寫入的 CSV
  --output-dir DIR              輸出資料夾
  --dry-run                     只產生測試計畫，不連線 Docker/不發封包
  --keep-attacker               完成後不刪除 hping3 Container
  -y, --yes                     略過確認
  -h, --help                    顯示說明

預設時間約 60–70 分鐘。training 與 holdout 必須使用不同執行輪次；
不可用同一輪資料同時訓練與評估模型。
為了安全使用 hping3 --rand-source，受測 Container 必須：
  1. 只連接一個 Docker --internal 網路。
  2. 沒有對 Host 發布任何 port。
EOF
}

require_value() {
    if [[ $# -lt 2 || -z "${2:-}" ]]; then
        echo "錯誤：$1 後面需要一個值。" >&2
        exit 2
    fi
}

is_uint() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-container) require_value "$@"; TARGET_CONTAINER="$2"; shift 2 ;;
        --target-port) require_value "$@"; TARGET_PORT="$2"; shift 2 ;;
        --phase-seconds) require_value "$@"; PHASE_SECONDS="$2"; shift 2 ;;
        --attack-seconds) require_value "$@"; ATTACK_SECONDS="$2"; shift 2 ;;
        --cooldown) require_value "$@"; COOLDOWN_SECONDS="$2"; shift 2 ;;
        --normal-multi-warmup-seconds)
            require_value "$@"; NORMAL_MULTI_WARMUP_SECONDS="$2"; shift 2 ;;
        --normal-multi-source-profiles)
            require_value "$@"; NORMAL_MULTI_SOURCE_SPEC="$2"; shift 2 ;;
        --dataset-role) require_value "$@"; DATASET_ROLE="$2"; shift 2 ;;
        --stats-csv) require_value "$@"; STATS_CSV="$2"; shift 2 ;;
        --output-dir) require_value "$@"; OUTPUT_DIR="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --keep-attacker) KEEP_ATTACKER=1; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) echo "錯誤：未知參數 $1" >&2; show_help >&2; exit 2 ;;
    esac
done

for value in "$TARGET_PORT" "$PHASE_SECONDS" "$ATTACK_SECONDS" \
    "$SHORT_ATTACK_SECONDS" "$COOLDOWN_SECONDS" \
    "$NORMAL_MULTI_WARMUP_SECONDS" "$BOUNDARY_SECONDS"; do
    if ! is_uint "$value"; then
        echo "錯誤：port 與時間必須是非負整數。" >&2
        exit 2
    fi
done
if ((TARGET_PORT < 1 || TARGET_PORT > 65535)); then
    echo "錯誤：target-port 必須介於 1 與 65535。" >&2; exit 2
fi
if ((PHASE_SECONDS < 30 || PHASE_SECONDS > 300)); then
    echo "錯誤：phase-seconds 必須介於 30 與 300。" >&2; exit 2
fi
if ((ATTACK_SECONDS < 30 || ATTACK_SECONDS > 300)); then
    echo "錯誤：attack-seconds 必須介於 30 與 300。" >&2; exit 2
fi
if ((COOLDOWN_SECONDS < 10 || COOLDOWN_SECONDS > 120)); then
    echo "錯誤：cooldown 必須介於 10 與 120。" >&2; exit 2
fi
if ((NORMAL_MULTI_WARMUP_SECONDS < 5 || NORMAL_MULTI_WARMUP_SECONDS > 60)); then
    echo "錯誤：normal-multi-warmup-seconds 必須介於 5 與 60。" >&2
    exit 2
fi
if [[ "$DATASET_ROLE" != "training" && "$DATASET_ROLE" != "holdout" ]]; then
    echo "錯誤：--dataset-role 只能是 training 或 holdout。" >&2
    exit 2
fi

old_ifs="$IFS"
IFS=',' read -r -a normal_multi_profiles <<< "$NORMAL_MULTI_SOURCE_SPEC"
IFS="$old_ifs"
if [[ ${#normal_multi_profiles[@]} -eq 0 ]]; then
    echo "錯誤：normal multi-source profiles 不可為空。" >&2
    exit 2
fi
for profile in "${normal_multi_profiles[@]}"; do
    old_ifs="$IFS"
    IFS=: read -r sources rate extra <<< "$profile"
    IFS="$old_ifs"
    if [[ -n "${extra:-}" ]] || ! is_uint "${sources:-}" || ! is_uint "${rate:-}" ||
        ((sources < 2 || sources > 64 || rate < sources || rate > 200)); then
        echo "錯誤：無效的正常多來源設定 '$profile'，格式應為 來源數:總連線率。" >&2
        echo "總連線率必須至少等於來源數，確保每個 IP 每秒都有流量。" >&2
        exit 2
    fi
    if ((sources > MAX_NORMAL_SOURCES)); then
        MAX_NORMAL_SOURCES=$sources
    fi
done

for required_file in "$HPING_DOCKERFILE" "$NORMAL_CLIENT_DOCKERFILE" \
    "$SOURCE_IP_ALLOCATOR" "$NORMAL_CONNECTION_SCRIPT" \
    "$NORMAL_KEEPALIVE_SCRIPT" "$MERGE_SCRIPT" \
    "$EVALUATOR" "$RUNTIME_MODEL"; do
    if [[ ! -f "$required_file" ]]; then
        echo "錯誤：找不到 $required_file" >&2
        exit 1
    fi
done

if [[ -z "$OUTPUT_DIR" ]]; then
    if [[ "$DATASET_ROLE" == "training" ]]; then
        OUTPUT_DIR="$SCRIPT_DIR/results/training_capture_$(date '+%Y%m%d_%H%M%S')"
    else
        OUTPUT_DIR="$SCRIPT_DIR/results/final_holdout_$(date '+%Y%m%d_%H%M%S')"
    fi
fi
mkdir -p -- "$OUTPUT_DIR"
RUN_ID="$(basename "$OUTPUT_DIR")"
LABEL_FILE="$OUTPUT_DIR/scenario_labels.csv"
PLAN_FILE="$OUTPUT_DIR/test_plan.csv"
ATTACKER_CONTAINER="synlab-hping-${RUN_ID//[^a-zA-Z0-9_.-]/-}"
NORMAL_CLIENT_CONTAINER="synlab-normal-${RUN_ID//[^a-zA-Z0-9_.-]/-}"

csv_row() {
    local first=1 value escaped
    for value in "$@"; do
        escaped=${value//\"/\"\"}
        if [[ $first -eq 0 ]]; then printf ','; fi
        printf '"%s"' "$escaped"
        first=0
    done
    printf '\n'
}

csv_row run_id scenario label include_in_training include_in_evaluation \
    start_time end_time start_epoch end_epoch actual_duration_seconds target \
    source_mode configured_rate configured_sources command_status notes > "$LABEL_FILE"
csv_row order scenario label evaluation duration_seconds source_mode configured_rate \
    configured_sources notes > "$PLAN_FILE"

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    if [[ -n "$ACTIVE_PID" ]]; then
        kill "$ACTIVE_PID" 2>/dev/null || true
        wait "$ACTIVE_PID" 2>/dev/null || true
    fi
    if [[ $ATTACKER_CREATED -eq 1 && $KEEP_ATTACKER -eq 0 ]]; then
        "${DOCKER[@]}" rm -f "$ATTACKER_CONTAINER" >/dev/null 2>&1 || true
    fi
    if [[ $NORMAL_CLIENT_CREATED -eq 1 ]]; then
        "${DOCKER[@]}" rm -f "$NORMAL_CLIENT_CONTAINER" >/dev/null 2>&1 || true
    fi
    if [[ -n "$SUDO_KEEPALIVE_PID" ]]; then
        kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
        wait "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    fi
    if [[ $exit_code -ne 0 ]]; then
        echo "實驗中止：已完成的標籤仍保存在 $LABEL_FILE" >&2
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP

run_phase() {
    local scenario="$1" label="$2" evaluation="$3" duration="$4"
    local source_mode="$5" rate="$6" sources="$7" notes="$8"
    shift 8
    local start_time end_time start_epoch end_epoch elapsed status log_file tolerance
    local include_training=0 include_evaluation=0

    CURRENT_SCENARIO="$scenario"
    log_file="$OUTPUT_DIR/${scenario}.log"
    start_time="$(date '+%Y-%m-%d %H:%M:%S')"
    start_epoch="$(date '+%s')"
    echo "[$start_time] 開始：$scenario (${duration}s, mode=$source_mode)"
    status=0
    if [[ $DRY_RUN -eq 1 ]]; then
        printf 'DRY RUN command:' > "$log_file"
        printf ' %q' "$@" >> "$log_file"
        printf '\n' >> "$log_file"
    else
        set +e
        "$@" > "$log_file" 2>&1
        status=$?
        set -e
    fi
    end_time="$(date '+%Y-%m-%d %H:%M:%S')"
    end_epoch="$(date '+%s')"
    elapsed=$((end_epoch - start_epoch))

    if [[ $DRY_RUN -eq 0 && $status -eq 0 ]]; then
        tolerance=$((duration / 2))
        if ((tolerance < 15)); then tolerance=15; fi
        if ((elapsed > duration + tolerance)); then
            status=124
            evaluation=0
            EXCLUDED_PHASES=$((EXCLUDED_PHASES + 1))
            notes="${notes}；執行時間異常，已排除"
        fi
    fi

    if [[ $status -eq 0 && ( "$label" == "0" || "$label" == "1" ) ]]; then
        if [[ "$DATASET_ROLE" == "training" ]]; then
            include_training=1
        else
            include_evaluation="$evaluation"
        fi
    fi

    csv_row "$RUN_ID" "$scenario" "$label" "$include_training" "$include_evaluation" \
        "$start_time" "$end_time" "$start_epoch" "$end_epoch" "$elapsed" \
        "${TARGET_IP:-dry-run}:$TARGET_PORT" "$source_mode" "$rate" "$sources" \
        "$status" "$notes" >> "$LABEL_FILE"
    if [[ $status -ne 0 && $status -ne 124 ]]; then
        echo "錯誤：$scenario 失敗，請查看 $log_file" >&2
        return "$status"
    fi
}

phase_order=0
plan_phase() {
    phase_order=$((phase_order + 1))
    csv_row "$phase_order" "$@" >> "$PLAN_FILE"
}

cooldown_number=0
run_cooldown() {
    cooldown_number=$((cooldown_number + 1))
    run_phase "cooldown_$(printf '%02d' "$cooldown_number")" -1 0 \
        "$COOLDOWN_SECONDS" none 0 0 "情境切換，等待告警狀態恢復" \
        sleep "$COOLDOWN_SECONDS"
}

run_normal_connections() {
    python3 "$NORMAL_CONNECTION_SCRIPT" --host "$TARGET_IP" --port "$TARGET_PORT" \
        --rate "$1" --duration "$2"
}

run_normal_keepalive() {
    python3 "$NORMAL_KEEPALIVE_SCRIPT" --host "$TARGET_IP" --port "$TARGET_PORT" \
        --vus "$1" --duration "$2"
}

first_normal_source_ips() {
    local requested="$1" value index=0 selected=""
    local old_ifs="$IFS"
    local -a all_source_ips
    IFS=',' read -r -a all_source_ips <<< "$NORMAL_SOURCE_IPS"
    IFS="$old_ifs"
    if ((${#all_source_ips[@]} < requested)); then
        echo "錯誤：只配置了 ${#all_source_ips[@]} 個正常來源 IP，需要 $requested 個。" >&2
        return 1
    fi
    for value in "${all_source_ips[@]}"; do
        if ((index >= requested)); then break; fi
        if [[ -n "$selected" ]]; then selected+=","; fi
        selected+="$value"
        index=$((index + 1))
    done
    printf '%s\n' "$selected"
}

run_normal_multi_source() {
    local sources="$1" rate="$2" duration="$3"
    local minimum_success_ratio="${4:-0.90}" source_ips
    source_ips="$(first_normal_source_ips "$sources")"
    "${DOCKER[@]}" exec "$NORMAL_CLIENT_CONTAINER" \
        python3 /usr/local/bin/normal_tcp_connections.py \
        --host "$TARGET_IP" --port "$TARGET_PORT" \
        --rate "$rate" --duration "$duration" --source-ips "$source_ips" \
        --minimum-success-ratio "$minimum_success_ratio"
}

run_syn_single() {
    local rate="$1" duration="$2"
    "${DOCKER[@]}" exec \
        -e "HPING_TARGET=$TARGET_IP" -e "HPING_PORT=$TARGET_PORT" \
        -e "HPING_RATE=$rate" -e "HPING_DURATION=$duration" \
        -e "HPING_SOURCE_IPS=" -e "HPING_RAND_SOURCE=0" \
        "$ATTACKER_CONTAINER" /usr/local/bin/hping3_multi_source.sh
}

run_syn_rand() {
    local rate="$1" duration="$2"
    "${DOCKER[@]}" exec \
        -e "HPING_TARGET=$TARGET_IP" -e "HPING_PORT=$TARGET_PORT" \
        -e "HPING_RATE=$rate" -e "HPING_DURATION=$duration" \
        -e "HPING_SOURCE_IPS=" -e "HPING_RAND_SOURCE=1" \
        -e "HPING_ISOLATED_LAB=1" \
        "$ATTACKER_CONTAINER" /usr/local/bin/hping3_multi_source.sh
}

run_mixed_single() {
    local vus="$1" rate="$2" duration="$3" normal_status attack_status
    python3 "$NORMAL_KEEPALIVE_SCRIPT" --host "$TARGET_IP" --port "$TARGET_PORT" \
        --vus "$vus" --duration "$duration" --minimum-success-ratio 0 \
        > "$OUTPUT_DIR/${CURRENT_SCENARIO}_normal.log" 2>&1 &
    ACTIVE_PID=$!
    set +e
    run_syn_single "$rate" "$duration"
    attack_status=$?
    wait "$ACTIVE_PID"
    normal_status=$?
    set -e
    ACTIVE_PID=""
    if [[ $attack_status -ne 0 ]]; then return "$attack_status"; fi
    return "$normal_status"
}

run_mixed_rand() {
    local vus="$1" rate="$2" duration="$3" normal_status attack_status
    python3 "$NORMAL_KEEPALIVE_SCRIPT" --host "$TARGET_IP" --port "$TARGET_PORT" \
        --vus "$vus" --duration "$duration" --minimum-success-ratio 0 \
        > "$OUTPUT_DIR/${CURRENT_SCENARIO}_normal.log" 2>&1 &
    ACTIVE_PID=$!
    set +e
    run_syn_rand "$rate" "$duration"
    attack_status=$?
    wait "$ACTIVE_PID"
    normal_status=$?
    set -e
    ACTIVE_PID=""
    if [[ $attack_status -ne 0 ]]; then return "$attack_status"; fi
    return "$normal_status"
}

# Record the complete plan before touching Docker. Diagnostics have evaluation=0
# because there is no defensible benign/attack ground truth near the boundary.
plan_phase warmup -1 0 15 none 0 0 "收集器預熱"
plan_phase idle 0 1 "$PHASE_SECONDS" none 0 0 "無主動測試流量"
old_ifs="$IFS"; IFS=',' read -r -a normal_rates <<< "$NORMAL_CONNECTION_SPEC"; IFS="$old_ifs"
for rate in "${normal_rates[@]}"; do
    plan_phase "normal_completed_${rate}cps" 0 1 "$PHASE_SECONDS" host 0 0 "正常新 HTTP 連線"
done
old_ifs="$IFS"; IFS=',' read -r -a normal_vus <<< "$NORMAL_VUS_SPEC"; IFS="$old_ifs"
for vus in "${normal_vus[@]}"; do
    plan_phase "normal_keepalive_${vus}vus" 0 1 "$PHASE_SECONDS" host 0 0 "正常 keep-alive HTTP"
done
for profile in "${normal_multi_profiles[@]}"; do
    old_ifs="$IFS"; IFS=: read -r sources rate <<< "$profile"; IFS="$old_ifs"
    plan_phase "warmup_normal_multi_${sources}ips_${rate}cps" -1 0 \
        "$NORMAL_MULTI_WARMUP_SECONDS" normal_multi_warmup "$rate" "$sources" \
        "多 IP 正常流量網路暖機，不納入訓練或評估"
    plan_phase "normal_multi_${sources}ips_${rate}cps" 0 1 "$PHASE_SECONDS" \
        normal_multi_ip "$rate" "$sources" "單一 Client Container 的多 IP 正常連線"
done
old_ifs="$IFS"; IFS=',' read -r -a benign_rates <<< "$BENIGN_SYN_SPEC"; IFS="$old_ifs"
for rate in "${benign_rates[@]}"; do
    plan_phase "benign_background_syn_${rate}pps" 0 1 "$PHASE_SECONDS" hping_single "$rate" 1 "低量背景純 SYN"
done
old_ifs="$IFS"; IFS=',' read -r -a diagnostic_rates <<< "$DIAGNOSTIC_SYN_SPEC"; IFS="$old_ifs"
for rate in "${diagnostic_rates[@]}"; do
    plan_phase "diagnostic_syn_${rate}pps" -1 0 "$PHASE_SECONDS" hping_single "$rate" 1 "邊界診斷，不計分"
done
plan_phase attack_short_single_70pps 1 1 "$SHORT_ATTACK_SECONDS" hping_single 70 1 "短攻擊反應時間"
plan_phase attack_short_rand_150pps 1 1 "$SHORT_ATTACK_SECONDS" hping_rand_source 150 random "短時間每封包隨機來源攻擊"
old_ifs="$IFS"; IFS=',' read -r -a single_rates <<< "$SINGLE_ATTACK_SPEC"; IFS="$old_ifs"
for rate in "${single_rates[@]}"; do
    plan_phase "attack_single_${rate}pps" 1 1 "$ATTACK_SECONDS" hping_single "$rate" 1 "長時間單來源 SYN Flood"
done
old_ifs="$IFS"; IFS=',' read -r -a rand_rates <<< "$RAND_ATTACK_SPEC"; IFS="$old_ifs"
for rate in "${rand_rates[@]}"; do
    plan_phase "attack_rand_${rate}pps" 1 1 "$ATTACK_SECONDS" hping_rand_source "$rate" random "每個封包使用隨機來源 IP"
done
old_ifs="$IFS"; IFS=',' read -r -a mixed_single_profiles <<< "$MIXED_SINGLE_SPEC"; IFS="$old_ifs"
for profile in "${mixed_single_profiles[@]}"; do
    old_ifs="$IFS"; IFS=: read -r vus rate <<< "$profile"; IFS="$old_ifs"
    plan_phase "mixed_single_${vus}vus_${rate}pps" 1 1 "$ATTACK_SECONDS" hping_single "$rate" 1 "正常 HTTP + 單來源攻擊"
done
old_ifs="$IFS"; IFS=',' read -r -a mixed_rand_profiles <<< "$MIXED_RAND_SPEC"; IFS="$old_ifs"
for profile in "${mixed_rand_profiles[@]}"; do
    old_ifs="$IFS"; IFS=: read -r vus rate <<< "$profile"; IFS="$old_ifs"
    plan_phase "mixed_rand_${vus}vus_${rate}pps" 1 1 "$ATTACK_SECONDS" hping_rand_source "$rate" random "正常 HTTP + 每封包隨機來源 SYN Flood"
done

estimated_active=$((
    15 + PHASE_SECONDS
    + 4 * PHASE_SECONDS + 3 * PHASE_SECONDS
    + ${#normal_multi_profiles[@]} * (PHASE_SECONDS + NORMAL_MULTI_WARMUP_SECONDS)
    + 2 * PHASE_SECONDS + 3 * PHASE_SECONDS
    + 2 * SHORT_ATTACK_SECONDS
    + 4 * ATTACK_SECONDS + 4 * ATTACK_SECONDS
    + 3 * ATTACK_SECONDS + 3 * ATTACK_SECONDS
))
estimated_cooldowns=$(((29 + ${#normal_multi_profiles[@]}) * COOLDOWN_SECONDS))
estimated_total=$((estimated_active + estimated_cooldowns))

cat <<EOF

SYN Flood 資料收集實驗
資料角色      : $DATASET_ROLE
受測 Container : $TARGET_CONTAINER
受測 port      : $TARGET_PORT
單段正常時間  : ${PHASE_SECONDS}s
多 IP 暖機時間   : ${NORMAL_MULTI_WARMUP_SECONDS}s（不納入資料集）
單段攻擊時間  : ${ATTACK_SECONDS}s
cooldown       : ${COOLDOWN_SECONDS}s
預估總時間      : 約 $((estimated_total / 60)) 分 $((estimated_total % 60)) 秒
輸出資料夾      : $OUTPUT_DIR

training 模式會產生訓練資料但不評估；holdout 模式只做獨立評估。
EOF

if [[ $DRY_RUN -eq 1 ]]; then
    echo "DRY RUN 完成。測試計畫：$PLAN_FILE"
    exit 0
fi

for command_name in docker python3 curl awk; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "錯誤：找不到 $command_name" >&2; exit 1
    fi
done
if [[ ! -f "$STATS_CSV" ]]; then
    echo "錯誤：找不到 $STATS_CSV，請先啟動 tcpip_stats.py" >&2
    exit 1
fi

if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
else
    if ! command -v sudo >/dev/null 2>&1; then
        echo "錯誤：無法連線 Docker，也沒有 sudo。" >&2; exit 1
    fi
    sudo -v
    DOCKER=(sudo -n docker)
    (
        while kill -0 "$$" 2>/dev/null; do
            sudo -n -v >/dev/null 2>&1 || exit 1
            sleep 60
        done
    ) &
    SUDO_KEEPALIVE_PID=$!
fi

if [[ "$("${DOCKER[@]}" inspect -f '{{.State.Running}}' "$TARGET_CONTAINER" 2>/dev/null || true)" != "true" ]]; then
    echo "錯誤：Container '$TARGET_CONTAINER' 不存在或未執行。" >&2; exit 1
fi

network_rows="$(
    "${DOCKER[@]}" inspect -f '{{range $name,$settings := .NetworkSettings.Networks}}{{$name}} {{$settings.IPAddress}}{{println}}{{end}}' "$TARGET_CONTAINER"
)"
network_count="$(awk 'NF == 2 {count++} END {print count + 0}' <<< "$network_rows")"
if [[ "$network_count" -ne 1 ]]; then
    echo "錯誤：$TARGET_CONTAINER 必須只連接一個 Docker 網路，才能確定 eBPF 監控的 eth0。" >&2
    echo "$network_rows" >&2
    exit 1
fi
read -r TARGET_NETWORK TARGET_IP <<< "$network_rows"
if [[ -z "${TARGET_NETWORK:-}" || -z "${TARGET_IP:-}" ]]; then
    echo "錯誤：無法取得受測 Container 的 Docker 網路與 IPv4。" >&2; exit 1
fi
TARGET_SUBNET="$("${DOCKER[@]}" network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$TARGET_NETWORK")"
TARGET_GATEWAY="$("${DOCKER[@]}" network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$TARGET_NETWORK")"
TARGET_NETWORK_INTERNAL="$("${DOCKER[@]}" network inspect -f '{{.Internal}}' "$TARGET_NETWORK")"
TARGET_PORT_BINDINGS="$("${DOCKER[@]}" inspect -f '{{json .HostConfig.PortBindings}}' "$TARGET_CONTAINER")"

if [[ "$TARGET_NETWORK_INTERNAL" != "true" ]]; then
    echo "錯誤：Docker 網路 '$TARGET_NETWORK' 不是 --internal 隔離網路。" >&2
    echo "--rand-source 只能在與外部網路隔離的專用實驗網路中執行。" >&2
    echo "請先執行：./traffic_test/create_isolated_synlab.sh" >&2
    exit 1
fi
if [[ "$TARGET_PORT_BINDINGS" != "null" && "$TARGET_PORT_BINDINGS" != "{}" ]]; then
    echo "錯誤：$TARGET_CONTAINER 仍有對 Host 發布的 port：$TARGET_PORT_BINDINGS" >&2
    echo "請改用沒有 -p/--publish 的專用受測 Container。" >&2
    exit 1
fi

if ! curl --fail --silent --show-error --max-time 5 "http://${TARGET_IP}:${TARGET_PORT}/" >/dev/null; then
    echo "錯誤：無法從 Ubuntu 存取 http://${TARGET_IP}:${TARGET_PORT}/" >&2; exit 1
fi

if [[ $ASSUME_YES -eq 0 ]]; then
    read -r -p "確定要對自己的 $TARGET_CONTAINER ($TARGET_IP) 執行約 $((estimated_total / 60)) 分鐘測試嗎？ [y/N] " reply
    case "$reply" in y|Y|yes|YES) ;; *) echo "已取消。"; exit 0 ;; esac
fi

echo "建置 hping3 與正常多來源 Client 映像..."
"${DOCKER[@]}" build -t "$HPING_IMAGE" -f "$HPING_DOCKERFILE" "$SCRIPT_DIR"
"${DOCKER[@]}" build -t "$NORMAL_CLIENT_IMAGE" \
    -f "$NORMAL_CLIENT_DOCKERFILE" "$SCRIPT_DIR"
"${DOCKER[@]}" rm -f "$ATTACKER_CONTAINER" >/dev/null 2>&1 || true
"${DOCKER[@]}" rm -f "$NORMAL_CLIENT_CONTAINER" >/dev/null 2>&1 || true
"${DOCKER[@]}" run -d --name "$ATTACKER_CONTAINER" \
    --network "$TARGET_NETWORK" --cap-add NET_RAW --entrypoint sleep \
    "$HPING_IMAGE" infinity >/dev/null
ATTACKER_CREATED=1
ATTACKER_IP="$("${DOCKER[@]}" inspect -f "{{(index .NetworkSettings.Networks \"$TARGET_NETWORK\").IPAddress}}" "$ATTACKER_CONTAINER")"

"${DOCKER[@]}" run -d --name "$NORMAL_CLIENT_CONTAINER" \
    --network "$TARGET_NETWORK" --cap-add NET_ADMIN \
    "$NORMAL_CLIENT_IMAGE" >/dev/null
NORMAL_CLIENT_CREATED=1
NORMAL_CLIENT_IP="$("${DOCKER[@]}" inspect -f "{{(index .NetworkSettings.Networks \"$TARGET_NETWORK\").IPAddress}}" "$NORMAL_CLIENT_CONTAINER")"

NORMAL_SOURCE_IPS="$(
    python3 "$SOURCE_IP_ALLOCATOR" \
        --subnet "$TARGET_SUBNET" \
        --count "$MAX_NORMAL_SOURCES" \
        --exclude "$TARGET_GATEWAY,$TARGET_IP,$ATTACKER_IP,$NORMAL_CLIENT_IP"
)"
NETWORK_PREFIX="${TARGET_SUBNET#*/}"
old_ifs="$IFS"
IFS=',' read -r -a configured_normal_source_ips <<< "$NORMAL_SOURCE_IPS"
IFS="$old_ifs"
for source_ip in "${configured_normal_source_ips[@]}"; do
    "${DOCKER[@]}" exec "$NORMAL_CLIENT_CONTAINER" \
        ip address add "$source_ip/$NETWORK_PREFIX" dev eth0
done

echo "目標：$TARGET_IP:$TARGET_PORT"
echo "Docker 網路：$TARGET_NETWORK ($TARGET_SUBNET)"
echo "hping3 Container：$ATTACKER_CONTAINER ($ATTACKER_IP)"
echo "正常 Client Container：$NORMAL_CLIENT_CONTAINER ($NORMAL_CLIENT_IP)"
echo "正常 Client 額外來源 IP：$NORMAL_SOURCE_IPS"

initial_stats_size="$(stat -c %s "$STATS_CSV")"
sleep 3
after_probe_size="$(stat -c %s "$STATS_CSV")"
if [[ "$after_probe_size" -le "$initial_stats_size" ]]; then
    echo "錯誤：$STATS_CSV 沒有持續增加，請先確認 tcpip_stats.py 正在執行。" >&2
    exit 1
fi

{
    echo "run_id=$RUN_ID"
    echo "dataset_role=$DATASET_ROLE"
    echo "target_container=$TARGET_CONTAINER"
    echo "target_ip=$TARGET_IP"
    echo "target_port=$TARGET_PORT"
    echo "docker_network=$TARGET_NETWORK"
    echo "docker_network_internal=$TARGET_NETWORK_INTERNAL"
    echo "docker_subnet=$TARGET_SUBNET"
    echo "attacker_container=$ATTACKER_CONTAINER"
    echo "attacker_ip=$ATTACKER_IP"
    echo "normal_client_container=$NORMAL_CLIENT_CONTAINER"
    echo "normal_client_primary_ip=$NORMAL_CLIENT_IP"
    echo "normal_client_source_ips=$NORMAL_SOURCE_IPS"
    echo "normal_multi_source_profiles=$NORMAL_MULTI_SOURCE_SPEC"
    echo "normal_multi_warmup_seconds=$NORMAL_MULTI_WARMUP_SECONDS"
    echo "phase_seconds=$PHASE_SECONDS"
    echo "attack_seconds=$ATTACK_SECONDS"
    echo "cooldown_seconds=$COOLDOWN_SECONDS"
    echo "runtime_model=$RUNTIME_MODEL"
} > "$OUTPUT_DIR/metadata.txt"

run_phase warmup -1 0 15 none 0 0 "收集器預熱" sleep 15
run_phase idle 0 1 "$PHASE_SECONDS" none 0 0 "無主動測試流量" sleep "$PHASE_SECONDS"
run_cooldown

for rate in "${normal_rates[@]}"; do
    run_phase "normal_completed_${rate}cps" 0 1 "$PHASE_SECONDS" host 0 0 \
        "${rate} 個/秒正常新 HTTP 連線" run_normal_connections "$rate" "$PHASE_SECONDS"
    run_cooldown
done
for vus in "${normal_vus[@]}"; do
    run_phase "normal_keepalive_${vus}vus" 0 1 "$PHASE_SECONDS" host 0 0 \
        "${vus} VUs 正常 keep-alive HTTP" run_normal_keepalive "$vus" "$PHASE_SECONDS"
    run_cooldown
done
for profile in "${normal_multi_profiles[@]}"; do
    old_ifs="$IFS"; IFS=: read -r sources rate <<< "$profile"; IFS="$old_ifs"
    run_phase "warmup_normal_multi_${sources}ips_${rate}cps" -1 0 \
        "$NORMAL_MULTI_WARMUP_SECONDS" normal_multi_warmup "$rate" "$sources" \
        "多 IP 正常流量網路暖機，不納入訓練或評估" \
        run_normal_multi_source "$sources" "$rate" \
        "$NORMAL_MULTI_WARMUP_SECONDS" 0
    run_phase "normal_multi_${sources}ips_${rate}cps" 0 1 "$PHASE_SECONDS" \
        normal_multi_ip "$rate" "$sources" \
        "${sources} 個來源 IP，共 ${rate} 個/秒正常新 HTTP 連線" \
        run_normal_multi_source "$sources" "$rate" "$PHASE_SECONDS"
    run_cooldown
done
for rate in "${benign_rates[@]}"; do
    run_phase "benign_background_syn_${rate}pps" 0 1 "$PHASE_SECONDS" hping_single "$rate" 1 \
        "低量背景純 SYN，檢查誤報" run_syn_single "$rate" "$PHASE_SECONDS"
    run_cooldown
done
for rate in "${diagnostic_rates[@]}"; do
    run_phase "diagnostic_syn_${rate}pps" -1 0 "$PHASE_SECONDS" hping_single "$rate" 1 \
        "邊界診斷，不計分" run_syn_single "$rate" "$PHASE_SECONDS"
    run_cooldown
done

run_phase attack_short_single_70pps 1 1 "$SHORT_ATTACK_SECONDS" hping_single 70 1 \
    "短攻擊，檢查 2-of-3 告警延遲" run_syn_single 70 "$SHORT_ATTACK_SECONDS"
run_cooldown
run_phase attack_short_rand_150pps 1 1 "$SHORT_ATTACK_SECONDS" hping_rand_source 150 random \
    "短時間每封包隨機來源攻擊" run_syn_rand 150 "$SHORT_ATTACK_SECONDS"
run_cooldown

for rate in "${single_rates[@]}"; do
    run_phase "attack_single_${rate}pps" 1 1 "$ATTACK_SECONDS" hping_single "$rate" 1 \
        "單來源長時間 SYN Flood" run_syn_single "$rate" "$ATTACK_SECONDS"
    run_cooldown
done
for rate in "${rand_rates[@]}"; do
    run_phase "attack_rand_${rate}pps" 1 1 "$ATTACK_SECONDS" hping_rand_source "$rate" random \
        "每封包使用隨機來源 IP 的 SYN Flood" run_syn_rand "$rate" "$ATTACK_SECONDS"
    run_cooldown
done
for profile in "${mixed_single_profiles[@]}"; do
    old_ifs="$IFS"; IFS=: read -r vus rate <<< "$profile"; IFS="$old_ifs"
    run_phase "mixed_single_${vus}vus_${rate}pps" 1 1 "$ATTACK_SECONDS" hping_single "$rate" 1 \
        "${vus} VUs 正常 HTTP + 單來源 SYN Flood" run_mixed_single "$vus" "$rate" "$ATTACK_SECONDS"
    run_cooldown
done
for profile in "${mixed_rand_profiles[@]}"; do
    old_ifs="$IFS"; IFS=: read -r vus rate <<< "$profile"; IFS="$old_ifs"
    run_phase "mixed_rand_${vus}vus_${rate}pps" 1 1 "$ATTACK_SECONDS" hping_rand_source "$rate" random \
        "${vus} VUs 正常 HTTP + 每封包隨機來源 SYN Flood" run_mixed_rand "$vus" "$rate" "$ATTACK_SECONDS"
    run_cooldown
done

echo
if [[ "$DATASET_ROLE" == "training" ]]; then
    LABELED_CSV="$OUTPUT_DIR/training_labeled.csv"
    python3 "$MERGE_SCRIPT" --stats "$STATS_CSV" --labels "$LABEL_FILE" \
        --output "$LABELED_CSV" --boundary-seconds "$BOUNDARY_SECONDS"
    echo "訓練資料收集完成。"
    echo "標籤：$LABEL_FILE"
    echo "已合併訓練資料：$LABELED_CSV"
    echo "這一輪不可同時當成模型準確率測試資料。"
else
    LABELED_CSV="$OUTPUT_DIR/final_holdout_labeled.csv"
    EVALUATION_DIR="$OUTPUT_DIR/evaluation"
    python3 "$MERGE_SCRIPT" --stats "$STATS_CSV" --labels "$LABEL_FILE" \
        --output "$LABELED_CSV" --boundary-seconds "$BOUNDARY_SECONDS" \
        --include-evaluation-only
    python3 "$EVALUATOR" --input "$LABELED_CSV" --runtime-model "$RUNTIME_MODEL" \
        --output-dir "$EVALUATION_DIR"
    echo "獨立測試完成。"
    echo "標籤：$LABEL_FILE"
    echo "已合併資料：$LABELED_CSV"
    echo "評估報告：$EVALUATION_DIR/SUMMARY.md"
    echo "請不要將 final_holdout_labeled.csv 加回訓練。"
fi
echo "時間異常而排除的情境數：$EXCLUDED_PHASES"
