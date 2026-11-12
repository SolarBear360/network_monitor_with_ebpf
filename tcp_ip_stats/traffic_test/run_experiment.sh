#!/usr/bin/env bash

# 在 Mac 上執行：產生正常 HTTP 流量和有上限的純 SYN 流量。
# 這支腳本只接受私有 IPv4，並且不使用 nping --flood。

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K6_SCRIPT="$SCRIPT_DIR/normal_http.js"

TARGET_HOST=""
TARGET_PORT=8080
DURATION_SECONDS=60
COOLDOWN_SECONDS=20
EXTENDED=0
PROFILE_VUS=""
PROFILE_SYN_RATE=""
DRY_RUN=0
ASSUME_YES=0
OUTPUT_DIR=""
ACTIVE_PID=""

show_help() {
    cat <<'EOF'
使用方式（在 Mac 上執行）：
  ./run_experiment.sh --target PRIVATE_IPV4 [選項]

必要選項：
  --target IPv4       測試主機的私有 IPv4，例如 192.168.1.183

其他選項：
  --port PORT         Docker 公開的主機 port（預設：8080）
  --duration SEC      每個主要情境的秒數（10–300，預設：60）
  --cooldown SEC      情境之間的休息秒數（3–120，預設：20）
  --quick             只做管線檢查：每段 15 秒，休息 5 秒
  --extended          加做 200 packets/s 純 SYN 情境
  --profile-vus N     單輪參數模式的正常 HTTP VUs（1–200）
  --profile-syn-rate N
                      單輪參數模式的純 SYN packets/s（1–300）
  --output-dir DIR    指定結果資料夾
  --dry-run           只顯示情境，不產生流量
  -y, --yes           略過執行前確認
  -h, --help          顯示說明

範例：
  ./run_experiment.sh --target 192.168.1.183 --port 8080 --quick
  ./run_experiment.sh --target 192.168.1.183 --port 8080 --extended
  ./run_experiment.sh --target 192.168.1.183 --profile-vus 30 --profile-syn-rate 70
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

is_private_ipv4() {
    local ip="$1"
    local a b c d octet

    if [[ ! "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        return 1
    fi

    IFS=. read -r a b c d <<< "$ip"
    for octet in "$a" "$b" "$c" "$d"; do
        if ((10#$octet < 0 || 10#$octet > 255)); then
            return 1
        fi
    done

    a=$((10#$a))
    b=$((10#$b))

    # RFC1918、loopback，以及 Tailscale 常用的 100.64.0.0/10。
    ((a == 10)) ||
        ((a == 127)) ||
        ((a == 172 && b >= 16 && b <= 31)) ||
        ((a == 192 && b == 168)) ||
        ((a == 100 && b >= 64 && b <= 127))
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            require_value "$@"
            TARGET_HOST="$2"
            shift 2
            ;;
        --port)
            require_value "$@"
            TARGET_PORT="$2"
            shift 2
            ;;
        --duration)
            require_value "$@"
            DURATION_SECONDS="$2"
            shift 2
            ;;
        --cooldown)
            require_value "$@"
            COOLDOWN_SECONDS="$2"
            shift 2
            ;;
        --quick)
            DURATION_SECONDS=15
            COOLDOWN_SECONDS=5
            shift
            ;;
        --extended)
            EXTENDED=1
            shift
            ;;
        --profile-vus)
            require_value "$@"
            PROFILE_VUS="$2"
            shift 2
            ;;
        --profile-syn-rate)
            require_value "$@"
            PROFILE_SYN_RATE="$2"
            shift 2
            ;;
        --output-dir)
            require_value "$@"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -y|--yes)
            ASSUME_YES=1
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

if [[ -z "$TARGET_HOST" ]]; then
    echo "錯誤：必須使用 --target 指定你自己的測試主機。" >&2
    exit 2
fi

if ! is_private_ipv4 "$TARGET_HOST"; then
    echo "錯誤：為避免誤測公網主機，這支腳本只接受私有 IPv4。" >&2
    exit 2
fi

if ! is_uint "$TARGET_PORT" || ((TARGET_PORT < 1 || TARGET_PORT > 65535)); then
    echo "錯誤：port 必須介於 1–65535。" >&2
    exit 2
fi

if ! is_uint "$DURATION_SECONDS" || ((DURATION_SECONDS < 10 || DURATION_SECONDS > 300)); then
    echo "錯誤：duration 必須介於 10–300 秒。" >&2
    exit 2
fi

if ! is_uint "$COOLDOWN_SECONDS" || ((COOLDOWN_SECONDS < 3 || COOLDOWN_SECONDS > 120)); then
    echo "錯誤：cooldown 必須介於 3–120 秒。" >&2
    exit 2
fi

if [[ -n "$PROFILE_VUS" || -n "$PROFILE_SYN_RATE" ]]; then
    if [[ -z "$PROFILE_VUS" || -z "$PROFILE_SYN_RATE" ]]; then
        echo "錯誤：--profile-vus 和 --profile-syn-rate 必須一起使用。" >&2
        exit 2
    fi
    if ! is_uint "$PROFILE_VUS" || ((PROFILE_VUS < 1 || PROFILE_VUS > 200)); then
        echo "錯誤：profile VUs 必須介於 1–200。" >&2
        exit 2
    fi
    if ! is_uint "$PROFILE_SYN_RATE" || ((PROFILE_SYN_RATE < 1 || PROFILE_SYN_RATE > 300)); then
        echo "錯誤：profile SYN rate 必須介於 1–300 packets/s。" >&2
        exit 2
    fi
    if [[ $EXTENDED -eq 1 ]]; then
        echo "錯誤：參數模式不需要 --extended。" >&2
        exit 2
    fi
    PROFILE_MODE=1
else
    PROFILE_MODE=0
fi

if [[ ! -f "$K6_SCRIPT" ]]; then
    echo "錯誤：找不到 $K6_SCRIPT" >&2
    exit 1
fi

if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$SCRIPT_DIR/results/$(date '+%Y%m%d_%H%M%S')"
fi
mkdir -p -- "$OUTPUT_DIR"

RUN_ID="$(basename "$OUTPUT_DIR")"
TARGET_URL="http://$TARGET_HOST:$TARGET_PORT/"
LABEL_FILE="$OUTPUT_DIR/scenario_labels.csv"

csv_row() {
    local first=1
    local value escaped

    for value in "$@"; do
        escaped=${value//\"/\"\"}
        if [[ $first -eq 0 ]]; then
            printf ','
        fi
        printf '"%s"' "$escaped"
        first=0
    done
    printf '\n'
}

csv_row \
    run_id scenario label include_in_training \
    start_time end_time start_epoch end_epoch \
    actual_duration_seconds target command_status notes > "$LABEL_FILE"

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM HUP

    if [[ -n "$ACTIVE_PID" ]]; then
        kill "$ACTIVE_PID" 2>/dev/null || true
        wait "$ACTIVE_PID" 2>/dev/null || true
    fi

    if [[ $exit_code -ne 0 ]]; then
        echo "實驗中止。已完成的標籤仍保存在：$LABEL_FILE" >&2
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP

run_phase() {
    local scenario="$1"
    local label="$2"
    local include_in_training="$3"
    local notes="$4"
    shift 4

    local start_time end_time start_epoch end_epoch actual_duration status
    local log_file="$OUTPUT_DIR/${scenario}.log"

    start_time="$(date '+%Y-%m-%d %H:%M:%S')"
    start_epoch="$(date '+%s')"
    echo
    # Mac 內建的 Bash 3.2 在某些 UTF-8 locale 中，可能會把緊接在
    # $scenario 後面的全形括號誤當成變數名的一部分。
    echo "[${start_time}] 開始：${scenario}（label=${label}）"

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
    actual_duration=$((end_epoch - start_epoch))

    csv_row \
        "$RUN_ID" "$scenario" "$label" "$include_in_training" \
        "$start_time" "$end_time" "$start_epoch" "$end_epoch" \
        "$actual_duration" "$TARGET_HOST:$TARGET_PORT" "$status" "$notes" \
        >> "$LABEL_FILE"

    if [[ $status -ne 0 ]]; then
        echo "錯誤：${scenario} 執行失敗（status=${status}）。" >&2
        echo "請查看：${log_file}" >&2
        return "$status"
    fi

    echo "[${end_time}] 完成：${scenario}（實際 ${actual_duration}s）"
}

run_cooldown() {
    run_phase \
        "cooldown_$1" -1 0 \
        "情境切換期，不納入訓練" \
        sleep "$COOLDOWN_SECONDS"
}

run_k6() {
    local vus="$1"
    local no_reuse="$2"
    local -a command

    command=(
        k6 run
        --no-usage-report
        --quiet
        --vus "$vus"
        --duration "${DURATION_SECONDS}s"
        -e "TARGET_URL=$TARGET_URL"
    )

    if [[ "$no_reuse" -eq 1 ]]; then
        command+=(--no-connection-reuse)
    fi

    command+=("$K6_SCRIPT")
    "${command[@]}"
}

run_syn() {
    local rate="$1"
    local count=$((rate * DURATION_SECONDS))

    sudo nping \
        --tcp \
        --flags SYN \
        --dest-port "$TARGET_PORT" \
        --rate "$rate" \
        --count "$count" \
        --no-capture \
        --quiet \
        "$TARGET_HOST"
}

run_mixed() {
    local vus="$1"
    local rate="$2"
    local count=$((rate * DURATION_SECONDS))
    local k6_status nping_status

    k6 run \
        --no-usage-report \
        --quiet \
        --vus "$vus" \
        --duration "${DURATION_SECONDS}s" \
        -e "TARGET_URL=$TARGET_URL" \
        "$K6_SCRIPT" \
        > "$OUTPUT_DIR/mixed_k6.log" 2>&1 &
    ACTIVE_PID=$!

    set +e
    sudo nping \
        --tcp \
        --flags SYN \
        --dest-port "$TARGET_PORT" \
        --rate "$rate" \
        --count "$count" \
        --no-capture \
        --quiet \
        "$TARGET_HOST"
    nping_status=$?

    wait "$ACTIVE_PID"
    k6_status=$?
    set -e
    ACTIVE_PID=""

    if [[ $nping_status -ne 0 ]]; then
        return "$nping_status"
    fi
    return "$k6_status"
}

if [[ $DRY_RUN -eq 0 ]]; then
    for command_name in curl k6 nping sudo; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "錯誤：找不到 '$command_name'。請先阅讀 README.md 的安裝步驟。" >&2
            exit 1
        fi
    done

    echo "檢查目標 HTTP 服務：$TARGET_URL"
    if ! curl --fail --silent --show-error --max-time 5 "$TARGET_URL" >/dev/null; then
        echo "錯誤：Mac 無法存取 $TARGET_URL" >&2
        echo "請先檢查 Docker port mapping、Ubuntu 防火牆與兩台電腦的網路。" >&2
        exit 1
    fi
fi

cat <<EOF

測試目標       : $TARGET_URL
每個情境       : ${DURATION_SECONDS}s
情境間休息     : ${COOLDOWN_SECONDS}s
擴充 200 pps 情境: $EXTENDED
單輪參數模式   : $PROFILE_MODE
正常 HTTP VUs    : ${PROFILE_VUS:-預設情境組}
純 SYN packets/s    : ${PROFILE_SYN_RATE:-預設情境組}
結果資料夾     : $OUTPUT_DIR

腳本只會對上述私有 IP 發送有上限的測試流量，不會使用 --flood。
EOF

if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 ]]; then
    read -r -p "確定這是你自己的測試主機並開始嗎？ [y/N] " reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) echo "已取消。"; exit 0 ;;
    esac
fi

if [[ $DRY_RUN -eq 0 ]]; then
    # 事先驗證 sudo，避免在 SYN 情境開始後才等待密碼。
    sudo -v
fi

{
    echo "run_id=$RUN_ID"
    echo "target=$TARGET_URL"
    echo "generator_host=$(hostname)"
    echo "generator_time=$(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "duration_seconds=$DURATION_SECONDS"
    echo "cooldown_seconds=$COOLDOWN_SECONDS"
    echo "profile_mode=$PROFILE_MODE"
    echo "profile_vus=$PROFILE_VUS"
    echo "profile_syn_rate=$PROFILE_SYN_RATE"
    if [[ $DRY_RUN -eq 0 ]]; then
        echo "k6_version_begin"
        k6 version 2>&1
        echo "k6_version_end"
        echo "nping_version_begin"
        nping --version 2>&1
        echo "nping_version_end"
    fi
} > "$OUTPUT_DIR/metadata.txt"

# 預熱與舊計數緩衝期：故意不納入訓練。
run_phase warmup -1 0 "收集器預熱，不納入訓練" sleep 10

run_phase idle 0 1 "無主動測試流量" sleep "$DURATION_SECONDS"
run_cooldown 01

if [[ $PROFILE_MODE -eq 1 ]]; then
    run_phase \
        "normal_http_vus_${PROFILE_VUS}" 0 1 \
        "${PROFILE_VUS} VUs，允許連線重用" \
        run_k6 "$PROFILE_VUS" 0
    run_cooldown 02

    run_phase \
        "normal_new_connections_vus_${PROFILE_VUS}" 0 1 \
        "${PROFILE_VUS} VUs，關閉 HTTP 連線重用" \
        run_k6 "$PROFILE_VUS" 1
    run_cooldown 03

    run_phase \
        "syn_${PROFILE_SYN_RATE}pps" 1 1 \
        "固定上限 ${PROFILE_SYN_RATE} packets/s 的純 SYN" \
        run_syn "$PROFILE_SYN_RATE"
    run_cooldown 04

    run_phase \
        "mixed_vus_${PROFILE_VUS}_syn_${PROFILE_SYN_RATE}pps" 1 1 \
        "${PROFILE_VUS} VUs 正常 HTTP + ${PROFILE_SYN_RATE} packets/s 純 SYN" \
        run_mixed "$PROFILE_VUS" "$PROFILE_SYN_RATE"
else
    run_phase normal_http_low 0 1 "5 VUs，允許連線重用" run_k6 5 0
    run_cooldown 02

    run_phase normal_http_high 0 1 "50 VUs，允許連線重用" run_k6 50 0
    run_cooldown 03

    run_phase normal_http_new_connections 0 1 "30 VUs，關閉 HTTP 連線重用" run_k6 30 1
    run_cooldown 04

    run_phase syn_50pps 1 1 "固定上限 50 packets/s 的純 SYN" run_syn 50
    run_cooldown 05

    run_phase syn_100pps 1 1 "固定上限 100 packets/s 的純 SYN" run_syn 100
    run_cooldown 06

    if [[ $EXTENDED -eq 1 ]]; then
        run_phase syn_200pps 1 1 "固定上限 200 packets/s 的純 SYN" run_syn 200
        run_cooldown 07
    fi

    run_phase mixed_http_syn 1 1 "20 VUs 正常 HTTP + 100 packets/s 純 SYN" run_mixed 20 100
fi

echo
echo "全部情境完成。"
echo "標籤檔：$LABEL_FILE"
echo "詳細 log：$OUTPUT_DIR"
