#!/usr/bin/env bash

# 在 Mac 上連續執行多輪實驗，每輪使用不同的正常 HTTP VUs 和純 SYN 速率。
# 實際封包產生與私有 IP 安全檢查由 run_experiment.sh 負責。

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run_experiment.sh"

TARGET_HOST=""
TARGET_PORT=8080
DURATION_SECONDS=60
COOLDOWN_SECONDS=20
ROUND_PAUSE_SECONDS=60
PROFILE_SPEC="10:30,30:70,70:150,70:250"
START_ROUND=1
OUTPUT_ROOT=""
QUICK=0
DRY_RUN=0
ASSUME_YES=0
ACTIVE_CHILD_PID=""

show_help() {
    cat <<'EOF'
使用方式（在 Mac 上執行）：
  ./run_multi_round_experiment.sh --target PRIVATE_IPV4 [選項]

預設四輪：
  round 1: 10 VUs +  30 SYN packets/s
  round 2: 30 VUs +  70 SYN packets/s
  round 3: 70 VUs + 150 SYN packets/s
  round 4: 70 VUs + 250 SYN packets/s

選項：
  --target IPv4       測試主機的私有 IPv4（必要）
  --port PORT         Docker 公開 port（預設：8080）
  --profiles LIST     自訂每輪 VUS:SYN_RATE，例如 10:30,30:70
  --duration SEC      每個主要情境秒數（預設：60）
  --cooldown SEC      每個情境間休息（預設：20）
  --round-pause SEC   每輪之間休息（預設：60）
  --start-round N     從第 N 輪開始，用於中斷後繼續
  --output-dir DIR    指定這批實驗的結果資料夾
  --quick             管線短測試：每情境 15 秒、cooldown 5 秒
  --dry-run           只產生測試計畫與標籤格式，不發送流量
  -y, --yes           略過整批實驗的確認
  -h, --help          顯示說明

範例：
  ./run_multi_round_experiment.sh --target 192.168.1.183 --quick
  ./run_multi_round_experiment.sh --target 192.168.1.183
  ./run_multi_round_experiment.sh --target 192.168.1.183 --profiles 10:30,30:70,70:150,70:250
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
        --profiles)
            require_value "$@"
            PROFILE_SPEC="$2"
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
        --round-pause)
            require_value "$@"
            ROUND_PAUSE_SECONDS="$2"
            shift 2
            ;;
        --start-round)
            require_value "$@"
            START_ROUND="$2"
            shift 2
            ;;
        --output-dir)
            require_value "$@"
            OUTPUT_ROOT="$2"
            shift 2
            ;;
        --quick)
            QUICK=1
            shift
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

for numeric_value in "$TARGET_PORT" "$DURATION_SECONDS" "$COOLDOWN_SECONDS" \
    "$ROUND_PAUSE_SECONDS" "$START_ROUND"; do
    if ! is_uint "$numeric_value"; then
        echo "錯誤：port、時間與 round 參數必須是非負整數。" >&2
        exit 2
    fi
done

if ((TARGET_PORT < 1 || TARGET_PORT > 65535)); then
    echo "錯誤：port 必須介於 1–65535。" >&2
    exit 2
fi
if ((DURATION_SECONDS < 10 || DURATION_SECONDS > 300)); then
    echo "錯誤：duration 必須介於 10–300 秒。" >&2
    exit 2
fi
if ((COOLDOWN_SECONDS < 3 || COOLDOWN_SECONDS > 120)); then
    echo "錯誤：cooldown 必須介於 3–120 秒。" >&2
    exit 2
fi
if ((ROUND_PAUSE_SECONDS < 0 || ROUND_PAUSE_SECONDS > 600)); then
    echo "錯誤：round-pause 必須介於 0–600 秒。" >&2
    exit 2
fi
if [[ ! -x "$RUNNER" ]]; then
    echo "錯誤：找不到可執行的 $RUNNER" >&2
    exit 1
fi

OLD_IFS=$IFS
IFS=',' read -r -a PROFILES <<< "$PROFILE_SPEC"
IFS=$OLD_IFS

if [[ ${#PROFILES[@]} -eq 0 ]]; then
    echo "錯誤：--profiles 至少需要一組 VUS:SYN_RATE。" >&2
    exit 2
fi

for profile in "${PROFILES[@]}"; do
    OLD_IFS=$IFS
    IFS=: read -r profile_vus profile_rate extra <<< "$profile"
    IFS=$OLD_IFS

    if [[ -n "${extra:-}" || -z "${profile_vus:-}" || -z "${profile_rate:-}" ]]; then
        echo "錯誤：無效 profile '$profile'，格式應為 VUS:SYN_RATE。" >&2
        exit 2
    fi
    if ! is_uint "$profile_vus" || ((profile_vus < 1 || profile_vus > 200)); then
        echo "錯誤：profile '$profile' 的 VUs 必須介於 1–200。" >&2
        exit 2
    fi
    if ! is_uint "$profile_rate" || ((profile_rate < 1 || profile_rate > 300)); then
        echo "錯誤：profile '$profile' 的 SYN rate 必須介於 1–300。" >&2
        exit 2
    fi
done

if ((START_ROUND < 1 || START_ROUND > ${#PROFILES[@]})); then
    echo "錯誤：start-round 必須介於 1 和 ${#PROFILES[@]}。" >&2
    exit 2
fi

if [[ -z "$OUTPUT_ROOT" ]]; then
    OUTPUT_ROOT="$SCRIPT_DIR/results/batch_$(date '+%Y%m%d_%H%M%S')"
fi
mkdir -p -- "$OUTPUT_ROOT"

MANIFEST="$OUTPUT_ROOT/batch_manifest.csv"
if [[ ! -s "$MANIFEST" ]]; then
    csv_row \
        round vus syn_rate start_time end_time start_epoch end_epoch \
        status output_dir > "$MANIFEST"
fi

if [[ $QUICK -eq 1 ]]; then
    EFFECTIVE_DURATION=15
    EFFECTIVE_COOLDOWN=5
else
    EFFECTIVE_DURATION=$DURATION_SECONDS
    EFFECTIVE_COOLDOWN=$COOLDOWN_SECONDS
fi

remaining_rounds=$((${#PROFILES[@]} - START_ROUND + 1))
estimated_seconds=$((
    remaining_rounds * (10 + 5 * EFFECTIVE_DURATION + 4 * EFFECTIVE_COOLDOWN)
    + (remaining_rounds - 1) * ROUND_PAUSE_SECONDS
))

echo
echo "測試目標   : http://${TARGET_HOST}:${TARGET_PORT}/"
echo "profiles   : $PROFILE_SPEC"
echo "從第幾輪開始 : $START_ROUND"
echo "輪間休息     : ${ROUND_PAUSE_SECONDS}s"
echo "預估剩餘時間 : 約 $((estimated_seconds / 60)) 分 $((estimated_seconds % 60)) 秒"
echo "結果資料夾   : $OUTPUT_ROOT"
echo
echo "每輪包含 idle、正常 keep-alive、正常新連線、純 SYN 和混合流量。"

if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 ]]; then
    read -r -p "確定這是你自己的私有測試主機並開始嗎？ [y/N] " reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) echo "已取消。"; exit 0 ;;
    esac
fi

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM HUP

    if [[ -n "$ACTIVE_CHILD_PID" ]]; then
        kill -TERM "$ACTIVE_CHILD_PID" 2>/dev/null || true
        wait "$ACTIVE_CHILD_PID" 2>/dev/null || true
    fi

    if [[ $exit_code -ne 0 ]]; then
        echo "多輪實驗中止。可使用 --start-round 和原本 --output-dir 繼續。" >&2
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP

round_number=0
for profile in "${PROFILES[@]}"; do
    round_number=$((round_number + 1))
    if ((round_number < START_ROUND)); then
        continue
    fi

    OLD_IFS=$IFS
    IFS=: read -r profile_vus profile_rate <<< "$profile"
    IFS=$OLD_IFS

    round_padded="$(printf '%02d' "$round_number")"
    round_dir="$OUTPUT_ROOT/run_${round_padded}_vus${profile_vus}_syn${profile_rate}"
    start_time="$(date '+%Y-%m-%d %H:%M:%S')"
    start_epoch="$(date '+%s')"

    echo
    echo "========== Round ${round_number}/${#PROFILES[@]}: ${profile_vus} VUs + ${profile_rate} pps =========="

    command=(
        "$RUNNER"
        --target "$TARGET_HOST"
        --port "$TARGET_PORT"
        --duration "$DURATION_SECONDS"
        --cooldown "$COOLDOWN_SECONDS"
        --profile-vus "$profile_vus"
        --profile-syn-rate "$profile_rate"
        --output-dir "$round_dir"
        --yes
    )

    if [[ $QUICK -eq 1 ]]; then
        command+=(--quick)
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        command+=(--dry-run)
    fi

    set +e
    "${command[@]}" &
    ACTIVE_CHILD_PID=$!
    wait "$ACTIVE_CHILD_PID"
    status=$?
    ACTIVE_CHILD_PID=""
    set -e

    end_time="$(date '+%Y-%m-%d %H:%M:%S')"
    end_epoch="$(date '+%s')"
    csv_row \
        "$round_number" "$profile_vus" "$profile_rate" \
        "$start_time" "$end_time" "$start_epoch" "$end_epoch" \
        "$status" "$round_dir" >> "$MANIFEST"

    if [[ $status -ne 0 ]]; then
        echo "錯誤：第 $round_number 輪失敗，請查看 $round_dir 內的 log。" >&2
        exit "$status"
    fi

    if ((round_number < ${#PROFILES[@]})) && [[ $DRY_RUN -eq 0 ]]; then
        echo "第 $round_number 輪完成，休息 ${ROUND_PAUSE_SECONDS}s。"
        sleep "$ROUND_PAUSE_SECONDS"
    fi
done

echo
echo "多輪實驗全部完成。"
echo "批次紀錄：$MANIFEST"
echo "各輪標籤：$OUTPUT_ROOT/run_*/scenario_labels.csv"

