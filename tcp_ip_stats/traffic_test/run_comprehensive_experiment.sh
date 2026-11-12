#!/usr/bin/env bash

# 在 Mac 上執行的進階版資料收集實驗。
# 只允許私有 IPv4，所有封包速率與持續時間都有上限，不使用 --flood。

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K6_SCRIPT="$SCRIPT_DIR/normal_http.js"
NORMAL_CONNECTION_SCRIPT="$SCRIPT_DIR/normal_tcp_connections.py"

TARGET_HOST=""
TARGET_PORT=8080
PHASE_SECONDS=45
SHORT_ATTACK_SECONDS=10
COOLDOWN_SECONDS=12
NORMAL_CONNECTION_SPEC="1,2,5,10,30"
NORMAL_VUS_SPEC="10,70"
BACKGROUND_SYN_SPEC="1,2"
DIAGNOSTIC_SYN_SPEC="5,10,20"
ATTACK_SYN_SPEC="30,70,150,250"
DIAGNOSTIC_MIXED_SPEC=""
MIXED_SPEC="10:30,30:70,70:150"
OUTPUT_DIR=""
DRY_RUN=0
QUICK=0
ASSUME_YES=0
ACTIVE_PID=""
CAFFEINATE_PID=""
SUDO_KEEPALIVE_PID=""
EXCLUDED_PHASES=0

show_help() {
    cat <<'EOF'
使用方式（在 Mac 上執行）：
  ./run_comprehensive_experiment.sh --target PRIVATE_IPV4 [選項]

測試內容：
  - idle
  - 固定速率、真正完成握手的正常新 TCP/HTTP 連線
  - k6 keep-alive 正常負載
  - 低量純 SYN 背景雜訊（label=0）
  - 介於背景雜訊與 flood 的低速診斷區（不納入訓練）
  - 多種速率 SYN Flood，以及正常 HTTP + SYN 的混合情境
  - 短時間 SYN Flood，檢查連續秒數規則的偵測延遲

必要選項：
  --target IPv4                 你自己的私有 IPv4 測試主機

其他選項：
  --port PORT                   Docker 公開 port（預設 8080）
  --phase-seconds SEC           主要情境秒數（預設 45）
  --short-attack-seconds SEC    短攻擊秒數（預設 10）
  --cooldown SEC                情境之間休息（預設 12）
  --normal-rates LIST           完成握手的正常新連線/秒
  --normal-vus LIST             k6 正常 keep-alive VUs
  --background-syn-rates LIST   標記為非 flood 的低量純 SYN/秒
  --diagnostic-syn-rates LIST   只供觀察、不納入訓練的純 SYN/秒
  --attack-syn-rates LIST       SYN Flood 實驗速率
  --diagnostic-mixed-profiles LIST
                                只供觀察的 VUS:SYN_RATE，不納入訓練
  --mixed-profiles LIST         VUS:SYN_RATE，例如 10:30,30:70
  --output-dir DIR              結果資料夾
  --quick                       管線測試：每段 10 秒、cooldown 3 秒
  --dry-run                     只產生計畫與標籤，不發送流量
  -y, --yes                     略過確認
  -h, --help                    顯示說明

範例：
  ./run_comprehensive_experiment.sh --target 192.168.1.183 --quick
  ./run_comprehensive_experiment.sh --target 192.168.1.183
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
    ((a == 10)) || ((a == 127)) ||
        ((a == 172 && b >= 16 && b <= 31)) ||
        ((a == 192 && b == 168)) ||
        ((a == 100 && b >= 64 && b <= 127))
}

validate_rate_list() {
    local option="$1"
    local raw="$2"
    local maximum="$3"
    local item
    local old_ifs="$IFS"
    IFS=',' read -r -a parsed_items <<< "$raw"
    IFS="$old_ifs"
    if [[ ${#parsed_items[@]} -eq 0 ]]; then
        echo "錯誤：${option} 不可為空。" >&2
        exit 2
    fi
    for item in "${parsed_items[@]}"; do
        if ! is_uint "$item" || ((item < 1 || item > maximum)); then
            echo "錯誤：${option} 的 '$item' 必須介於 1 與 ${maximum}。" >&2
            exit 2
        fi
    done
}

validate_mixed_list() {
    local raw="$1"
    local profile vus rate extra
    local old_ifs="$IFS"
    IFS=',' read -r -a profiles <<< "$raw"
    IFS="$old_ifs"
    for profile in "${profiles[@]}"; do
        old_ifs="$IFS"
        IFS=: read -r vus rate extra <<< "$profile"
        IFS="$old_ifs"
        if [[ -n "${extra:-}" ]] || ! is_uint "${vus:-}" || ! is_uint "${rate:-}" ||
            ((vus < 1 || vus > 200 || rate < 1 || rate > 300)); then
            echo "錯誤：無效 mixed profile '$profile'，格式應為 VUS:SYN_RATE。" >&2
            exit 2
        fi
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) require_value "$@"; TARGET_HOST="$2"; shift 2 ;;
        --port) require_value "$@"; TARGET_PORT="$2"; shift 2 ;;
        --phase-seconds) require_value "$@"; PHASE_SECONDS="$2"; shift 2 ;;
        --short-attack-seconds) require_value "$@"; SHORT_ATTACK_SECONDS="$2"; shift 2 ;;
        --cooldown) require_value "$@"; COOLDOWN_SECONDS="$2"; shift 2 ;;
        --normal-rates) require_value "$@"; NORMAL_CONNECTION_SPEC="$2"; shift 2 ;;
        --normal-vus) require_value "$@"; NORMAL_VUS_SPEC="$2"; shift 2 ;;
        --background-syn-rates) require_value "$@"; BACKGROUND_SYN_SPEC="$2"; shift 2 ;;
        --diagnostic-syn-rates) require_value "$@"; DIAGNOSTIC_SYN_SPEC="$2"; shift 2 ;;
        --attack-syn-rates) require_value "$@"; ATTACK_SYN_SPEC="$2"; shift 2 ;;
        --diagnostic-mixed-profiles) require_value "$@"; DIAGNOSTIC_MIXED_SPEC="$2"; shift 2 ;;
        --mixed-profiles) require_value "$@"; MIXED_SPEC="$2"; shift 2 ;;
        --output-dir) require_value "$@"; OUTPUT_DIR="$2"; shift 2 ;;
        --quick) QUICK=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) echo "錯誤：未知參數 $1" >&2; show_help >&2; exit 2 ;;
    esac
done

if [[ -z "$TARGET_HOST" ]] || ! is_private_ipv4 "$TARGET_HOST"; then
    echo "錯誤：必須使用 --target 指定你自己的私有 IPv4。" >&2
    exit 2
fi

for value in "$TARGET_PORT" "$PHASE_SECONDS" "$SHORT_ATTACK_SECONDS" "$COOLDOWN_SECONDS"; do
    if ! is_uint "$value"; then
        echo "錯誤：port 與時間參數必須是非負整數。" >&2
        exit 2
    fi
done
if ((TARGET_PORT < 1 || TARGET_PORT > 65535)); then
    echo "錯誤：port 必須介於 1 與 65535。" >&2; exit 2
fi
if ((PHASE_SECONDS < 10 || PHASE_SECONDS > 300)); then
    echo "錯誤：phase-seconds 必須介於 10 與 300。" >&2; exit 2
fi
if ((SHORT_ATTACK_SECONDS < 5 || SHORT_ATTACK_SECONDS > 60)); then
    echo "錯誤：short-attack-seconds 必須介於 5 與 60。" >&2; exit 2
fi
if ((COOLDOWN_SECONDS < 3 || COOLDOWN_SECONDS > 120)); then
    echo "錯誤：cooldown 必須介於 3 與 120。" >&2; exit 2
fi

validate_rate_list --normal-rates "$NORMAL_CONNECTION_SPEC" 200
validate_rate_list --normal-vus "$NORMAL_VUS_SPEC" 200
validate_rate_list --background-syn-rates "$BACKGROUND_SYN_SPEC" 10
validate_rate_list --diagnostic-syn-rates "$DIAGNOSTIC_SYN_SPEC" 30
validate_rate_list --attack-syn-rates "$ATTACK_SYN_SPEC" 300
if [[ -n "$DIAGNOSTIC_MIXED_SPEC" ]]; then
    validate_mixed_list "$DIAGNOSTIC_MIXED_SPEC"
fi
validate_mixed_list "$MIXED_SPEC"

if [[ $QUICK -eq 1 ]]; then
    PHASE_SECONDS=10
    SHORT_ATTACK_SECONDS=5
    COOLDOWN_SECONDS=3
fi

if [[ ! -f "$K6_SCRIPT" || ! -f "$NORMAL_CONNECTION_SCRIPT" ]]; then
    echo "錯誤：找不到 traffic_test 的輔助程式。" >&2
    exit 1
fi

if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$SCRIPT_DIR/results/comprehensive_$(date '+%Y%m%d_%H%M%S')"
fi
mkdir -p -- "$OUTPUT_DIR"

RUN_ID="$(basename "$OUTPUT_DIR")"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}/"
LABEL_FILE="$OUTPUT_DIR/scenario_labels.csv"

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

csv_row run_id scenario label include_in_training start_time end_time \
    start_epoch end_epoch actual_duration_seconds target command_status notes > "$LABEL_FILE"

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    if [[ -n "$ACTIVE_PID" ]]; then
        kill "$ACTIVE_PID" 2>/dev/null || true
        wait "$ACTIVE_PID" 2>/dev/null || true
    fi
    if [[ -n "$CAFFEINATE_PID" ]]; then
        kill "$CAFFEINATE_PID" 2>/dev/null || true
        wait "$CAFFEINATE_PID" 2>/dev/null || true
    fi
    if [[ -n "$SUDO_KEEPALIVE_PID" ]]; then
        kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
        wait "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    fi
    if [[ $exit_code -ne 0 ]]; then
        echo "實驗中止，已完成標籤仍保存在：$LABEL_FILE" >&2
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP

run_phase() {
    local scenario="$1" label="$2" include="$3" notes="$4"
    shift 4
    local start_time end_time start_epoch end_epoch elapsed status log_file
    local expected_duration="" duration_tolerance maximum_duration argument
    # 這支腳本的每個 phase command 都將秒數放在最後一個參數。
    # 用實際時間檢測 Mac 睡眠、網路卡住或工具異常停頓。
    for argument in "$@"; do
        expected_duration="$argument"
    done
    log_file="$OUTPUT_DIR/${scenario}.log"
    start_time="$(date '+%Y-%m-%d %H:%M:%S')"
    start_epoch="$(date '+%s')"
    echo "[${start_time}] 開始：${scenario}（label=${label}, training=${include}）"
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

    if is_uint "$expected_duration"; then
        duration_tolerance=$((expected_duration / 2))
        if ((duration_tolerance < 15)); then
            duration_tolerance=15
        fi
        maximum_duration=$((expected_duration + duration_tolerance))
        if [[ $status -eq 0 && $elapsed -gt $maximum_duration ]]; then
            status=124
            include=0
            EXCLUDED_PHASES=$((EXCLUDED_PHASES + 1))
            notes="${notes}；實際 ${elapsed}s 超過預期 ${expected_duration}s，可能發生電腦睡眠或工具停頓，已排除"
            echo "錯誤：${scenario} 預期約 ${expected_duration}s，實際卻執行 ${elapsed}s。" >&2
            echo "為避免產生錯誤標籤，這段已標記為不納入訓練。" >&2
        fi
    fi
    csv_row "$RUN_ID" "$scenario" "$label" "$include" "$start_time" "$end_time" \
        "$start_epoch" "$end_epoch" "$elapsed" "$TARGET_HOST:$TARGET_PORT" "$status" "$notes" \
        >> "$LABEL_FILE"
    if [[ $status -ne 0 ]]; then
        if [[ $status -eq 124 ]]; then
            echo "警告：${scenario} 已排除，腳本會繼續執行後續情境。" >&2
            return 0
        fi
        echo "錯誤：${scenario} 失敗（status=${status}），請查看 ${log_file}" >&2
        return "$status"
    fi
}

run_cooldown() {
    run_phase "cooldown_$1" -1 0 "情境切換，不納入訓練" sleep "$COOLDOWN_SECONDS"
}

run_normal_connections() {
    python3 "$NORMAL_CONNECTION_SCRIPT" --host "$TARGET_HOST" --port "$TARGET_PORT" \
        --rate "$1" --duration "$2"
}

run_k6() {
    k6 run --no-usage-report --quiet --vus "$1" --duration "${2}s" \
        -e "TARGET_URL=$TARGET_URL" "$K6_SCRIPT"
}

run_syn() {
    local rate="$1" duration="$2"
    sudo -n nping --tcp --flags SYN --dest-port "$TARGET_PORT" --rate "$rate" \
        --count "$((rate * duration))" --no-capture --quiet "$TARGET_HOST"
}

run_mixed() {
    local vus="$1" rate="$2" duration="$3"
    local k6_status nping_status
    k6 run --no-usage-report --quiet --vus "$vus" --duration "${duration}s" \
        -e "TARGET_URL=$TARGET_URL" "$K6_SCRIPT" > "$OUTPUT_DIR/mixed_${vus}_${rate}_k6.log" 2>&1 &
    ACTIVE_PID=$!
    set +e
    sudo -n nping --tcp --flags SYN --dest-port "$TARGET_PORT" --rate "$rate" \
        --count "$((rate * duration))" --no-capture --quiet "$TARGET_HOST"
    nping_status=$?
    wait "$ACTIVE_PID"
    k6_status=$?
    set -e
    ACTIVE_PID=""
    if [[ $nping_status -ne 0 ]]; then return "$nping_status"; fi
    return "$k6_status"
}

if [[ $DRY_RUN -eq 0 ]]; then
    for command_name in curl k6 nping sudo python3; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "錯誤：找不到 '$command_name'。" >&2; exit 1
        fi
    done
    if ! curl --fail --silent --show-error --max-time 5 "$TARGET_URL" >/dev/null; then
        echo "錯誤：無法存取 $TARGET_URL" >&2; exit 1
    fi
fi

cat <<EOF

進階實驗目標   : $TARGET_URL
主要情境秒數 : ${PHASE_SECONDS}s
短攻擊秒數     : ${SHORT_ATTACK_SECONDS}s
結果資料夾     : $OUTPUT_DIR
正常新連線/秒  : $NORMAL_CONNECTION_SPEC
正常 VUs          : $NORMAL_VUS_SPEC
背景純 SYN/秒     : $BACKGROUND_SYN_SPEC
診斷純 SYN/秒     : $DIAGNOSTIC_SYN_SPEC
攻擊純 SYN/秒     : $ATTACK_SYN_SPEC
診斷混合情境      : ${DIAGNOSTIC_MIXED_SPEC:-無}
混合情境          : $MIXED_SPEC

注意：診斷速率的純 SYN 不自動納入訓練，因為「封包行為像攻擊」不等於
「已經構成會影響服務的 flood」。
執行前會要求一次 sudo 密碼，後續由腳本維持認證時效，
不會在 Nping 情境中途再停下等待密碼。
EOF

if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 ]]; then
    read -r -p "確定這是你自己的私有測試主機嗎？ [y/N] " reply
    case "$reply" in y|Y|yes|YES) ;; *) echo "已取消。"; exit 0 ;; esac
fi

if [[ $DRY_RUN -eq 0 ]]; then
    # 開始時只輸入一次密碼。macOS 的 sudo timestamp 通常幾分鐘後就過期，
    # 而前半段正常流量測試會超過這個時間。背景程序每 60 秒只更新
    # sudo 時效，不儲存密碼；主腳本結束時 cleanup 會將它停止。
    sudo -v
    (
        while kill -0 "$$" 2>/dev/null; do
            sudo -n -v >/dev/null 2>&1 || exit 1
            sleep 60
        done
    ) &
    SUDO_KEEPALIVE_PID=$!

    # Mac 在長時間實驗途中睡眠會讓當下情境的時間軸壞掉。
    # caffeinate 會等待本腳本 PID 結束，期間防止閒置睡眠。
    if command -v caffeinate >/dev/null 2>&1; then
        caffeinate -di -w $$ >/dev/null 2>&1 &
        CAFFEINATE_PID=$!
    fi
fi

{
    echo "run_id=$RUN_ID"
    echo "target=$TARGET_URL"
    echo "generator_host=$(hostname)"
    echo "generator_time=$(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "phase_seconds=$PHASE_SECONDS"
    echo "short_attack_seconds=$SHORT_ATTACK_SECONDS"
    echo "cooldown_seconds=$COOLDOWN_SECONDS"
    echo "normal_connection_rates=$NORMAL_CONNECTION_SPEC"
    echo "normal_vus=$NORMAL_VUS_SPEC"
    echo "background_syn_rates=$BACKGROUND_SYN_SPEC"
    echo "diagnostic_syn_rates=$DIAGNOSTIC_SYN_SPEC"
    echo "attack_syn_rates=$ATTACK_SYN_SPEC"
    echo "diagnostic_mixed_profiles=$DIAGNOSTIC_MIXED_SPEC"
    echo "mixed_profiles=$MIXED_SPEC"
} > "$OUTPUT_DIR/metadata.txt"

phase_number=0
next_cooldown() {
    phase_number=$((phase_number + 1))
    run_cooldown "$(printf '%02d' "$phase_number")"
}

run_phase warmup -1 0 "收集器預熱" sleep 10
run_phase idle 0 1 "無主動測試流量" sleep "$PHASE_SECONDS"
next_cooldown

old_ifs="$IFS"; IFS=',' read -r -a normal_rates <<< "$NORMAL_CONNECTION_SPEC"; IFS="$old_ifs"
for rate in "${normal_rates[@]}"; do
    run_phase "normal_completed_${rate}cps" 0 1 \
        "${rate} 個/秒真正完成握手的新 HTTP 連線" \
        run_normal_connections "$rate" "$PHASE_SECONDS"
    next_cooldown
done

old_ifs="$IFS"; IFS=',' read -r -a normal_vus <<< "$NORMAL_VUS_SPEC"; IFS="$old_ifs"
for vus in "${normal_vus[@]}"; do
    run_phase "normal_keepalive_${vus}vus" 0 1 \
        "${vus} VUs 正常 HTTP keep-alive" run_k6 "$vus" "$PHASE_SECONDS"
    next_cooldown
done

old_ifs="$IFS"; IFS=',' read -r -a background_rates <<< "$BACKGROUND_SYN_SPEC"; IFS="$old_ifs"
for rate in "${background_rates[@]}"; do
    run_phase "benign_background_syn_${rate}pps" 0 1 \
        "低量未完成握手的背景純 SYN，用來檢查是否誤報為 flood" \
        run_syn "$rate" "$PHASE_SECONDS"
    next_cooldown
done

old_ifs="$IFS"; IFS=',' read -r -a diagnostic_rates <<< "$DIAGNOSTIC_SYN_SPEC"; IFS="$old_ifs"
for rate in "${diagnostic_rates[@]}"; do
    run_phase "diagnostic_syn_${rate}pps" -1 0 \
        "低速純 SYN 診斷區；只觀察模型機率，不直接當成訓練標籤" \
        run_syn "$rate" "$PHASE_SECONDS"
    next_cooldown
done

# 短攻擊要在長攻擊之前執行，測試告警規則的反應時間。
run_phase syn_short_70pps 1 1 \
    "短時間 70 packets/s 純 SYN，檢查持續性規則延遲" \
    run_syn 70 "$SHORT_ATTACK_SECONDS"
next_cooldown

old_ifs="$IFS"; IFS=',' read -r -a attack_rates <<< "$ATTACK_SYN_SPEC"; IFS="$old_ifs"
for rate in "${attack_rates[@]}"; do
    run_phase "syn_attack_${rate}pps" 1 1 \
        "固定上限 ${rate} packets/s 的純 SYN 攻擊測試" \
        run_syn "$rate" "$PHASE_SECONDS"
    next_cooldown
done

if [[ -n "$DIAGNOSTIC_MIXED_SPEC" ]]; then
    old_ifs="$IFS"; IFS=',' read -r -a diagnostic_mixed_profiles <<< "$DIAGNOSTIC_MIXED_SPEC"; IFS="$old_ifs"
    for profile in "${diagnostic_mixed_profiles[@]}"; do
        old_ifs="$IFS"; IFS=: read -r vus rate <<< "$profile"; IFS="$old_ifs"
        run_phase "diagnostic_mixed_${vus}vus_syn_${rate}pps" -1 0 \
            "${vus} VUs 正常 HTTP + ${rate} packets/s 純 SYN；邊界診斷資料，不直接當成訓練標籤" \
            run_mixed "$vus" "$rate" "$PHASE_SECONDS"
        next_cooldown
    done
fi

old_ifs="$IFS"; IFS=',' read -r -a mixed_profiles <<< "$MIXED_SPEC"; IFS="$old_ifs"
for profile in "${mixed_profiles[@]}"; do
    old_ifs="$IFS"; IFS=: read -r vus rate <<< "$profile"; IFS="$old_ifs"
    run_phase "mixed_${vus}vus_syn_${rate}pps" 1 1 \
        "${vus} VUs 正常 HTTP + ${rate} packets/s 純 SYN" \
        run_mixed "$vus" "$rate" "$PHASE_SECONDS"
    next_cooldown
done

echo
echo "進階實驗全部完成。"
echo "標籤：$LABEL_FILE"
echo "日誌：$OUTPUT_DIR"
echo "因時間異常自動排除的情境數：$EXCLUDED_PHASES"
