#!/usr/bin/env bash

# 在 Mac 上執行的低速 SYN 邊界實驗。
#
# 目標是找出「正常 HTTP 與低速純 SYN 同時存在」時，現有模型的
# 判斷邊界。這些邊界情境先標成 label=-1、include_in_training=0，
# 避免在尚未確定是否已構成 Flood 前產生錯誤訓練標籤。

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPREHENSIVE_SCRIPT="$SCRIPT_DIR/run_comprehensive_experiment.sh"

if [[ ! -f "$COMPREHENSIVE_SCRIPT" ]]; then
    echo "錯誤：找不到 $COMPREHENSIVE_SCRIPT" >&2
    exit 1
fi

if ! grep -q -- '--diagnostic-mixed-profiles' "$COMPREHENSIVE_SCRIPT"; then
    echo "錯誤：run_comprehensive_experiment.sh 是舊版。" >&2
    echo "請同時更新這支腳本與 run_comprehensive_experiment.sh。" >&2
    exit 1
fi

exec "$COMPREHENSIVE_SCRIPT" \
    --phase-seconds 45 \
    --short-attack-seconds 10 \
    --cooldown 12 \
    --normal-rates 10,30 \
    --normal-vus 10,30 \
    --background-syn-rates 1,2 \
    --diagnostic-syn-rates 5,10,20 \
    --attack-syn-rates 70 \
    --diagnostic-mixed-profiles 10:5,10:10,10:15,10:20,10:25,10:30,10:35,10:40 \
    --mixed-profiles 10:70 \
    "$@"
