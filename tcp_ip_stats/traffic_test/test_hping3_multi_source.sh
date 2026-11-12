#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GENERATOR="$SCRIPT_DIR/hping3_multi_source.sh"
FAKE_HPING="$SCRIPT_DIR/test_fixtures/fake_hping3.sh"

run_case() {
    local mode="$1" expected_status="$2" output status

    set +e
    output="$(
        FAKE_HPING_MODE="$mode" \
        HPING_BIN="$FAKE_HPING" \
        HPING_TARGET="192.0.2.1" \
        HPING_PORT=80 \
        HPING_RATE=2 \
        HPING_DURATION=2 \
        HPING_RAND_SOURCE=1 \
        HPING_ISOLATED_LAB=1 \
        "$GENERATOR" 2>&1
    )"
    status=$?
    set -e

    if [[ $status -ne $expected_status ]]; then
        echo "FAIL: mode=$mode expected_status=$expected_status actual_status=$status" >&2
        echo "$output" >&2
        return 1
    fi
    echo "PASS: mode=$mode status=$status"
}

run_case complete_no_reply 0
run_case success 0
run_case incomplete 1
run_case missing_summary 1
run_case hard_error 2
