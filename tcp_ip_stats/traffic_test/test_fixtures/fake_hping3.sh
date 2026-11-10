#!/usr/bin/env bash

set -u

count=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --count)
            count="${2:-}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ ! "$count" =~ ^[0-9]+$ ]]; then
    echo "fake hping3: missing --count" >&2
    exit 2
fi

case "${FAKE_HPING_MODE:-}" in
    complete_no_reply)
        printf '%s packets transmitted, 0 packets received, 100%% packet loss\n' "$count"
        exit 1
        ;;
    incomplete)
        sent=$((count > 0 ? count - 1 : 0))
        printf '%s packets transmitted, 0 packets received, 100%% packet loss\n' "$sent"
        exit 1
        ;;
    missing_summary)
        echo "fake hping3: summary unavailable"
        exit 0
        ;;
    hard_error)
        echo "fake hping3: simulated execution error" >&2
        exit 2
        ;;
    success)
        printf '%s packets transmitted, 1 packets received, 0%% packet loss\n' "$count"
        exit 0
        ;;
    *)
        echo "fake hping3: unknown FAKE_HPING_MODE" >&2
        exit 2
        ;;
esac
