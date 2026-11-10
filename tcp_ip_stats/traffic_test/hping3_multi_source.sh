#!/usr/bin/env bash

# Run inside the dedicated hping3 container. The final holdout uses either
# the container's real source or hping3 --rand-source. An explicit source list
# remains available for smaller diagnostic experiments.

set -Eeuo pipefail

: "${HPING_TARGET:?HPING_TARGET is required}"
: "${HPING_PORT:?HPING_PORT is required}"
: "${HPING_RATE:?HPING_RATE is required}"
: "${HPING_DURATION:?HPING_DURATION is required}"

HPING_SOURCE_IPS="${HPING_SOURCE_IPS:-}"
HPING_RAND_SOURCE="${HPING_RAND_SOURCE:-0}"
HPING_ISOLATED_LAB="${HPING_ISOLATED_LAB:-0}"

is_uint() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

for value in "$HPING_PORT" "$HPING_RATE" "$HPING_DURATION"; do
    if ! is_uint "$value"; then
        echo "port, rate and duration must be positive integers" >&2
        exit 2
    fi
done
if ((HPING_PORT < 1 || HPING_PORT > 65535)); then
    echo "HPING_PORT must be in 1..65535" >&2
    exit 2
fi
if ((HPING_RATE < 1 || HPING_RATE > 500)); then
    echo "HPING_RATE must be in 1..500 packets/s" >&2
    exit 2
fi
if ((HPING_DURATION < 1 || HPING_DURATION > 300)); then
    echo "HPING_DURATION must be in 1..300 seconds" >&2
    exit 2
fi

children=()
cleanup() {
    local child
    trap - EXIT INT TERM HUP
    for child in "${children[@]}"; do
        kill "$child" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

interval_for_rate() {
    local rate="$1" interval_us

    # hping3's uN form is a microsecond field. u1000000 is an invalid
    # boundary value for some packaged versions and can stall after packet 1.
    if ((rate == 1)); then
        printf '1'
        return
    fi

    interval_us=$((1000000 / rate))
    if ((interval_us < 1000)); then
        interval_us=1000
    fi
    printf 'u%s' "$interval_us"
}

run_one_source() {
    local source_ip="$1" rate="$2" duration="$3"
    local interval count guard_seconds
    interval="$(interval_for_rate "$rate")"
    count=$((rate * duration))
    guard_seconds=$((duration + 15))

    if [[ -n "$source_ip" ]]; then
        timeout --foreground --signal=TERM --kill-after=5s "${guard_seconds}s" \
            hping3 --syn --numeric --quiet --spoof "$source_ip" \
            --destport "$HPING_PORT" --interval "$interval" \
            --count "$count" "$HPING_TARGET"
    else
        timeout --foreground --signal=TERM --kill-after=5s "${guard_seconds}s" \
            hping3 --syn --numeric --quiet \
            --destport "$HPING_PORT" --interval "$interval" \
            --count "$count" "$HPING_TARGET"
    fi
}

if [[ "$HPING_RAND_SOURCE" == "1" ]]; then
    if [[ "$HPING_ISOLATED_LAB" != "1" ]]; then
        echo "rand-source refused: HPING_ISOLATED_LAB=1 was not supplied" >&2
        exit 2
    fi
    if [[ -n "$HPING_SOURCE_IPS" ]]; then
        echo "HPING_RAND_SOURCE and HPING_SOURCE_IPS cannot be used together" >&2
        exit 2
    fi
    interval="$(interval_for_rate "$HPING_RATE")"
    count=$((HPING_RATE * HPING_DURATION))
    guard_seconds=$((HPING_DURATION + 15))
    echo "hping3 rand-source: target=${HPING_TARGET}:${HPING_PORT}, rate=${HPING_RATE}pps, duration=${HPING_DURATION}s"
    timeout --foreground --signal=TERM --kill-after=5s "${guard_seconds}s" \
        hping3 --syn --numeric --quiet --rand-source \
        --destport "$HPING_PORT" --interval "$interval" \
        --count "$count" "$HPING_TARGET"
    exit 0
fi

if [[ "$HPING_RAND_SOURCE" != "0" ]]; then
    echo "HPING_RAND_SOURCE must be 0 or 1" >&2
    exit 2
fi

if [[ -z "$HPING_SOURCE_IPS" ]]; then
    echo "hping3 single-source: target=${HPING_TARGET}:${HPING_PORT}, rate=${HPING_RATE}pps, duration=${HPING_DURATION}s"
    run_one_source "" "$HPING_RATE" "$HPING_DURATION"
    exit 0
fi

old_ifs="$IFS"
IFS=',' read -r -a source_ips <<< "$HPING_SOURCE_IPS"
IFS="$old_ifs"

# More sources than packets per second would create zero-rate workers.  The
# host-side generator already avoids this, but keep the container defensive.
if ((${#source_ips[@]} > HPING_RATE)); then
    source_ips=("${source_ips[@]:0:HPING_RATE}")
fi

base_rate=$((HPING_RATE / ${#source_ips[@]}))
remainder=$((HPING_RATE % ${#source_ips[@]}))

echo "hping3 multi-source: target=${HPING_TARGET}:${HPING_PORT}, total_rate=${HPING_RATE}pps, sources=${#source_ips[@]}, duration=${HPING_DURATION}s"
for index in "${!source_ips[@]}"; do
    source_rate="$base_rate"
    if ((index < remainder)); then
        source_rate=$((source_rate + 1))
    fi
    run_one_source "${source_ips[$index]}" "$source_rate" "$HPING_DURATION" &
    children+=("$!")
done

status=0
for child in "${children[@]}"; do
    wait "$child" || status=$?
done
children=()
exit "$status"
