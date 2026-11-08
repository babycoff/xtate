#!/usr/bin/env bash
# Local deterministic lab for Redis/Memcached/NTP/MQTT/SOCKS5/Telnet probes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-probes-$$"
PREFIX="xtate-ci-probe-$$"
LOG="${XTATE_CI_LOG:-$ROOT/tests/lab/ci-probes.log}"
TARGETS=(redis memcached ntp mqtt socks5 telnet)

cleanup() {
    local rc=$?
    for n in "${TARGETS[@]}"; do docker rm -f "$PREFIX-$n" >/dev/null 2>&1 || true; done
    docker network rm "$NET" >/dev/null 2>&1 || true
    if [[ $rc -eq 0 ]]; then rm -f "$LOG"; else echo "CI log preserved: $LOG" >&2; fi
}
trap cleanup EXIT
docker network create "$NET" >/dev/null

start() {
    local name="$1"
    MSYS_NO_PATHCONV=1 docker run -d --name "$PREFIX-$name" --network "$NET" \
        -v "$ROOT:/src:ro" "$TARGET_IMAGE" \
        python3 -u "/src/tests/lab/${name}_server.py" >/dev/null
    sleep 0.5
    docker ps --format '{{.Names}}' | grep -qx "$PREFIX-$name" || { docker logs "$PREFIX-$name" >&2; exit 1; }
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PREFIX-$name"
}

REDIS_IP="$(start redis)"
MEM_IP="$(start memcached)"
NTP_IP="$(start ntp)"
MQTT_IP="$(start mqtt)"
SOCKS_IP="$(start socks5)"
TELNET_IP="$(start telnet)"

run() {
    local name="$1" ip="$2" port="$3" scan="$4" probe="$5" extra="$6" pattern="$7"
    local cmd="
      sed 's/\\r$//;s/sudo //g' /src/firewall/add_rules.sh >/tmp/fw
      bash /tmp/fw >/dev/null
      IP=\$(hostname -I | cut -d' ' -f1)
      /xtate -ip $ip -p $port -scan $scan -probe $probe \
        $extra --source-ip \"\$IP\" -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 4 --no-status -show info -show failed"
    timeout 180 docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
        --network "$NET" -v "$BIN:/xtate:ro" -v "$ROOT:/src:ro" \
        "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1 || { cat "$LOG" >&2; exit 1; }
    grep -q "$pattern" "$LOG" || { echo "FAIL: $name missing $pattern" >&2; cat "$LOG" >&2; exit 1; }
    echo "PASS: $name"
}

run redis "$REDIS_IP" 6380 zbanner redis "" 'redis_version: "7.2.0"'
run memcached "$MEM_IP" 11211 zbanner memcached "" 'memcached_version: "1.6.21"'
run mqtt "$MQTT_IP" 1883 zbanner mqtt "" 'mqtt_return_code: 0'
run socks5 "$SOCKS_IP" 1080 tcp-state socks5 "" 'socks5_method: 0'
run telnet "$TELNET_IP" 2323 tcp-state telnet "" 'telnet_options: "IAC DO 1; IAC WILL 3"'
run ntp "$NTP_IP" U:12345 udp ntp "" 'ntp_stratum: 2'
echo "PASS: protocol probe lab"
