#!/usr/bin/env bash
# Local deterministic lab for Batch C first probes: IPP, AMQP, PPTP.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-batchc-$$"
TARGET="xtate-ci-batchc-target-$$"
LOG="${XTATE_CI_LOG:-$ROOT/tests/lab/ci-batch-c.log}"
cleanup() {
    local rc=$?
    docker rm -f "$TARGET" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    if [[ $rc -eq 0 ]]; then rm -f "$LOG"; else echo "CI log preserved: $LOG" >&2; fi
}
trap cleanup EXIT
docker network create "$NET" >/dev/null
MSYS_NO_PATHCONV=1 docker run -d --name "$TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$TARGET_IMAGE" python3 -u /src/tests/lab/batchc_server.py >/dev/null
IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")"
sleep 1
docker ps --format '{{.Names}}' | grep -qx "$TARGET" || { docker logs "$TARGET" >&2; exit 1; }

run() {
    local name="$1" port="$2" scan="$3" probe="$4" pattern="$5"
    local cmd="
      sed 's/\\r$//;s/sudo //g' /src/firewall/add_rules.sh >/tmp/fw
      bash /tmp/fw >/dev/null
      SRC=\$(hostname -I | cut -d' ' -f1)
      /xtate -ip $IP -p $port -scan $scan -probe $probe \
        --source-ip \"\$SRC\" -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 4 --no-status -show info -show failed"
    timeout 180 docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
        --network "$NET" -v "$BIN:/xtate:ro" -v "$ROOT:/src:ro" \
        "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1 || { cat "$LOG" >&2; exit 1; }
    grep -q "$pattern" "$LOG" || { echo "FAIL: $name missing $pattern" >&2; cat "$LOG" >&2; exit 1; }
    echo "PASS: $name"
}

run ipp 631 zbanner ipp 'ipp_http_status: 200'
run ipp-state 631 tcp-state ipp-state 'ipp_http_status: 200'
run amqp 5672 zbanner amqp 'amqp_version_major: 0'
run amqp-state 5672 tcp-state amqp-state 'amqp_version_major: 0'
run pptp 1723 zbanner pptp 'pptp_result_code: 1'
run pptp-state 1723 tcp-state pptp-state 'pptp_result_code: 1'
echo "PASS: Batch C protocol lab"
