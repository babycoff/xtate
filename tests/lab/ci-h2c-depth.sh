#!/usr/bin/env bash
# Cleartext H2C depth matrix: settings/ping client controls and frame parsing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-h2c-depth-$$"
TARGET="xtate-ci-h2c-depth-target-$$"
PORT=8446
LOG="${XTATE_CI_LOG:-$ROOT/tests/lab/ci-h2c-depth.log}"
cleanup() {
    local rc=$?
    docker rm -f "$TARGET" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    if [[ $rc -eq 0 ]]; then rm -f "$LOG"; else echo "CI log preserved: $LOG" >&2; fi
}
trap cleanup EXIT
docker network create "$NET" >/dev/null
MSYS_NO_PATHCONV=1 docker run -d --name "$TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$TARGET_IMAGE" \
    python3 -u /src/tests/lab/h2c_server.py >/dev/null
TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")"
sleep 1
docker ps --format '{{.Names}}' | grep -qx "$TARGET" || { docker logs "$TARGET" >&2; exit 1; }

run_case() {
    local name="$1"; local extra="$2"
    local parg=""
    if [[ -n "$extra" ]]; then parg="-probe-arg '$extra'"; fi
    local cmd="
      sed 's/\\r$//;s/sudo //g' /src/firewall/add_rules.sh >/tmp/fw
      bash /tmp/fw >/dev/null
      IP=\$(hostname -I | cut -d' ' -f1)
      /xtate -ip $TARGET_IP -p $PORT -scan zbanner -probe h2c \
        $parg --source-ip \"\$IP\" -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 3 --no-status -show info -show failed"
    timeout 180 docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
        --network "$NET" -v "$BIN:/xtate:ro" -v "$ROOT:/src:ro" \
        "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1 || { cat "$LOG" >&2; exit 1; }
    grep -q 'http2_frame_count: 3' "$LOG" || { cat "$LOG" >&2; exit 1; }
    echo "PASS: $name"
}

run_case default ""
run_case all-frames "--all-frames"
run_case settings "--settings-hex=000000000000"
run_case ping "--ping-hex=5854415445"
run_case no-ping "--no-ping"
run_case no-settings "--no-settings"
echo "PASS: H2C depth matrix"
