#!/usr/bin/env bash
# Focused TLS/H2 semantic matrix: status, empty data, extra header and matcher.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-h2-depth-$$"
TARGET="xtate-ci-h2-depth-target-$$"
PORT=8445
LOG="${XTATE_CI_LOG:-$ROOT/tests/lab/ci-h2-depth.log}"

cleanup() {
    local rc=$?
    docker rm -f "$TARGET" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    if [[ $rc -eq 0 ]]; then rm -f "$LOG"; else echo "CI log preserved: $LOG" >&2; fi
}
trap cleanup EXIT
if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not found" >&2
    exit 0
fi
[[ -f "$BIN" ]] || { echo "xtate binary not found: $BIN" >&2; exit 1; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
if command -v cygpath >/dev/null 2>&1; then
    ROOT="$(cygpath -w "$ROOT")"; BIN="$(cygpath -w "$BIN")"
fi

docker network create "$NET" >/dev/null
TARGET_IP=""

start_target() {
    local status="$1" empty="$2" extra="$3" second="${4:-}"
    docker rm -f "$TARGET" >/dev/null 2>&1 || true
    MSYS_NO_PATHCONV=1 docker run -d --name "$TARGET" --network "$NET" \
        -e H2_STATUS="$status" -e H2_EMPTY_DATA="$empty" \
        -e H2_EXTRA_HEADER="$extra" -e H2_SECOND_HEADER="$second" \
        -v "$ROOT:/src:ro" "$TARGET_IMAGE" bash -lc "
          openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/h2-key.pem \
            -out /tmp/h2-cert.pem -subj '/CN=example.test' -days 1 >/dev/null 2>&1 &&
          exec python3 -u /src/tests/lab/h2_tls_server.py" >/dev/null
    TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")"
    local ready=0
    for _ in $(seq 1 60); do
        if docker exec "$TARGET" bash -c "timeout 1 bash -c '</dev/tcp/127.0.0.1/$PORT'" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 1
    done
    [[ $ready -eq 1 ]] || { docker logs "$TARGET" >&2; exit 1; }
}

run_case() {
    local name="$1"; local probe_args="$2"
    local cmd="
      sed 's/\\r$//;s/sudo //g' /src/firewall/add_rules.sh >/tmp/fw
      bash /tmp/fw >/dev/null
      IP=\$(hostname -I | cut -d' ' -f1)
      /xtate -ip $TARGET_IP -p $PORT -scan tcp-state -probe tls-state \
        -probe-arg '$probe_args' \
        --source-ip \"\$IP\" -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 5 --no-status -show info -show failed"
    timeout 180 docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
        --network "$NET" -v "$BIN:/xtate:ro" -v "$ROOT:/src:ro" \
        "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1 || { cat "$LOG" >&2; exit 1; }
    grep -q "$3" "$LOG" || { echo "FAIL: $name missing $3" >&2; cat "$LOG" >&2; exit 1; }
    echo "PASS: $name"
}

start_target 200 0 ""
run_case default "-subprobe h2 -sni example.test -alpn h2" 'h2_status: "200"'
run_case matcher "-subprobe h2 -sni example.test -alpn h2 -subprobe-arg --keyword=hello" 'h2_match: 1'

start_target 404 0 ""
run_case status404 "-subprobe h2 -sni example.test -alpn h2" 'h2_status: "404"'

start_target 200 1 ""
run_case empty-data "-subprobe h2 -sni example.test -alpn h2" 'h2_data_len: 0'

start_target 200 0 "x-extra:value"
run_case extra-header "-subprobe h2 -sni example.test -alpn h2" 'x-extra: value'

start_target 200 0 "" "x-trailer:tail"
run_case multi-headers "-subprobe h2 -sni example.test -alpn h2" 'x-trailer: tail'

start_target 200 0 ""
run_tls_case() {
    local cmd="
      sed 's/\\r$//;s/sudo //g' /src/firewall/add_rules.sh >/tmp/fw
      bash /tmp/fw >/dev/null
      IP=\$(hostname -I | cut -d' ' -f1)
      /xtate -ip $TARGET_IP -p $PORT -scan tcp-state -probe tls-state \
        -probe-arg '-subprobe close-state --sni example.test --alpn h2 --dump-cert-details --dump-version' \
        --source-ip \"\$IP\" -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 5 --no-status -show info -show failed"
    timeout 180 docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
        --network "$NET" -v "$BIN:/xtate:ro" -v "$ROOT:/src:ro" \
        "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1 || { cat "$LOG" >&2; exit 1; }
    grep -q 'tls_alpn: "h2"' "$LOG" || { cat "$LOG" >&2; exit 1; }
    grep -q 'cert_subject: "CN=example.test"' "$LOG" || { cat "$LOG" >&2; exit 1; }
    grep -q 'tls_version: "TLSv1.3"' "$LOG" || { cat "$LOG" >&2; exit 1; }
    echo "PASS: tls-cert-alpn"
}
run_tls_case

echo "PASS: TLS/H2 depth matrix"
