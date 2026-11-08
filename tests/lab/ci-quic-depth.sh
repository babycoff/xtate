#!/usr/bin/env bash
# Focused QUIC/HTTP3 semantic matrix: status, body/header/no-match and headers.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-quic-depth-$$"
TARGET="xtate-ci-quic-depth-target-$$"
PORT=4435
LOG="${XTATE_CI_LOG:-$ROOT/tests/lab/ci-quic-depth.log}"

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
if ! docker run --rm -v "$BIN:/xtate:ro" "$IMAGE" /xtate --help-scan quic-state >/dev/null 2>&1; then
    echo "SKIP: quic-state not built"
    exit 0
fi

docker network create "$NET" >/dev/null
TARGET_IP=""

start_target() {
    local status="$1" empty="$2" extra="$3" body="$4"
    docker rm -f "$TARGET" >/dev/null 2>&1 || true
    MSYS_NO_PATHCONV=1 docker run -d --name "$TARGET" --network "$NET" \
        -e H3_STATUS="$status" -e H3_EMPTY_DATA="$empty" \
        -e H3_EXTRA_HEADER="$extra" -e H3_BODY="$body" \
        -v "$ROOT:/src:ro" "$TARGET_IMAGE" bash -lc "
          openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem \
            -out /tmp/cert.pem -subj '/CN=quic.test' -days 1 >/dev/null 2>&1 &&
          exec python3 -u /src/tests/lab/http3_server.py /tmp/cert.pem /tmp/key.pem $PORT" >/dev/null
    TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")"
    sleep 3
    docker ps --format '{{.Names}}' | grep -qx "$TARGET" || { docker logs "$TARGET" >&2; exit 1; }
}

run_case() {
    local name="$1"; local probe_args="$2"; local pattern="$3"
    local parg=""
    if [[ -n "$probe_args" ]]; then parg="-probe-arg '$probe_args'"; fi
    local cmd="/xtate -ip $TARGET_IP -p U:$PORT -scan quic-state -probe http3-state \
      $parg --no-resume-file --wait 8 --no-status \
      -show success -show info -show failed"
    timeout 180 docker run --rm --network "$NET" -v "$BIN:/xtate:ro" \
        "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1 || { cat "$LOG" >&2; exit 1; }
    grep -q "$pattern" "$LOG" || { echo "FAIL: $name missing $pattern" >&2; cat "$LOG" >&2; exit 1; }
    echo "PASS: $name"
}

start_target 200 0 "" "hello from xtate http3 lab"
run_case default "" 'http3_status: 200'
run_case body-match '--keyword=hello --match-scope=body' 'http3_match: 1'
run_case header-match '--keyword=xtate-http3-lab --match-scope=headers' 'http3_match_scope: "headers"'
run_case no-match '--keyword=absent --match-scope=body' 'http3_match: 0'

start_target 404 0 "" "hello from xtate http3 lab"
run_case status404 "" 'http3_status: 404'

start_target 200 1 "" ""
run_case empty-body "" 'http3_body_len: 0'

start_target 200 0 "x-extra:value" "hello from xtate http3 lab"
run_case extra-header "" 'x-extra'

echo "PASS: QUIC/HTTP3 depth matrix"
