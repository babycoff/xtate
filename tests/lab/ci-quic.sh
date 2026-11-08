#!/usr/bin/env bash
# Focused local CI test for QUIC + HTTP/3.  No public network.
#
# Requires Docker, a Linux xtate binary linked with ngtcp2/GnuTLS, and an image
# with python3/aioquic/openssl (default: xtate-builder:24.04; override with
# XTATE_LAB_IMAGE; target image override: XTATE_LAB_TARGET_IMAGE).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-quic-$$"
TARGET="xtate-ci-quic-target-$$"
PORT=4435
LOG="${TMPDIR:-/tmp}/xtate-ci-quic.$$.log"

cleanup() {
    docker rm -f "$TARGET" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -f "$LOG"
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not found" >&2
    exit 0
fi
if [[ ! -f "$BIN" ]]; then
    echo "xtate binary not found: $BIN" >&2
    exit 1
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
if command -v cygpath >/dev/null 2>&1; then
    ROOT="$(cygpath -w "$ROOT")"
    BIN="$(cygpath -w "$BIN")"
fi

# Optional module: skip cleanly on builds without ngtcp2.
if ! docker run --rm -v "$BIN:/xtate:ro" "$IMAGE" /xtate --help-scan quic-state >/dev/null 2>&1; then
    echo "SKIP: quic-state not built"
    exit 0
fi

docker network create "$NET" >/dev/null
MSYS_NO_PATHCONV=1 docker run -d --name "$TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$TARGET_IMAGE" bash -lc "
      openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem \
        -out /tmp/cert.pem -subj '/CN=quic.test' -days 1 >/dev/null 2>&1 &&
      exec python3 -u /src/tests/lab/http3_server.py /tmp/cert.pem /tmp/key.pem $PORT" >/dev/null
TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")"
sleep 3

cmd="/xtate -ip $TARGET_IP -p U:$PORT -scan quic-state -probe http3-state \
  -probe-arg '--keyword=hello --match-scope=body' \
  --no-resume-file --wait 8 --no-status -show info -show failed"
set +e
docker run --rm --network "$NET" -v "$BIN:/xtate:ro" "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
    cat "$LOG" >&2
    exit 1
fi
grep -q 'http3_status: 200' "$LOG" || { cat "$LOG" >&2; exit 1; }
grep -q 'http3_body' "$LOG" || { cat "$LOG" >&2; exit 1; }
grep -q 'http3_match: 1' "$LOG" || { cat "$LOG" >&2; exit 1; }
echo "PASS: QUIC + HTTP/3 local CI"
