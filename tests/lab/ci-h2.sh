#!/usr/bin/env bash
# Focused local CI test for TLS + HTTP/2.  No public network.
#
# Requires Docker, a Linux xtate binary, and an image with python3/openssl and
# the Xtate runtime libraries (default: xtate-builder:24.04, override with
# XTATE_LAB_IMAGE; target image override: XTATE_LAB_TARGET_IMAGE).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-h2-$$"
TARGET="xtate-ci-h2-target-$$"
PORT=8445
LOG="${TMPDIR:-/tmp}/xtate-ci-h2.$$.log"

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

docker network create "$NET" >/dev/null
MSYS_NO_PATHCONV=1 docker run -d --name "$TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$TARGET_IMAGE" bash -lc "
      openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem \
        -out /tmp/cert.pem -subj '/CN=example.test' -days 1 >/dev/null 2>&1 &&
      exec python3 -u /src/tests/lab/h2_tls_server.py" >/dev/null
TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")"

for _ in $(seq 1 60); do
    if docker exec "$TARGET" bash -c "timeout 1 bash -c '</dev/tcp/127.0.0.1/$PORT'" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

cmd='
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq iptables >/dev/null 2>&1
  sed "s/\\r$//;s/sudo //g" /src/firewall/add_rules.sh >/tmp/fw
  bash /tmp/fw >/dev/null
  IP=$(hostname -I | awk "{print \\$1}")
  /xtate -ip '"$TARGET_IP"' -p '"$PORT"' -scan tcp-state -probe tls-state \
    -probe-arg "-subprobe h2 -sni example.test -alpn h2" \
    --source-ip "$IP" -source-port 40000-40255 -seed 123 \
    --no-resume-file --wait 5 --no-status -show info -show failed
'

# The -probe-arg above intentionally keeps the nested h2 args as one token.
set +e
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --network "$NET" \
    -v "$BIN:/xtate:ro" -v "$ROOT:/src:ro" "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
    cat "$LOG" >&2
    exit 1
fi
grep -q 'h2_status: 200' "$LOG" || { cat "$LOG" >&2; exit 1; }
grep -q 'h2_data' "$LOG" || { cat "$LOG" >&2; exit 1; }
grep -q '"http/2"' "$LOG" || { cat "$LOG" >&2; exit 1; }
echo "PASS: TLS + H2 local CI"
