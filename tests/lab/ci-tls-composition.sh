#!/usr/bin/env bash
# TLS/STARTTLS composition: Batch B state probes inside tls-state.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-tls-compose-$$"
TARGET="xtate-ci-tls-compose-target-$$"
LOG="${XTATE_CI_LOG:-$ROOT/tests/lab/ci-tls-composition.log}"
cleanup() {
    local rc=$?
    docker rm -f "$TARGET" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    if [[ $rc -eq 0 ]]; then rm -f "$LOG"; else echo "CI log preserved: $LOG" >&2; fi
}
trap cleanup EXIT
docker network create "$NET" >/dev/null
MSYS_NO_PATHCONV=1 docker run -d --name "$TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$TARGET_IMAGE" bash -lc '
      openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem \
        -out /tmp/cert.pem -subj "/CN=example.test" -days 1 >/dev/null 2>&1
      python3 -u /src/tests/lab/starttls_server.py /tmp/cert.pem /tmp/key.pem &
      python3 -u /src/tests/lab/tls_smtp_server.py /tmp/cert.pem /tmp/key.pem
    ' >/dev/null
IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")"
sleep 1
docker ps --format '{{.Names}}' | grep -qx "$TARGET" || { docker logs "$TARGET" >&2; exit 1; }

run() {
    local name="$1" port="$2" extra="$3" pattern="$4"
    local cmd="
      IP=\$(hostname -I | cut -d' ' -f1)
      /xtate -ip $IP -p $port -scan tcp-state -probe tls-state \
        -probe-arg \"-subprobe smtp-state $extra -sni example.test\" \
        --source-ip \"\$IP\" -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 5 --no-status -show info -show failed"
    timeout 180 docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
        --network "$NET" -v "$BIN:/xtate:ro" -v "$ROOT:/src:ro" \
        "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1 || { cat "$LOG" >&2; exit 1; }
    grep -q "$pattern" "$LOG" || { echo "FAIL: $name missing $pattern" >&2; cat "$LOG" >&2; exit 1; }
    echo "PASS: $name"
}

run implicit-tls 2465 "" 'smtp_starttls: true'
run starttls-smtp 2525 "--starttls smtp -subprobe-arg --after-tls" 'smtp_starttls: true'
echo "PASS: TLS/STARTTLS composition"
