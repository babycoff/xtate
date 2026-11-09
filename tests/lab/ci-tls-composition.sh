#!/usr/bin/env bash
# TLS/STARTTLS composition matrix: implicit TLS and STARTTLS state probes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-tls-matrix-$$"
TARGET="xtate-ci-tls-matrix-target-$$"
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
      python3 -u /src/tests/lab/tls_matrix_server.py /tmp/cert.pem /tmp/key.pem
    ' >/dev/null
IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")"
sleep 1
docker ps --format '{{.Names}}' | grep -qx "$TARGET" || { docker logs "$TARGET" >&2; exit 1; }

run() {
    local name="$1" port="$2" subprobe="$3" extra="$4" pattern="$5"
    local cmd="
      apt-get update -qq >/dev/null 2>&1
      apt-get install -y -qq iptables >/dev/null 2>&1
      sed 's/\\r$//;s/sudo //g' /src/firewall/add_rules.sh >/tmp/fw
      bash /tmp/fw >/dev/null
      SRC=\$(hostname -I | cut -d' ' -f1)
      /xtate -ip $IP -p $port -scan tcp-state -probe tls-state \
        -probe-arg \"-subprobe $subprobe $extra -sni example.test -alpn h2 \
                    --dump-cert-details --dump-version\" \
        --source-ip \"\$SRC\" -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 6 --no-status -show info -show failed"
    timeout 180 docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
        --network "$NET" -v "$BIN:/xtate:ro" -v "$ROOT:/src:ro" \
        "$IMAGE" bash -lc "$cmd" >"$LOG" 2>&1 || { cat "$LOG" >&2; exit 1; }
    grep -q "$pattern" "$LOG" || { echo "FAIL: $name missing $pattern" >&2; cat "$LOG" >&2; exit 1; }
    grep -q 'tls_alpn: "h2"' "$LOG" || { echo "FAIL: $name ALPN" >&2; cat "$LOG" >&2; exit 1; }
    grep -q 'cert_subject: "CN=example.test"' "$LOG" || { echo "FAIL: $name cert" >&2; cat "$LOG" >&2; exit 1; }
    grep -q 'tls_version: "TLSv1.3"' "$LOG" || { echo "FAIL: $name TLS version" >&2; cat "$LOG" >&2; exit 1; }
    echo "PASS: $name"
}

# Implicit TLS targets.
run implicit-smtp 2465 smtp-state "" 'smtp_starttls: true'
run implicit-mysql 3307 mysql-state "" 'mysql_version: "8.0.34"'
run implicit-postgres 5432 postgres-state "-subprobe-arg --after-tls" 'postgres_auth_type: 5'
run implicit-mongodb 27018 mongodb-state "" 'mongodb_wire_version: 17'

# STARTTLS targets.
run starttls-smtp 2525 smtp-state "--starttls smtp -subprobe-arg --after-tls" 'smtp_starttls: true'
run starttls-imap 2143 imap-state "--starttls imap -subprobe-arg --after-tls" 'imap_starttls: true'
run starttls-pop3 2110 pop3-state "--starttls pop3 -subprobe-arg --after-tls" 'pop3_stls: true'
run starttls-ftp 2121 ftp-state "--starttls ftp -subprobe-arg --after-tls" 'ftp_auth_tls: true'
run starttls-managesieve 4191 managesieve-state "--starttls managesieve" 'tls info'

echo "PASS: TLS/STARTTLS composition matrix"
