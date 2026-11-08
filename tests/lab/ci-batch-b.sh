#!/usr/bin/env bash
# Local deterministic lab for Batch B protocol probes (tcp + state variants).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGET_IMAGE="${XTATE_LAB_TARGET_IMAGE:-$IMAGE}"
NET="xtate-ci-batchb-$$"
TARGET="xtate-ci-batchb-target-$$"
LOG="${XTATE_CI_LOG:-$ROOT/tests/lab/ci-batch-b.log}"
cleanup() {
    local rc=$?
    docker rm -f "$TARGET" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    if [[ $rc -eq 0 ]]; then rm -f "$LOG"; else echo "CI log preserved: $LOG" >&2; fi
}
trap cleanup EXIT
docker network create "$NET" >/dev/null
MSYS_NO_PATHCONV=1 docker run -d --name "$TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$TARGET_IMAGE" python3 -u /src/tests/lab/batchb_server.py >/dev/null
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

run mysql 3307 zbanner mysql 'mysql_version: "8.0.34"'
run mysql-state 3307 tcp-state mysql-state 'mysql_version: "8.0.34"'
run postgres 5432 zbanner postgres 'postgres_ssl_supported: false'
run postgres-state 5432 tcp-state postgres-state 'postgres_auth_type: 5'
run mongodb 27018 zbanner mongodb 'mongodb_wire_version: 17'
run smtp 2525 zbanner smtp 'smtp_code: 220'
run smtp-state 2525 tcp-state smtp-state 'smtp_starttls: true'
run imap 1430 zbanner imap 'imap_banner'
run imap-state 1430 tcp-state imap-state 'imap_starttls: true'
run pop3 1100 zbanner pop3 'pop3_banner'
run pop3-state 1100 tcp-state pop3-state 'pop3_stls: true'
run ftp 2121 zbanner ftp 'ftp_code: 220'
run ftp-state 2121 tcp-state ftp-state 'ftp_auth_tls: true'
run managesieve 4190 zbanner managesieve 'sieve_banner'
run managesieve-state 4190 tcp-state managesieve-state 'sieve_starttls: true'
echo "PASS: Batch B protocol lab"
