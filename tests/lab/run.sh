#!/usr/bin/env bash
#
# Local, isolated ZBanner / HLTCP regression lab.
#
# Requirements:
#   - Docker
#   - a Linux xtate binary (default: ./bin/xtate)
#   - the xtate-builder:24.04 image, or set XTATE_LAB_IMAGE to a compatible
#     Ubuntu 24.04 image with build tools (the script installs iptables).
#
# The lab never touches the public Internet: both targets are containers on a
# dedicated Docker network. It uses 100 pps and cleans up all containers and
# the network on exit.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
NET="xtate-lab-$$"
HTTP_TARGET="xtate-lab-http-$$"
TLS_TARGET="xtate-lab-tls-$$"
JARM_TARGET="xtate-lab-jarm-$$"
UDP_ECHO_TARGET="xtate-lab-udp-echo-$$"
SSH_TARGET="xtate-lab-ssh-$$"
HTTP_PORT=8080
CLOSED_PORT=9
TLS_PORT=8443
JARM_PORT=9443
SSH_PORT=2222

cleanup() {
    docker rm -f "$HTTP_TARGET" "$TLS_TARGET" "$JARM_TARGET" "$UDP_ECHO_TARGET" "$SSH_TARGET" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found" >&2
    exit 1
fi
if [ ! -f "$BIN" ]; then
    echo "xtate binary not found: $BIN (set XTATE_BIN)" >&2
    exit 1
fi
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

# Git Bash presents POSIX paths, while Docker Desktop expects Windows paths for
# bind mounts. Convert both roots before they reach `docker -v`.
if command -v cygpath >/dev/null 2>&1; then
    ROOT="$(cygpath -w "$ROOT")"
    BIN="$(cygpath -w "$BIN")"
fi

echo "==> creating isolated network $NET"
docker network create "$NET" >/dev/null

echo "==> starting HTTP target"
docker run -d --name "$HTTP_TARGET" --network "$NET" "$IMAGE" bash -lc \
    "if ! command -v python3 >/dev/null 2>&1; then \
       apt-get update -qq >/dev/null 2>&1 && \
       apt-get install -y -qq python3 >/dev/null 2>&1; \
     fi && \
     python3 -u -m http.server $HTTP_PORT" >/dev/null

echo "==> starting TLS target"
docker run -d --name "$TLS_TARGET" --network "$NET" "$IMAGE" bash -lc \
    "if ! command -v openssl >/dev/null 2>&1; then \
       apt-get update -qq >/dev/null 2>&1 && \
       apt-get install -y -qq openssl >/dev/null 2>&1; \
     fi && \
     openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem \
       -out /tmp/cert.pem -subj '/CN=localhost' -days 1 >/dev/null 2>&1 && \
     openssl s_server -accept $TLS_PORT -cert /tmp/cert.pem -key /tmp/key.pem -tlsextdebug -www" >/dev/null

wait_tcp() {
    local host="$1"
    local port="$2"
    for _ in $(seq 1 180); do
        if docker exec "$host" bash -c "timeout 1 bash -c '</dev/tcp/127.0.0.1/$port'" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "target $host port $port did not become ready" >&2
    return 1
}
echo "==> starting isolated JARM TLS target"
docker run -d --name "$JARM_TARGET" --network "$NET" "$IMAGE" bash -lc \
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem \
       -out /tmp/cert.pem -subj '/CN=localhost' -days 1 >/dev/null 2>&1 && \
     openssl s_server -accept $JARM_PORT -cert /tmp/cert.pem -key /tmp/key.pem -tlsextdebug -www" >/dev/null

echo "==> starting UDP echo target"
MSYS_NO_PATHCONV=1 docker run -d --name "$UDP_ECHO_TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$IMAGE" \
    python3 -u /src/tests/lab/udp_echo.py >/dev/null
sleep 1

echo "==> starting SSH banner target"
MSYS_NO_PATHCONV=1 docker run -d --name "$SSH_TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$IMAGE" \
    python3 -u /src/tests/lab/ssh_banner.py >/dev/null

wait_tcp "$HTTP_TARGET" "$HTTP_PORT"
wait_tcp "$TLS_TARGET" "$TLS_PORT"
wait_tcp "$JARM_TARGET" "$JARM_PORT"
wait_tcp "$SSH_TARGET" "$SSH_PORT"

HTTP_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$HTTP_TARGET")"
TLS_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TLS_TARGET")"
JARM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$JARM_TARGET")"
UDP_ECHO_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$UDP_ECHO_TARGET")"
SSH_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SSH_TARGET")"
echo "HTTP target: $HTTP_IP:$HTTP_PORT (closed test port $CLOSED_PORT)"
echo "TLS  target: $TLS_IP:$TLS_PORT"
echo "JARM target: $JARM_IP:$JARM_PORT"
echo "UDP echo:   $UDP_ECHO_IP:8082"
echo "SSH banner:  $SSH_IP:$SSH_PORT"

docker run --rm \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    --network "$NET" \
    -e HTTP_IP="$HTTP_IP" -e TLS_IP="$TLS_IP" -e JARM_IP="$JARM_IP" -e UDP_ECHO_IP="$UDP_ECHO_IP" -e SSH_IP="$SSH_IP" \
    -e HTTP_PORT="$HTTP_PORT" -e CLOSED_PORT="$CLOSED_PORT" \
    -e TLS_PORT="$TLS_PORT" -e JARM_PORT="$JARM_PORT" -e SSH_PORT="$SSH_PORT" \
    -v "$ROOT:/src:ro" -v "$BIN:/xtate:ro" \
    "$IMAGE" bash -lc '
set -euo pipefail
if ! command -v iptables >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq iptables >/dev/null 2>&1
fi

mkdir -p /work
cp -a /src /work/xtate
cd /work/xtate

# Normalize scripts so a Windows checkout does not inject CRLF into bash.
sed -i "s/\r$//" firewall/add_rules.sh firewall/rm_rules.sh
sed -i "s/sudo //g" firewall/add_rules.sh firewall/rm_rules.sh

if command -v iptables >/dev/null 2>&1; then
    bash firewall/add_rules.sh >/dev/null 2>&1
else
    echo "WARN: iptables not available in lab image; host RST suppression skipped" >&2
fi


run_case() {
    local name="$1"
    shift
    echo "--- $name"
    timeout 25 /xtate "$@" > "/tmp/$name.log" 2>&1 || true
    cat "/tmp/$name.log"
}

run_case zbanner-default \
    -ip "$HTTP_IP" -p "$HTTP_PORT,$CLOSED_PORT" -scan zbanner -probe http \
    -src-port 41000-41255 -rate 100 --wait 2 --no-status -show info -show failed
grep -q "\"open\" because \"syn-ack\"" /tmp/zbanner-default.log
grep -q "\"closed\" because \"rst\"" /tmp/zbanner-default.log

run_case zbanner-record-ack \
    -ip "$HTTP_IP" -p "$HTTP_PORT,$CLOSED_PORT" -scan zbanner -probe http \
    -src-port 42000-42255 -scan-arg "--record-ack" -rate 100 --wait 2 --no-status -show info -show failed
grep -q "\"closed\" because \"rst\"" /tmp/zbanner-record-ack.log
grep -q "\"acknowledged\" because \"ack\"" /tmp/zbanner-record-ack.log

run_case hltcp-http \
    -ip "$HTTP_IP" -p "$HTTP_PORT,$CLOSED_PORT" -scan tcp-state -probe http-state \
    -src-port 43000-43255 -rate 100 --wait 2 --no-status -show info -show failed
grep -q "\"open\" because \"syn-ack\"" /tmp/hltcp-http.log
grep -q "\"closed\" because \"rst\"" /tmp/hltcp-http.log

run_case hltcp-tls \
    -ip "$TLS_IP" -p "$TLS_PORT" -scan tcp-state -probe tls-state \
    -src-port 44000-44255 -probe-arg "-subprobe close-state -sni example.test -alpn h2,http/1.1 --dump-version --dump-cipher --dump-cert --ssl-keylog --graceful-tls-close" \
    -rate 100 --wait 2 --no-status -show info -show failed
grep -q "tls info" /tmp/hltcp-tls.log
grep -q "TLSv1" /tmp/hltcp-tls.log
grep -q "key_log" /tmp/hltcp-tls.log

run_case hltcp-tls-http \
    -ip "$TLS_IP" -p "$TLS_PORT" -scan tcp-state -probe tls-state \
    -src-port 45000-45255 -probe-arg "-subprobe http-state -subprobe-arg '--all-banner' -sni example.test -alpn http/1.1 --dump-version" \
    -rate 100 --wait 2 --no-status -show info -show failed
grep -q "tls info" /tmp/hltcp-tls-http.log

run_case zbanner-jarm \
    -ip "$JARM_IP" -p "$JARM_PORT" -scan zbanner -probe jarm \
    -src-port 40000-40255 -rate 100 --wait 8 --no-status -show info -show failed \
    -output-module ndjson -output-file /tmp/jarm.jsonl -output-screen
grep -q "jarm_slot" /tmp/zbanner-jarm.log
grep -q "jarm_slots" /tmp/zbanner-jarm.log
grep -q "jarm_part" /tmp/zbanner-jarm.log
python3 /work/xtate/tools/jarm_aggregate.py /tmp/jarm.jsonl \
    --complete-out /tmp/jarm-complete.jsonl \
    --stats-out /tmp/jarm-stats.json >/dev/null
grep -q "jarm" /tmp/jarm-complete.jsonl
grep -q "complete.*1" /tmp/jarm-stats.json

run_case zbanner-slot-test \
    -ip "$HTTP_IP" -p "$HTTP_PORT" -scan zbanner -probe slot-test \
    -src-port 46000-46255 -rate 100 --wait 2 --no-status -show info -show failed
grep -q "slot_test_slot: 1" /tmp/zbanner-slot-test.log
grep -q "slot_test_slot: 2" /tmp/zbanner-slot-test.log
grep -q "slot_test_slot: 3" /tmp/zbanner-slot-test.log

run_case zbanner-ssh \
    -ip "$SSH_IP" -p "$SSH_PORT" -scan zbanner -probe ssh \
    -src-port 48000-48255 -rate 100 --wait 2 --no-status -show info -show failed
grep -q "ssh_banner" /tmp/zbanner-ssh.log
grep -q "ssh_protocol" /tmp/zbanner-ssh.log
grep -q "OpenSSH_9.9" /tmp/zbanner-ssh.log

run_case udp-slot-test \
    -ip "$UDP_ECHO_IP" -p U:8082 -scan udp -probe slot-test-udp \
    -src-port 47000-47255 -rate 100 --wait 2 --no-status -show info -show failed
grep -q "slot_test_slot: 1" /tmp/udp-slot-test.log
grep -q "slot_test_slot: 2" /tmp/udp-slot-test.log
grep -q "slot_test_slot: 3" /tmp/udp-slot-test.log

if command -v iptables >/dev/null 2>&1; then
    bash firewall/rm_rules.sh >/dev/null 2>&1 || true
fi

echo "ALL LOCAL LAB CHECKS PASSED"
' 

if ! docker logs "$TLS_TARGET" 2>&1 | grep -q "server name"; then
    echo "TLS target did not receive the SNI extension" >&2
    exit 1
fi
if ! docker logs "$TLS_TARGET" 2>&1 | grep -q "application layer protocol negotiation"; then
    echo "TLS target did not receive the ALPN extension" >&2
    exit 1
fi

echo "==> SNI/ALPN extensions verified"
echo "==> lab passed"

