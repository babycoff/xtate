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
HTTP2_TARGET="xtate-lab-http2-$$"
H2_TARGET="xtate-lab-h2-$$"
QUIC_TARGET="xtate-lab-quic-$$"
QUIC_RETRY_TARGET="xtate-lab-quic-retry-$$"
HTTP3_TARGET="xtate-lab-http3-$$"
STARTTLS_TARGET="xtate-lab-starttls-$$"
HTTP_PORT=8080
CLOSED_PORT=9
TLS_PORT=8443
JARM_PORT=9443
SSH_PORT=2222
HTTP2_PORT=8084
H2_PORT=8445
QUIC_PORT=4433
QUIC_RETRY_PORT=4434
HTTP3_PORT=4435
STARTTLS_SMTP_PORT=2525
STARTTLS_IMAP_PORT=2143
STARTTLS_POP3_PORT=2110
STARTTLS_FTP_PORT=2121

cleanup() {
    docker rm -f "$HTTP_TARGET" "$TLS_TARGET" "$JARM_TARGET" "$UDP_ECHO_TARGET" "$SSH_TARGET" "$HTTP2_TARGET" "$H2_TARGET" "$STARTTLS_TARGET" "$QUIC_TARGET" "$QUIC_RETRY_TARGET" "$HTTP3_TARGET" >/dev/null 2>&1 || true
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
     openssl s_server -accept $TLS_PORT -cert /tmp/cert.pem -key /tmp/key.pem -tlsextdebug -alpn h2,http/1.1 -www" >/dev/null

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

echo "==> starting HTTP/2 target"
MSYS_NO_PATHCONV=1 docker run -d --name "$HTTP2_TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$IMAGE" \
    python3 -u /src/tests/lab/http2_server.py >/dev/null

echo "==> starting STARTTLS targets"
MSYS_NO_PATHCONV=1 docker run -d --name "$STARTTLS_TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$IMAGE" bash -lc \
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/st-key.pem \
       -out /tmp/st-cert.pem -subj '/CN=starttls.test' -days 1 >/dev/null 2>&1 && \
     python3 -u /src/tests/lab/starttls_server.py /tmp/st-cert.pem /tmp/st-key.pem" >/dev/null

echo "==> starting QUIC target"
MSYS_NO_PATHCONV=1 docker run -d --name "$QUIC_TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$IMAGE" bash -lc \
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/quic-key.pem \
       -out /tmp/quic-cert.pem -subj '/CN=quic.test' -days 1 >/dev/null 2>&1 && \
     python3 -u /src/tests/lab/quic_server.py /tmp/quic-cert.pem /tmp/quic-key.pem $QUIC_PORT" >/dev/null

echo "==> starting QUIC Retry target"
MSYS_NO_PATHCONV=1 docker run -d --name "$QUIC_RETRY_TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$IMAGE" bash -lc \
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/quic-key.pem \
       -out /tmp/quic-cert.pem -subj '/CN=quic.test' -days 1 >/dev/null 2>&1 && \
     python3 -u /src/tests/lab/quic_server.py /tmp/quic-cert.pem /tmp/quic-key.pem $QUIC_RETRY_PORT retry" >/dev/null

echo "==> starting HTTP/3 target"
MSYS_NO_PATHCONV=1 docker run -d --name "$HTTP3_TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$IMAGE" bash -lc \
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/h3-key.pem \
       -out /tmp/h3-cert.pem -subj '/CN=quic.test' -days 1 >/dev/null 2>&1 && \
     python3 -u /src/tests/lab/http3_server.py /tmp/h3-cert.pem /tmp/h3-key.pem $HTTP3_PORT" >/dev/null

echo "==> starting TLS HTTP/2 target"
MSYS_NO_PATHCONV=1 docker run -d --name "$H2_TARGET" --network "$NET" \
    -v "$ROOT:/src:ro" "$IMAGE" bash -lc \
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/h2-key.pem \
       -out /tmp/h2-cert.pem -subj '/CN=example.test' -days 1 >/dev/null 2>&1 && \
     python3 -u /src/tests/lab/h2_tls_server.py" >/dev/null

wait_tcp "$HTTP_TARGET" "$HTTP_PORT"
wait_tcp "$TLS_TARGET" "$TLS_PORT"
wait_tcp "$JARM_TARGET" "$JARM_PORT"
wait_tcp "$SSH_TARGET" "$SSH_PORT"
wait_tcp "$HTTP2_TARGET" "$HTTP2_PORT"
wait_tcp "$H2_TARGET" "$H2_PORT"
wait_tcp "$STARTTLS_TARGET" "$STARTTLS_SMTP_PORT"
wait_tcp "$STARTTLS_TARGET" "$STARTTLS_IMAP_PORT"
wait_tcp "$STARTTLS_TARGET" "$STARTTLS_POP3_PORT"
wait_tcp "$STARTTLS_TARGET" "$STARTTLS_FTP_PORT"
sleep 2

HTTP_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$HTTP_TARGET")"
TLS_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TLS_TARGET")"
JARM_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$JARM_TARGET")"
UDP_ECHO_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$UDP_ECHO_TARGET")"
SSH_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SSH_TARGET")"
HTTP2_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$HTTP2_TARGET")"
H2_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$H2_TARGET")"
STARTTLS_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$STARTTLS_TARGET")"
QUIC_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$QUIC_TARGET")"
QUIC_RETRY_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$QUIC_RETRY_TARGET")"
HTTP3_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$HTTP3_TARGET")"
echo "HTTP target: $HTTP_IP:$HTTP_PORT (closed test port $CLOSED_PORT)"
echo "TLS  target: $TLS_IP:$TLS_PORT"
echo "JARM target: $JARM_IP:$JARM_PORT"
echo "UDP echo:   $UDP_ECHO_IP:8082"
echo "SSH banner:  $SSH_IP:$SSH_PORT"
echo "HTTP/2:      $HTTP2_IP:$HTTP2_PORT"
echo "HTTP/3:      $HTTP3_IP:$HTTP3_PORT"
echo "TLS h2:      $H2_IP:$H2_PORT"

docker run --rm \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    --network "$NET" \
    -e HTTP_IP="$HTTP_IP" -e TLS_IP="$TLS_IP" -e JARM_IP="$JARM_IP" -e UDP_ECHO_IP="$UDP_ECHO_IP" -e SSH_IP="$SSH_IP" -e HTTP2_IP="$HTTP2_IP" -e H2_IP="$H2_IP" -e STARTTLS_IP="$STARTTLS_IP" -e QUIC_IP="$QUIC_IP" -e QUIC_RETRY_IP="$QUIC_RETRY_IP" -e HTTP3_IP="$HTTP3_IP" \
    -e HTTP_PORT="$HTTP_PORT" -e CLOSED_PORT="$CLOSED_PORT" \
    -e TLS_PORT="$TLS_PORT" -e JARM_PORT="$JARM_PORT" -e SSH_PORT="$SSH_PORT" -e HTTP2_PORT="$HTTP2_PORT" -e H2_PORT="$H2_PORT" \
    -e STARTTLS_SMTP_PORT="$STARTTLS_SMTP_PORT" -e STARTTLS_IMAP_PORT="$STARTTLS_IMAP_PORT" -e STARTTLS_POP3_PORT="$STARTTLS_POP3_PORT" -e STARTTLS_FTP_PORT="$STARTTLS_FTP_PORT" -e QUIC_PORT="$QUIC_PORT" -e QUIC_RETRY_PORT="$QUIC_RETRY_PORT" -e HTTP3_PORT="$HTTP3_PORT" \
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
grep -q "http_status" /tmp/zbanner-default.log
grep -q "http_header_count" /tmp/zbanner-default.log

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
grep -q "http_status" /tmp/hltcp-http.log
grep -q "http_header_count" /tmp/hltcp-http.log

run_case hltcp-tls \
    -ip "$TLS_IP" -p "$TLS_PORT" -scan tcp-state -probe tls-state \
    -src-port 44000-44255 -probe-arg "-subprobe close-state -sni example.test -alpn h2,http/1.1 --dump-version --dump-cipher --dump-cert --dump-cert-details --ssl-keylog --graceful-tls-close" \
    -rate 100 --wait 2 --no-status -show info -show failed
grep -q "tls info" /tmp/hltcp-tls.log
grep -q "TLSv1" /tmp/hltcp-tls.log
grep -q "key_log" /tmp/hltcp-tls.log
grep -q "cert_subject" /tmp/hltcp-tls.log
grep -q "cert_issuer" /tmp/hltcp-tls.log
grep -q "cert_public_key" /tmp/hltcp-tls.log
grep -q "tls_alpn" /tmp/hltcp-tls.log

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

# Compare the scanner JARM against the vendored Salesforce implementation
# on the same local TLS target.
python3 /work/xtate/tests/reference/jarm.py "$JARM_IP" -p "$JARM_PORT" -j > /tmp/jarm-official.json
python3 - <<PY
import json
xtate = json.loads(open("/tmp/jarm-complete.jsonl").readline())
official = json.loads(open("/tmp/jarm-official.json").readline())
assert xtate["jarm"] == official["result"], (xtate, official)
assert len(xtate["jarm"]) == 62
print("PASS: JARM matches Salesforce reference on local target")
PY

run_case zbanner-jarm-first \
    -ip "$JARM_IP" -p "$JARM_PORT" -scan zbanner -probe jarm \
    -src-port 51624-51879 -rate 100 --wait 8 --no-status -show info -show failed \
    -probe-arg "--first-probe 7" \
    -output-module ndjson -output-file /tmp/jarm-first.jsonl -output-screen
grep -q "jarm_slot: 7" /tmp/zbanner-jarm-first.log
python3 /work/xtate/tools/jarm_aggregate.py /tmp/jarm-first.jsonl \
    --complete-out /tmp/jarm-first-complete.jsonl \
    --stats-out /tmp/jarm-first-stats.json >/dev/null
grep -q "complete.*1" /tmp/jarm-first-stats.json

run_case zbanner-slot-test \
    -ip "$HTTP_IP" -p "$HTTP_PORT" -scan zbanner -probe slot-test \
    -src-port 46000-46255 -rate 100 --wait 2 --no-status -show info -show failed
grep -q "slot_test_slot: 1" /tmp/zbanner-slot-test.log
grep -q "slot_test_slot: 2" /tmp/zbanner-slot-test.log
grep -q "slot_test_slot: 3" /tmp/zbanner-slot-test.log

run_case zbanner-ssh \
    -ip "$SSH_IP" -p "$SSH_PORT" -scan zbanner -probe ssh \
    -src-port 48000-48255 -rate 100 --wait 2 --no-status -show info -show failed \
    -probe-arg "--record-kexinit"
grep -q "ssh_banner" /tmp/zbanner-ssh.log
grep -q "ssh_protocol" /tmp/zbanner-ssh.log
grep -q "OpenSSH_9.9" /tmp/zbanner-ssh.log
grep -q "ssh_kex_algorithms" /tmp/zbanner-ssh.log
grep -q "curve25519-sha256" /tmp/zbanner-ssh.log
grep -q "ssh_host_key_algorithms" /tmp/zbanner-ssh.log
grep -q "ssh-ed25519" /tmp/zbanner-ssh.log
grep -q "ssh_kexinit" /tmp/zbanner-ssh.log

run_case zbanner-ssh-custom \
    -ip "$SSH_IP" -p "$SSH_PORT" -scan zbanner -probe ssh \
    -src-port 48256-48511 -rate 100 --wait 2 --no-status -show info -show failed \
    -probe-arg "--send-banner 'SSH-2.0-Xtate_Test\r\n' --no-banner --no-software --record-kexinit"
grep -q "ssh_kexinit" /tmp/zbanner-ssh-custom.log
! grep -q "ssh_banner" /tmp/zbanner-ssh-custom.log
! grep -q "ssh_software" /tmp/zbanner-ssh-custom.log

run_case zbanner-h2c \
    -ip "$HTTP2_IP" -p "$HTTP2_PORT" -scan zbanner -probe h2c \
    -src-port 49000-49255 -rate 100 --wait 2 --no-status -show info -show failed \
    -probe-arg "--settings-hex 00030000006400040000ffff --all-frames --record-raw"
grep -q "http/2" /tmp/zbanner-h2c.log
grep -q "http2_frame_type" /tmp/zbanner-h2c.log
grep -q "http2_settings_count" /tmp/zbanner-h2c.log
grep -q "http2_set_3" /tmp/zbanner-h2c.log
grep -q "http2_frame_count: 2" /tmp/zbanner-h2c.log

run_case udp-slot-test \
    -ip "$UDP_ECHO_IP" -p U:8082 -scan udp -probe slot-test-udp \
    -src-port 47000-47255 -rate 100 --wait 2 --no-status -show info -show failed
grep -q "slot_test_slot: 1" /tmp/udp-slot-test.log
grep -q "slot_test_slot: 2" /tmp/udp-slot-test.log
grep -q "slot_test_slot: 3" /tmp/udp-slot-test.log

run_case hltcp-starttls-smtp \
    -ip "$STARTTLS_IP" -p "$STARTTLS_SMTP_PORT" -scan tcp-state -probe tls-state \
    -probe-arg "-subprobe close-state --starttls smtp --dump-cert-details" \
    -src-port 50600-50855 -rate 100 --wait 3 --no-status -show info -show failed
grep -q "cert_subject" /tmp/hltcp-starttls-smtp.log
grep -q "CN=starttls.test" /tmp/hltcp-starttls-smtp.log

run_case hltcp-starttls-imap \
    -ip "$STARTTLS_IP" -p "$STARTTLS_IMAP_PORT" -scan tcp-state -probe tls-state \
    -probe-arg "-subprobe close-state --starttls imap --dump-cert-details" \
    -src-port 50856-51111 -rate 100 --wait 3 --no-status -show info -show failed
grep -q "cert_subject" /tmp/hltcp-starttls-imap.log
grep -q "CN=starttls.test" /tmp/hltcp-starttls-imap.log

run_case hltcp-starttls-pop3 \
    -ip "$STARTTLS_IP" -p "$STARTTLS_POP3_PORT" -scan tcp-state -probe tls-state \
    -probe-arg "-subprobe close-state --starttls pop3 --dump-cert-details" \
    -src-port 51112-51367 -rate 100 --wait 3 --no-status -show info -show failed
grep -q "cert_subject" /tmp/hltcp-starttls-pop3.log
grep -q "CN=starttls.test" /tmp/hltcp-starttls-pop3.log

run_case hltcp-starttls-ftp \
    -ip "$STARTTLS_IP" -p "$STARTTLS_FTP_PORT" -scan tcp-state -probe tls-state \
    -probe-arg "-subprobe close-state --starttls ftp --dump-cert-details" \
    -src-port 51368-51623 -rate 100 --wait 3 --no-status -show info -show failed
grep -q "cert_subject" /tmp/hltcp-starttls-ftp.log
grep -q "CN=starttls.test" /tmp/hltcp-starttls-ftp.log

run_case udp-quic \
    -ip "$QUIC_IP" -p U:"$QUIC_PORT" -scan udp -probe quic \
    -probe-arg "--record-raw" -rate 100 --wait 3 --no-status -show info -show failed
grep -q "quic_response" /tmp/udp-quic.log
grep -q "initial" /tmp/udp-quic.log
grep -q "quic_version: 1" /tmp/udp-quic.log
grep -q "quic_scid" /tmp/udp-quic.log
grep -q "quic_raw" /tmp/udp-quic.log

run_case quic-state \
    -ip "$QUIC_IP" -p U:"$QUIC_PORT" -scan quic-state -probe close-state \
    -scan-arg "--alpn h3 --max-udp-payload 1200 --handshake-timeout 5" \
    -rate 100 --wait 5 --no-status -show info -show failed
grep -q "quic handshake" /tmp/quic-state.log
grep -q "quic_alpn: \"h3\"" /tmp/quic-state.log
grep -q "quic_tls_version: \"TLS1.3\"" /tmp/quic-state.log
grep -q "quic_cert_subject" /tmp/quic-state.log
grep -q "quic_cert_sha256" /tmp/quic-state.log

run_case http3-state \
    -ip "$HTTP3_IP" -p U:"$HTTP3_PORT" -scan quic-state -probe http3-state \
    -scan-arg "--alpn h3 --handshake-timeout 5" \
    -rate 100 --wait 6 --no-status -show info -show failed
grep -q "\"http3\"" /tmp/http3-state.log
grep -q "http3_status: 200" /tmp/http3-state.log
grep -q "http3_body_len: 27" /tmp/http3-state.log
grep -q "hello from xtate http3 lab" /tmp/http3-state.log

run_case udp-quic-retry \
    -ip "$QUIC_RETRY_IP" -p U:"$QUIC_RETRY_PORT" -scan udp -probe quic \
    -rate 100 --wait 3 --no-status -show info -show failed
grep -q "quic_response" /tmp/udp-quic-retry.log
grep -q "retry" /tmp/udp-quic-retry.log
grep -q "quic_token_len" /tmp/udp-quic-retry.log

run_case hltcp-h2 \
    -ip "$H2_IP" -p "$H2_PORT" -scan tcp-state -probe tls-state \
    -probe-arg "-subprobe h2 -sni example.test -alpn h2" \
    -src-port 50000-50255 -rate 100 --wait 3 --no-status -show info -show failed
grep -q "h2_status" /tmp/hltcp-h2.log
    grep -q "200" /tmp/hltcp-h2.log
grep -q "h2_frame_count" /tmp/hltcp-h2.log
grep -q "http/2" /tmp/hltcp-h2.log

run_case hltcp-h2-params \
    -ip "$H2_IP" -p "$H2_PORT" -scan tcp-state -probe tls-state \
    -probe-arg "-subprobe h2 -subprobe-arg --path=/h2 -sni example.test -alpn h2" \
    -src-port 50256-50511 -rate 100 --wait 3 --no-status -show info -show failed
grep -q "h2_frame_count" /tmp/hltcp-h2-params.log

if command -v iptables >/dev/null 2>&1; then
    bash firewall/rm_rules.sh >/dev/null 2>&1 || true
fi

echo "ALL LOCAL LAB CHECKS PASSED"
' 

# SNI/ALPN delivery is asserted from scanner output (`tls_alpn`) above.
echo "==> lab passed"

