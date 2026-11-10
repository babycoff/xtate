#!/usr/bin/env bash
# Isolated DoT / DoH regression lab. Requires Docker and a Linux xtate binary.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
TARGET_IMAGE="${XTATE_TARGET_IMAGE:-xtate-lab-target:24.04}"
SCANNER_IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
NET="xtate-dns-lab-$$"
DOT=xtate-dot-$$
DOH=xtate-doh-$$
DOH2=xtate-doh2-$$
cleanup() { docker rm -f "$DOT" "$DOH" "$DOH2" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker network create "$NET" >/dev/null
for spec in "dot:$DOT:8853:dot_server.py" "doh:$DOH:8854:doh_server.py" "doh2:$DOH2:8855:doh_h2_server.py"; do
    IFS=: read -r tag name port script <<< "$spec"
    docker run -d --name "$name" --network "$NET" -v "$ROOT:/src:ro" "$TARGET_IMAGE" bash -lc \
      "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem -out /tmp/cert.pem -subj '/CN=dns.test' -days 1 >/dev/null 2>&1 && python3 -u /src/tests/lab/$script /tmp/cert.pem /tmp/key.pem $port" >/dev/null
done

wait_port() {
    local c=$1 p=$2
    for _ in $(seq 1 60); do
        docker exec "$c" bash -c "timeout 1 bash -c '</dev/tcp/127.0.0.1/$p'" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "target $c:$p not ready" >&2; docker logs "$c" >&2 || true; return 1
}
wait_port "$DOT" 8853; wait_port "$DOH" 8854; wait_port "$DOH2" 8855
DOT_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$DOT")
DOH_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$DOH")
DOH2_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$DOH2")
DOT_MAC=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' "$DOT")
DOH_MAC=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' "$DOH")
DOH2_MAC=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' "$DOH2")

docker run --rm --network "$NET" --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$BIN:/xtate:ro" -e DOT_IP="$DOT_IP" -e DOH_IP="$DOH_IP" -e DOH2_IP="$DOH2_IP" \
  -e DOT_MAC="$DOT_MAC" -e DOH_MAC="$DOH_MAC" -e DOH2_MAC="$DOH2_MAC" "$SCANNER_IMAGE" bash -lc '
set -euo pipefail
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq iptables >/dev/null 2>&1 || true
bash /src/firewall/add_rules.sh >/dev/null 2>&1 || true
run() { local name="$1"; shift; timeout 15 /xtate "$@" > "/tmp/$name.log" 2>&1 || true; cat "/tmp/$name.log"; }
run dot -if eth0 -ip "$DOT_IP" -p 8853 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe dot -alpn dot -sni dns.test -subprobe-arg --req-name=example.com" \
  --router-mac "$DOT_MAC" -src-port 48000-48255 --rate 100 --no-resume-file --wait 3 --no-status -show info -show failed
grep -q "dot_rcode" /tmp/dot.log
run doh -if eth0 -ip "$DOH_IP" -p 8854 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe doh -alpn http/1.1 -sni dns.test -subprobe-arg \"--req-name=example.com --doh-host=dns.test\"" \
  --router-mac "$DOH_MAC" -src-port 48300-48555 --rate 100 --no-resume-file --wait 3 --no-status -show info -show failed
grep -q "doh_status: 200" /tmp/doh.log
run doh2 -if eth0 -ip "$DOH2_IP" -p 8855 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe doh-h2 -alpn h2 -sni dns.test -subprobe-arg \"--dns-name=example.com --authority=dns.test --path=/dns-query\"" \
  --router-mac "$DOH2_MAC" -src-port 48600-48855 --rate 100 --no-resume-file --wait 3 --no-status -show info -show failed
grep -q "doh_status: 200" /tmp/doh2.log
! grep -q "h2_hpack_decode_failed" /tmp/doh2.log
'
echo "dns transport lab passed"
