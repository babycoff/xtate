#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/xtate}"
PYTHON="${PYTHON:-python3}"
TMP="${TMPDIR:-/tmp}/xtate-udp-pcap.$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"
[[ -x "$BIN" ]] || { echo "xtate binary not found: $BIN" >&2; exit 1; }

"$PYTHON" "$ROOT/tests/udp-pcap/make_fixture.py" --out "$TMP/udp.pcap"
"$PYTHON" "$ROOT/tests/udp-pcap/make_fixture.py" --out "$TMP/udp6.pcap" --ip-version 6 --target 2001:db8::2 --ip-me 2001:db8::1
"$PYTHON" "$ROOT/tests/udp-pcap/make_fixture.py" --out "$TMP/icmp6.pcap" --mode icmp --ip-version 6 --target 2001:db8::2 --ip-me 2001:db8::1
"$PYTHON" "$ROOT/tests/udp-pcap/make_fixture.py" --out "$TMP/icmp.pcap" --mode icmp
"$BIN" -ip 192.0.2.2 -p U:8080 -scan udp -probe echo \
    --adapter "file:$TMP/udp.pcap" \
    --source-ip 192.0.2.1 \
    --source-mac 02-00-00-00-00-01 \
    --router-mac 02-00-00-00-00-02 \
    -source-port 40000-40255 -seed 123 \
    --no-resume-file --wait 2 --no-status -show success -show info -show failed \
    >"$TMP/udp.log" 2>&1
grep -q '"responsed" because "carrying data"' "$TMP/udp.log" || { cat "$TMP/udp.log" >&2; exit 1; }
grep -q 'banner:' "$TMP/udp.log" || { cat "$TMP/udp.log" >&2; exit 1; }

"$BIN" -ip 192.0.2.2 -p U:8080 -scan udp -probe echo \
    --adapter "file:$TMP/icmp.pcap" \
    --source-ip 192.0.2.1 \
    --source-mac 02-00-00-00-00-01 \
    --router-mac 02-00-00-00-00-02 \
    -source-port 40000-40255 -seed 123 \
    --no-resume-file --wait 2 --no-status -show success -show info -show failed \
    >"$TMP/icmp.log" 2>&1
grep -q '"closed" because "port unreachable"' "$TMP/icmp.log" || { cat "$TMP/icmp.log" >&2; exit 1; }
grep -q 'icmp proto: "UDP"' "$TMP/icmp.log" || { cat "$TMP/icmp.log" >&2; exit 1; }

for f in udp6 icmp6; do
    "$BIN" -ip 2001:db8::2 -p U:8080 -scan udp -probe echo \
        --adapter "file:$TMP/$f.pcap" \
        --source-ip 2001:db8::1 \
        --source-mac 02-00-00-00-00-01 \
        --router-mac 02-00-00-00-00-02 \
        -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 2 --no-status -show success -show info -show failed \
        >"$TMP/$f.log" 2>&1
    if [[ $f == udp6 ]]; then
        grep -q '"responsed" because "carrying data"' "$TMP/$f.log" || { cat "$TMP/$f.log" >&2; exit 1; }
    else
        grep -q '"closed" because "port unreachable"' "$TMP/$f.log" || { cat "$TMP/$f.log" >&2; exit 1; }
    fi
done

echo "PASS: UDP pcap matrix"
