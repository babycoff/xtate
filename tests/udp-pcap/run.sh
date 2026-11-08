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
echo "PASS: UDP pcap matrix"
