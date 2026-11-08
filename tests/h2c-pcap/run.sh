#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/xtate}"
PYTHON="${PYTHON:-python3}"
TMP="${TMPDIR:-/tmp}/xtate-h2c-pcap.$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"
[[ -x "$BIN" ]] || { echo "xtate binary not found: $BIN" >&2; exit 1; }

"$PYTHON" "$ROOT/tests/h2c-pcap/make_fixture.py" --out "$TMP/h2c.pcap"
"$BIN" -ip 172.20.0.4 -p 8446 -scan zbanner -probe h2c \
    -scan-arg '--all-banner --no-dedup-banner' \
    --adapter "file:$TMP/h2c.pcap" \
    --source-ip 172.20.0.5 \
    --source-mac 02-00-00-00-00-01 \
    --router-mac 02-00-00-00-00-02 \
    -source-port 40000-40255 -seed 123 \
    --no-resume-file --wait 3 --no-status -show info -show failed \
    >"$TMP/h2c.log" 2>&1
grep -q 'http2_frame_count: 3' "$TMP/h2c.log" || { cat "$TMP/h2c.log" >&2; exit 1; }
grep -q '"http/2" because "frame"' "$TMP/h2c.log" || { cat "$TMP/h2c.log" >&2; exit 1; }

"$BIN" -ip 172.20.0.4 -p 8446 -scan zbanner -probe h2c \
    -scan-arg '--all-banner --no-dedup-banner' \
    -probe-arg '--all-frames' \
    --adapter "file:$TMP/h2c.pcap" \
    --source-ip 172.20.0.5 \
    --source-mac 02-00-00-00-00-01 \
    --router-mac 02-00-00-00-00-02 \
    -source-port 40000-40255 -seed 123 \
    --no-resume-file --wait 3 --no-status -show info -show failed \
    >"$TMP/h2c-allframes.log" 2>&1
grep -q 'http2_frame_count: 3' "$TMP/h2c-allframes.log" || { cat "$TMP/h2c-allframes.log" >&2; exit 1; }
grep -q 'http2_f3_type: 0' "$TMP/h2c-allframes.log" || { cat "$TMP/h2c-allframes.log" >&2; exit 1; }

echo "PASS: H2C synthetic pcap matrix"
