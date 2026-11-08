#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/xtate}"
PYTHON="${PYTHON:-python3}"
TMP="${TMPDIR:-/tmp}/xtate-tcpsyn-pcap.$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"
[[ -x "$BIN" ]] || { echo "xtate binary not found: $BIN" >&2; exit 1; }

"$PYTHON" "$ROOT/tests/tcp-syn-pcap/make_fixture.py" --out "$TMP/synack.pcap" --mode synack
"$PYTHON" "$ROOT/tests/tcp-syn-pcap/make_fixture.py" --out "$TMP/rst.pcap" --mode rst

run() {
    local name="$1"
    local log="$TMP/$name.log"
    "$BIN" -ip 192.0.2.2 -p 8080 -scan tcp-syn \
        --adapter "file:$TMP/$name.pcap" \
        --source-ip 192.0.2.1 \
        --source-mac 02-00-00-00-00-01 \
        --router-mac 02-00-00-00-00-02 \
        -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 2 --no-status -show info -show failed \
        >"$log" 2>&1
    echo "$log"
}

grep -q '"open" because "syn-ack"' "$(run synack)" || { cat "$TMP/synack.log" >&2; exit 1; }
grep -q '"closed" because "rst"' "$(run rst)" || { cat "$TMP/rst.log" >&2; exit 1; }
echo "PASS: tcp-syn pcap offline matrix"
