#!/usr/bin/env bash
# Input/output regression checks: NDJSON/CSV validity, BSON length cap, target
# line limit. Uses the recorded HTTP-state pcap; no network required.
set -euo pipefail
ROOT="${XTATE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="${XTATE_BIN:-$ROOT/xtate}"
TMP="${TMPDIR:-/tmp}/xtate-io-audit.$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"
[[ -x "$BIN" ]] || { echo "xtate binary not found: $BIN" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

run_replay() {
    local out="$1" module="$2"
    "$BIN" -ip 172.20.0.2 -p 8080 -scan tcp-state -probe http-state \
        --adapter "file:$ROOT/tests/http-state-pcap/httpstate.pcap" \
        --source-ip 172.20.0.3 --source-mac 02-00-00-00-00-01 \
        --router-mac 02-00-00-00-00-02 -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 2 --no-status -show info -show failed \
        -output-module "$module" -output-file "$out" >/dev/null 2>&1
}

run_replay "$TMP/out.ndjson" ndjson
python3 - "$TMP/out.ndjson" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    json.loads(line)
print("ndjson: ok")
PY

run_replay "$TMP/out.csv" csv
python3 - "$TMP/out.csv" <<'PY'
import csv, sys
rows = list(csv.reader(open(sys.argv[1], encoding="utf-8")))
assert rows and len(rows[0]) == 12, rows[0]
import json
for row in rows[1:]:
    for i in (9, 10, 11):
        json.loads(row[i])
print("csv: ok")
PY

python3 - "$TMP/long.txt" <<'PY'
import sys
open(sys.argv[1], "w").write("1.1.1.1\n" + "a" * 70000 + "\n")
PY
if "$BIN" --list-target --include-file "$TMP/long.txt" >"$TMP/long.log" 2>&1; then
    echo "FAIL: long target line accepted" >&2
    exit 1
fi
grep -q "line too long" "$TMP/long.log"

python3 - "$TMP/bad.bson" <<'PY'
import sys
open(sys.argv[1], "wb").write((0x7fffffff).to_bytes(4, "little"))
PY
if "$BIN" --parse-bson "$TMP/bad.bson" >"$TMP/bson.log" 2>&1; then
    echo "FAIL: oversized BSON accepted" >&2
    exit 1
fi
grep -q "Invalid BSON document length" "$TMP/bson.log"

echo "input/output audit: success"
