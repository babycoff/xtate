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
    local out="$1" module="$2" pcap="${3:-$ROOT/tests/http-state-pcap/httpstate.pcap}"
    "$BIN" -ip 172.20.0.2 -p 8080 -scan tcp-state -probe http-state \
        --adapter "file:$pcap" \
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


# Build a copy of the HTTP fixture with a quoted/backslash header value and
# verify both NDJSON and CSV preserve it as a valid JSON string.
python3 - "$ROOT/tests/http-state-pcap/httpstate.pcap" "$TMP/quote.pcap" <<'PY'
import struct, sys
src = open(sys.argv[1], "rb").read()
out = bytearray(src)
off = 24
target = None
while off + 16 <= len(out):
    hdr_off = off
    _, _, incl, _ = struct.unpack_from("<IIII", out, off)
    off += 16
    data_off = off
    d = out[off:off + incl]
    off += incl
    if b"HTTP/1.0 200 OK\r\nServer:" in d:
        target = (hdr_off, data_off, incl)
        break
assert target
_, data_off, incl = target
eth, ip, tcp = 14, 34, 54
old = b"Server: SimpleHTTP/0.6 Python/3.12.3"
new = b'Server: "Quoted\\Value"'
assert len(new) <= len(old)
new += b" " * (len(old) - len(new))
d = bytearray(out[data_off:data_off + incl])
pos = d.find(old)
assert pos >= 0
d[pos:pos + len(old)] = new
def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff
d[eth + 10:eth + 12] = b"\0\0"
d[eth + 20 + 16:eth + 20 + 18] = b"\0\0"
d[eth + 10:eth + 12] = struct.pack("!H", csum(d[eth:eth + 20]))
pseudo = (d[eth + 12:eth + 16] + d[eth + 16:eth + 20] + b"\0" +
          d[eth + 9:eth + 10] + struct.pack("!H", len(d[eth + 20:])))
d[eth + 20 + 16:eth + 20 + 18] = struct.pack("!H", csum(pseudo + d[eth + 20:]))
out[data_off:data_off + incl] = d
open(sys.argv[2], "wb").write(out)
PY
run_replay "$TMP/quote.ndjson" ndjson "$TMP/quote.pcap"
python3 - "$TMP/quote.ndjson" <<'PY'
import json, sys
vals = []
for line in open(sys.argv[1], encoding="utf-8"):
    doc = json.loads(line)
    h = doc.get("probe report", {}).get("http_header_0")
    if h:
        vals.append(h)
assert any('Quoted' in v for v in vals), vals
print("quoted ndjson: ok")
PY
run_replay "$TMP/quote.csv" csv "$TMP/quote.pcap"
python3 - "$TMP/quote.csv" <<'PY'
import csv, json, sys
rows = list(csv.reader(open(sys.argv[1], encoding="utf-8")))
found = False
for row in rows[1:]:
    doc = json.loads(row[10])
    if "http_header_0" in doc and "Quoted" in doc["http_header_0"]:
        found = True
assert found
print("quoted csv: ok")
PY

echo "input/output audit: success"
