#!/usr/bin/env bash
# Output-side JARM aggregation: complete, incomplete, duplicate slots.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

python3 - "$TMP/in.ndjson" <<'PY'
import json
import sys

path = sys.argv[1]
rows = []

def add(ip, port, slot, part):
    rows.append({
        "ip_them": ip,
        "port_them": port,
        "probe report": {
            "jarm_slot": slot,
            "jarm_slots": 10,
            "jarm_part": part,
        },
    })

for slot in range(1, 11):
    add("192.0.2.10", 443, slot, f"c0{slot:02x}|0303|ext{slot}")
for slot in range(1, 11):
    if slot not in (3, 4):
        add("192.0.2.11", 443, slot, f"c1{slot:02x}|0303|ext{slot}")
for slot in range(1, 11):
    add("192.0.2.12", 443, slot, f"c2{slot:02x}|0303|ext{slot}")
# duplicate slot on the third target; latest value wins
add("192.0.2.12", 443, 1, "dup|0303|duplicate")

with open(path, "w", encoding="utf-8") as out:
    for row in rows:
        out.write(json.dumps(row, sort_keys=True) + "\n")
PY

python3 "$ROOT/tools/jarm_aggregate.py" \
    "$TMP/in.ndjson" \
    --complete-out "$TMP/complete.jsonl" \
    --retry-out "$TMP/retry.jsonl" \
    --retry-csv "$TMP/retry.csv" \
    --retry-ip-file "$TMP/retry-ip.txt" \
    --retry-ports-file "$TMP/retry-ports.txt" \
    --retry-dir "$TMP/retry" \
    --retry-template "xtate -iL {ips_file} -p {port} -scan zbanner -probe jarm" \
    --stats-out "$TMP/stats.json" >/dev/null

python3 - "$TMP" <<'PY'
import json
import sys
from pathlib import Path

tmp = Path(sys.argv[1])
stats = json.loads((tmp / "stats.json").read_text())
assert stats["records"] == 29, stats
assert stats["targets"] == 3, stats
assert stats["complete"] == 2, stats
assert stats["incomplete"] == 1, stats
assert stats["duplicate_slots"] == 1, stats
assert stats["missing_slot_counts"] == {"3": 1, "4": 1}, stats

complete = [json.loads(line) for line in (tmp / "complete.jsonl").read_text().splitlines()]
assert len(complete) == 2, complete
assert all(len(row["jarm"]) == 62 for row in complete), complete
assert all(len(row["jarm_sha256"]) == 64 for row in complete), complete
assert all(len(row["parts"]) == 10 for row in complete), complete

retry = [json.loads(line) for line in (tmp / "retry.jsonl").read_text().splitlines()]
assert len(retry) == 1, retry
assert retry[0]["ip_them"] == "192.0.2.11", retry
assert retry[0]["missing_slots"] == [3, 4], retry
assert (tmp / "retry-ip.txt").read_text().strip() == "192.0.2.11"
assert (tmp / "retry-ports.txt").read_text().strip() == "443"
assert (tmp / "retry" / "port-443.ips").read_text().strip() == "192.0.2.11"
assert "xtate -iL" in (tmp / "retry" / "retry-commands.txt").read_text()
assert "192.0.2.11,443,3 4" in (tmp / "retry.csv").read_text()
print("PASS: JARM aggregation complete/incomplete/retry")
PY

if [[ -n "${XTATE_BIN:-}" ]]; then
    help="$("$XTATE_BIN" --help-probe jarm)"
    grep -q "Slot count: 10" <<<"$help"
    grep -q "Slot trigger: after first reply" <<<"$help"
    ! grep -q 'lzr' <<<"$("$XTATE_BIN" --list-probe)"
    count="$("$XTATE_BIN" --list-probe | grep -cE '^[[:space:]]*[0-9]+\.[A-Za-z]')"
    [[ "$count" -eq 21 ]]
    echo "PASS: JARM slot plan help and 21-probe inventory"
fi

