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

# Ciphers are from the ordered JARM cipher table.  The expected 62-character
# fingerprint below is the Salesforce JARM 1.0 fuzzy hash (cipher index +
# version nibble + first 32 hex chars of SHA-256 over ALPN/extensions).
ciphers = ["0033", "009d", "009f", "c013", "c013",
           "0033", "1302", "1303", "1301", "1302"]
for slot, cipher in enumerate(ciphers, 1):
    add("192.0.2.10", 443, slot,
        f"{cipher}|0303|h2|ff01-0001-0023-0017")
for slot in range(1, 11):
    if slot not in (3, 4):
        add("192.0.2.11", 443, slot, f"{ciphers[slot - 1]}|0303|h2|ext{slot}")
for slot in range(1, 11):
    add("192.0.2.12", 443, slot, f"{ciphers[slot - 1]}|0303|h2|ext{slot}")
# duplicate slot on the third target; latest value wins
add("192.0.2.12", 443, 1, "dup|0303|duplicate")
# A valid open row with no JARM part: it is not a JARM target.
rows.append({"ip_them": "192.0.2.13", "port_them": 443,
             "classification": "open", "reason": "syn-ack"})

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
assert stats["records_total"] == 30, stats
assert stats["records_without_parts"] == 1, stats
assert stats["invalid_records"] == 0, stats
assert stats["targets_with_parts"] == 3, stats
assert stats["complete"] == 2, stats
assert stats["incomplete"] == 1, stats
assert stats["duplicate_slots"] == 1, stats
assert "not the number of scanned targets" in stats["meaning"]
assert stats["missing_slot_counts"] == {"3": 1, "4": 1}, stats

complete = [json.loads(line) for line in (tmp / "complete.jsonl").read_text().splitlines()]
assert len(complete) == 2, complete
assert all(len(row["jarm"]) == 62 for row in complete), complete
assert all(len(row["jarm_sha256"]) == 64 for row in complete), complete
assert all(len(row["parts"]) == 10 for row in complete), complete
reference = "07d14d16d21d21d07d42d43d41d42ddfc43ee7acc62b036086f04e8bdf3c46"
assert complete[0]["jarm"] == reference, complete[0]
assert complete[0]["jarm_sha256"] == (
    "9f397111b7a54b810bc9e2424812cc7133b1718f4077f08f65a396a1b9535044"
), complete[0]

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

python3 - "$ROOT/tools" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import jarm_aggregate as ja

all_refused = {slot: "|||" for slot in range(1, 11)}
assert ja.jarm_hash(all_refused, 10)[1] == "0" * 62
assert ja.cipher_bytes("0033") == "07"
assert ja.version_byte("0303") == "d"
print("PASS: JARM 1.0 hash edge cases")
PY

if [[ -n "${XTATE_BIN:-}" ]]; then
    help="$("$XTATE_BIN" --help-probe jarm)"
    grep -q "Slot count: 10" <<<"$help"
    grep -q "Slot trigger: after first reply" <<<"$help"
    grep -q -- "--first-probe" <<<"$help"
    ! grep -q 'lzr' <<<"$("$XTATE_BIN" --list-probe)"
    count="$("$XTATE_BIN" --list-probe | grep -cE '^[[:space:]]*[0-9]+\.[A-Za-z]')"
    # 59 probes on Windows, 60 on Linux builds with ngtcp2/GnuTLS.
    [[ "$count" -eq 59 || "$count" -eq 60 ]]
    echo "PASS: JARM slot plan help and $count-probe inventory"
fi

