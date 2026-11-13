#!/usr/bin/env python3
"""Runtime checks for --scan-request: codes, dry-run and closed fields."""
import json, os, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = os.environ.get("XTATE_BIN", str(ROOT / "bin" / "xtate"))
if not Path(BIN).is_file():
    print("SKIP: xtate binary not found", file=sys.stderr)
    sys.exit(0)

base = {"scan":"tcp-state","probe":"doh-h2","targets":["203.0.113.10"],
        "ports":[443],"probe_args":{"dns_name":"example.com"},"dry_run":True}

def run(req, expect_code=None):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(req, f); path = f.name
    try:
        r = subprocess.run([BIN, "--scan-request=" + path], text=True,
                           capture_output=True, timeout=15)
    finally:
        os.unlink(path)
    if expect_code:
        assert r.returncode != 0, r.stdout
        assert f'"code":"{expect_code}"' in r.stderr, r.stderr
    return r

run(base)
run({**base, "targets": []}, "INVALID_ARGUMENT")
run({**base, "bad": 1}, "INVALID_ARGUMENT")
run({**base, "scan": "does-not-exist"}, "UNSUPPORTED_SCAN")
run({**base, "probe": "does-not-exist"}, "UNSUPPORTED_PROBE")
run({**base, "targets": ["not-an-ip"]}, "TARGET_INVALID")

# Deeply nested JSON must be rejected by the parser depth limit, not crash the
# worker with a stack overflow.
deep = ('{"scan":"tcp-syn","targets":["1.1.1.1"],"probe_args":' +
        "[" * 5000 + "]" * 5000 + "}")
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
    f.write(deep); deep_path = f.name
try:
    r = subprocess.run([BIN, "--scan-request=" + deep_path], text=True,
                       capture_output=True, timeout=15)
finally:
    os.unlink(deep_path)
assert r.returncode != 0, r.stdout
assert '"code":"INVALID_JSON"' in r.stderr, r.stderr
print("scan-request runtime: PASS")
