#!/usr/bin/env python3
"""Validate --list-modules-json against module.schema.json and coverage rules."""
import json, os, subprocess, sys
from pathlib import Path
from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BIN = os.environ.get("XTATE_BIN", str(ROOT / "bin" / "xtate"))
if not Path(BIN).is_file():
    print("SKIP: xtate binary not found", file=sys.stderr)
    sys.exit(0)
out = subprocess.check_output([BIN, "--list-modules-json"], text=True)
data = json.loads(out)
schema = json.loads((ROOT / "schemas/module.schema.json").read_text(encoding="utf-8"))
v = Draft202012Validator(schema)
seen = set()
kinds = {"scan": 0, "probe": 0, "output": 0, "generate": 0}
for m in data["modules"]:
    v.validate(m)
    key = (m["kind"], m["name"])
    assert key not in seen, f"duplicate module {key}"
    seen.add(key)
    kinds[m["kind"]] += 1
    for p in m.get("parameters") or []:
        assert p["name"], m["name"]
        assert p["type"] in ("flag", "arg")
print("module json:", len(data["modules"]), kinds)
