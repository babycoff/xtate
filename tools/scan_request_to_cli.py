#!/usr/bin/env python3
"""Translate a validated Xtate scan-request JSON object into CLI arguments.

This is the reference adapter for agents/MCP. It never invokes a shell.
"""
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("pip install jsonschema", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/scan-request.schema.json").read_text())

def build(req):
    Draft202012Validator(SCHEMA).validate(req)
    if req.get("dry_run", True) is not False:
        # still build the argv; the caller must not execute it without confirmation
        pass
    argv = ["-scan", req["scan"], "-ip", ",".join(req["targets"])]
    if req.get("probe"):
        argv += ["-probe", req["probe"]]
    if req.get("ports"):
        argv += ["-p", ",".join(str(p) for p in req["ports"])]
    if req.get("rate"):
        argv += ["-rate", str(req["rate"])]
    if req.get("probe_args"):
        argv += ["-probe-arg", " ".join(f"--{k.replace(chr(95), chr(45))}={v}" for k, v in req["probe_args"].items())]
    if req.get("scan_args"):
        argv += ["-scan-arg", " ".join(f"--{k.replace(chr(95), chr(45))}={v}" for k, v in req["scan_args"].items())]
    return argv

if __name__ == "__main__":
    req = json.load(sys.stdin)
    print(json.dumps(build(req)))
