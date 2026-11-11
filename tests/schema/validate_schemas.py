#!/usr/bin/env python3
"""Validate Xtate JSON contracts against fixtures and real NDJSON results."""
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("SKIP: pip install jsonschema", file=sys.stderr)
    sys.exit(0)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"
HERE = Path(__file__).resolve().parent
NAMES = ["module", "scan-request", "result", "error"]

def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def main():
    validators = {}
    for name in NAMES:
        schema = load(SCHEMAS / f"{name}.schema.json")
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(schema)

    for name in NAMES:
        for path in sorted((HERE / "valid").glob(f"{name}.json")):
            validators[name].validate(load(path))
        for path in sorted((HERE / "invalid").glob(f"{name}.json")):
            try:
                validators[name].validate(load(path))
            except Exception:
                continue
            raise AssertionError(f"invalid fixture accepted: {path}")

    for path in sorted((HERE / "real-results").glob("*.ndjson")):
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    validators["result"].validate(json.loads(line))
                except Exception as exc:
                    raise AssertionError(f"{path}:{lineno}: {exc}") from exc

    print("json contracts: schema metaschema, fixtures and real NDJSON ok")

if __name__ == "__main__":
    main()
