#!/usr/bin/env python3
"""Deterministic black-box fuzz for the CLI parameter parser.

It does not scan the network.  It only checks that malformed argument
combinations terminate (success or explicit parser error) without a crash.
"""
import os
import random
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.environ.get("XTATE_BIN", os.path.join(ROOT, "bin", "xtate"))
if not os.path.exists(BIN):
    print("SKIP: executable not found: %s" % BIN, file=sys.stderr)
    raise SystemExit(0)

ALPHABET = [
    "--list-probe", "--list-scan", "--help-probe", "ssh",
    "--rate", "--rate=4x", "--rate:", "--wait", "--wait=abc",
    "--probe-arg", "--scan-arg", "--output-arg", "--gen-arg",
    "--lang", "zh", "en", "nope", "--",
    "-", "--definitely-unknown", "stray",
    "--path=/", "--path=", "--max-frames", "4",
    "'--path=/h2'", '"--path=/space"', "a" * 80, "\\", "\"", "'",
]
rng = random.Random(0x58544154)
for case in range(200):
    argc = rng.randint(1, 6)
    args = [rng.choice(ALPHABET) for _ in range(argc)]
    # Keep the parser path bounded and non-scanning.
    args.append("--list-probe")
    try:
        proc = subprocess.run([BIN] + args, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=3)
    except subprocess.TimeoutExpired:
        print("FAIL: timeout case %d: %r" % (case, args), file=sys.stderr)
        raise SystemExit(1)
    if proc.returncode < 0:
        print("FAIL: crash case %d rc=%d: %r" %
              (case, proc.returncode, args), file=sys.stderr)
        raise SystemExit(1)
print("PASS: parser fuzz (%d cases)" % 200)
