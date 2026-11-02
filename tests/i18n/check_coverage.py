#!/usr/bin/env python3
"""Check that --lang zh actually translates every help description.

This is intentionally separate from the C self-test: it exercises the shipped
binary and catches a parameter that was added without a catalog entry.

Usage:
    XTATE_BIN=./build/xtate python3 tests/i18n/check_coverage.py
"""

import os
import re
import subprocess
import sys

CJK = re.compile(r"[\u3400-\u9fff]")


def run(binary, *args):
    p = subprocess.run([binary, *args], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    text = p.stdout.decode("utf-8", "replace")
    if p.returncode != 0:
        raise SystemExit("command failed (%d): %s %s\n%s" %
                         (p.returncode, binary, " ".join(args), text))
    return text


def parse_help(text):
    """Return {param_name: description} for one module/global help page."""
    params = {}
    current = None
    lines = []
    for line in text.splitlines():
        m = re.match(r"^  --([^, ]+)", line)
        if m:
            if current:
                params[current] = " ".join(lines)
            current = m.group(1)
            lines = []
            continue
        if current is None:
            continue
        if line.startswith("  --") or line.startswith("===="):
            params[current] = " ".join(lines)
            current = None
            lines = []
            continue
        if line.startswith("      "):
            lines.append(line.strip())
    if current:
        params[current] = " ".join(lines)
    return params


def module_names(binary, kind):
    text = run(binary, "--list-%s" % kind)
    names = []
    for line in text.splitlines():
        m = re.match(r"^  \d+\.(\S+)", line)
        if m:
            names.append(m.group(1))
    return names


def main():
    binary = os.environ.get("XTATE_BIN")
    if not binary:
        binary = os.path.join(os.path.dirname(__file__), "..", "..", "bin",
                              "xtate")
    if not os.path.exists(binary):
        print("SKIP: binary not found: %s" % binary)
        return 0

    missing = []

    globals_ = parse_help(run(binary, "--lang", "zh", "--help"))
    for name, desc in globals_.items():
        if not CJK.search(desc):
            missing.append("global:%s" % name)

    for kind in ("scan", "probe", "out", "gen"):
        for module in module_names(binary, kind):
            text = run(binary, "--lang", "zh", "--help-%s" % kind, module)
            params = parse_help(text)
            for name, desc in params.items():
                if not CJK.search(desc):
                    missing.append("%s:%s:%s" % (kind, module, name))

    if missing:
        print("untranslated help descriptions:")
        for item in missing:
            print("  " + item)
        return 1

    print("PASS: every global and module parameter description is Chinese")
    return 0


if __name__ == "__main__":
    sys.exit(main())
