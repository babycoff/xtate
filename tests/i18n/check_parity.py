#!/usr/bin/env python3
"""Structural English/Chinese help parity checks.

This cannot judge translation quality, but it catches the common failure mode:
a Chinese help page falling back to English, a missing module description, or a
parameter whose Chinese text is missing/suspiciously short. Pair it with a
human review when adding a parameter; see docs/help-i18n.md.
"""
import os
import re
import subprocess
import sys

CJK = re.compile(r"[\u3400-\u9fff]")
BIN = os.environ.get("XTATE_BIN", os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "bin", "xtate"))


def run(*args):
    p = subprocess.run([BIN, *args], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    text = p.stdout.decode("utf-8", "replace")
    if p.returncode != 0:
        raise SystemExit("command failed (%d): %s %s\n%s" %
                         (p.returncode, BIN, " ".join(args), text))
    return text


def parse_help(text):
    desc = []
    params = {}
    current = None
    lines = []
    in_desc = False
    for line in text.splitlines():
        if re.match(r"^\s+(描述：|Description:)", line):
            in_desc = True
            continue
        if in_desc:
            if re.match(r"^  --", line):
                in_desc = False
            else:
                desc.append(line.strip())
        m = re.match(r"^  --([^, ]+)", line)
        if m:
            if current:
                params[current] = " ".join(lines)
            current = m.group(1)
            lines = []
            continue
        if current is not None:
            if line.startswith("  --") or line.startswith("===="):
                params[current] = " ".join(lines)
                current = None
                lines = []
            elif line.startswith("      "):
                lines.append(line.strip())
    if current:
        params[current] = " ".join(lines)
    return " ".join(desc), params


def module_names(kind):
    names = []
    for line in run("--list-" + kind).splitlines():
        m = re.match(r"^\s*\d+\.(\S+)", line)
        if m:
            names.append(m.group(1))
    return names


def main():
    if not os.path.exists(BIN):
        print("SKIP: binary not found: %s" % BIN, file=sys.stderr)
        return 0

    errors = []
    for kind, flag in (("scan", "--help-scan"), ("probe", "--help-probe"),
                       ("out", "--help-output"), ("gen", "--help-gen")):
        for name in module_names(kind):
            en_desc, en_params = parse_help(run(flag, name))
            zh_desc, zh_params = parse_help(
                run("--lang", "zh", flag, name))
            label = "%s:%s" % (kind, name)
            if en_desc and (not CJK.search(zh_desc) or len(zh_desc) < 20):
                errors.append("%s: module description is not detailed Chinese "
                              "(en=%d zh=%d)" %
                              (label, len(en_desc), len(zh_desc)))
            for pname, en_text in en_params.items():
                zh_text = zh_params.get(pname, "")
                if not CJK.search(zh_text):
                    errors.append("%s:%s: missing Chinese parameter help" %
                                  (label, pname))
                elif len(en_text) > 100 and len(zh_text) < 20:
                    errors.append("%s:%s: Chinese help is too short "
                                  "(en=%d zh=%d)" %
                                  (label, pname, len(en_text), len(zh_text)))

    en_desc, en_params = parse_help(run("--help"))
    zh_desc, zh_params = parse_help(run("--lang", "zh", "--help"))
    for pname, en_text in en_params.items():
        if pname == "Alvin":  # contact block, not a parameter
            continue
        zh_text = zh_params.get(pname, "")
        if not CJK.search(zh_text):
            errors.append("global:%s: missing Chinese parameter help" % pname)
        elif len(en_text) > 100 and len(zh_text) < 20:
            errors.append("global:%s: Chinese help is too short (en=%d zh=%d)" %
                          (pname, len(en_text), len(zh_text)))

    if errors:
        print("FAIL: English/Chinese help parity", file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        return 1
    print("PASS: English/Chinese help parity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
