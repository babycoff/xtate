#!/usr/bin/env python3
"""Check that the public version is consistent across the release surfaces.

Surfaces checked:
  * CMake project version + XTATE_VERSION_SUFFIX
  * generated src/version.h
  * the built binary (--version and MCP initialize serverInfo.version)
  * root README badge and docs index banners (unless --skip-docs)

This is intentionally a release-gate test, not a build-time generator: it must
fail loudly if the version is bumped in one place only.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def expected_version():
    cmake = read("CMakeLists.txt")
    m = re.search(r"project\(\s*xtate\b.*?\bVERSION\s+([0-9]+(?:\.[0-9]+)*)", cmake, re.S)
    assert m, "CMake project version not found"
    base = m.group(1)
    m = re.search(r'set\(XTATE_VERSION_SUFFIX\s+"([^"]*)"', cmake)
    assert m, "XTATE_VERSION_SUFFIX not found"
    return base + m.group(1)


def check_version_header(expected):
    hdr = read("src/version.h")
    macros = {}
    for m in re.finditer(r'#define\s+(\w+)\s+(?:"([^"]*)"|(\S+))', hdr):
        macros[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    assert macros.get("XTATE_VERSION") == expected, (
        f"src/version.h XTATE_VERSION={macros.get('XTATE_VERSION')!r}, expected {expected!r}")
    assert macros.get("XTATE_WITH_VERSION") == "xtate/" + expected, (
        f"XTATE_WITH_VERSION={macros.get('XTATE_WITH_VERSION')!r}")
    return macros


def check_binary(binary, expected):
    out = subprocess.check_output([binary, "--version"], text=True, encoding="utf-8", errors="replace")
    m = re.search(r"Xtate version ([^\s]+) in", out)
    assert m, f"cannot parse --version output: {out!r}"
    assert m.group(1) == expected, f"binary version {m.group(1)!r}, expected {expected!r}"


def check_mcp(binary, expected):
    """Start --mcp in private mode and verify initialize.serverInfo.version."""
    state = tempfile.mkdtemp(prefix="xtate-version-")
    env = dict(os.environ, XTATE_STATE_DIR=state)
    p = subprocess.Popen(
        [binary, "--mcp"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8", env=env,
    )
    try:
        assert p.stdin and p.stdout
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
        p.stdin.flush()
        line = p.stdout.readline()
        assert line, "MCP server closed stdout during initialize"
        msg = json.loads(line)
        got = msg["result"]["serverInfo"]["version"]
        assert got == expected, f"MCP serverInfo.version {got!r}, expected {expected!r}"
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)


def check_docs(expected):
    checks = [
        # Shields escapes a literal hyphen as "--" in a static badge URL.
        ("README.md", r"badge/version-([0-9][^?\"-]*(?:(?:--|-)[^?\"-]+)*)-"),
        ("README.zh-CN.md", r"badge/version-([0-9][^?\"-]*(?:(?:--|-)[^?\"-]+)*)-"),
        ("docs/README.md", r"\*\*Xtate v([0-9][^\s*]+)\*\*"),
        ("docs/zh-CN/README.md", r"\*\*Xtate v([0-9][^\s*]+)\*\*"),
    ]
    for path, pattern in checks:
        text = read(path)
        m = re.search(pattern, text)
        assert m, f"no version banner found in {path} with {pattern!r}"
        got = m.group(1).replace("--", "-")
        assert got == expected, f"{path} version banner {got!r}, expected {expected!r}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--binary",
        default=os.environ.get("XTATE_BIN", os.path.join(ROOT, "bin", "xtate")),
    )
    ap.add_argument("--skip-docs", action="store_true", help="skip README/docs banner checks")
    ap.add_argument("--skip-mcp", action="store_true", help="skip MCP serverInfo.version check")
    args = ap.parse_args()

    expected = expected_version()
    check_version_header(expected)
    check_binary(args.binary, expected)
    if not args.skip_mcp:
        check_mcp(args.binary, expected)
    if not args.skip_docs:
        check_docs(expected)
    print(f"version consistency: PASS ({expected})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
