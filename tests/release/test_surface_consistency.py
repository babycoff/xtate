#!/usr/bin/env python3
"""Check that the user-visible CLI, MCP, GUI and documentation surfaces agree.

This is the release gate for the "add one thing, update every surface" rule:

  * module catalogs and counts in the binary vs README and docs/modules.md
  * scan/probe names used by --usage examples
  * the number of global parameters in --help vs docs/help-i18n.md
  * the MCP tool list vs docs/mcp-server.md
  * the GUI HTTP route list vs docs/gui.md

Version consistency has its own gate (test_version_consistency.py); this test
does not repeat it, but it does verify the generated version header carries the
same suffix as CMakeLists.txt so a stale generated header cannot hide.

Run it from the repository root after a build:

    python3 tests/release/test_surface_consistency.py --binary bin/xtate

The test is deliberately read-only: it starts no control plane, opens no
network socket and sends no packets.
"""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Modules that legitimately exist in the full documentation but are absent from
# a Windows / dependency-reduced build.
OPTIONAL_MODULES = {"quic-state", "http3-state"}


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def run(binary, *args):
    return subprocess.check_output(
        [binary, *args], text=True, encoding="utf-8", errors="replace", timeout=60
    )


def parse_version_header():
    hdr = read("src/version.h")
    macros = {}
    for m in re.finditer(r'#define\s+(\w+)\s+(?:"([^"]*)"|(\S+))', hdr):
        macros[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return macros


def check_generated_version():
    cmake = read("CMakeLists.txt")
    m = re.search(r'set\(XTATE_VERSION_SUFFIX\s+"([^"]*)"', cmake)
    assert m, "CMakeLists.txt has no XTATE_VERSION_SUFFIX"
    suffix = m.group(1)
    macros = parse_version_header()
    assert macros.get("XTATE_VERSION_SUFFIX") == suffix, (
        "src/version.h suffix %r is stale; CMake sets %r. Re-run CMake configure."
        % (macros.get("XTATE_VERSION_SUFFIX"), suffix)
    )
    assert macros.get("XTATE_VERSION", "").endswith(suffix), (
        "src/version.h XTATE_VERSION %r does not end with %r"
        % (macros.get("XTATE_VERSION"), suffix)
    )


def capability_counts(binary):
    data = json.loads(run(binary, "--list-capabilities"))
    mods = data["modules"]
    return data, {k: int(mods[k]) for k in ("scan", "probe", "output", "generate")}


def module_names(binary):
    names = {}
    for kind, flag in (
        ("scan", "--list-scan"),
        ("probe", "--list-probe"),
        ("output", "--list-output"),
        ("generate", "--list-gen"),
    ):
        out = run(binary, flag)
        found = re.findall(r"^\s*\d+\.([A-Za-z0-9_.-]+)\s*$", out, re.M)
        assert found, f"{flag} returned no module names"
        names[kind] = found
    return names


def check_module_counts(binary, caps):
    docs = read("docs/modules.md")
    m = re.search(
        r"\*\*(\d+) Scan \+ (\d+) Probe \+ (\d+) Output \+ (\d+) Generate\*\* modules \((\d+) total\)",
        docs,
    )
    assert m, "docs/modules.md full-build count sentence not found"
    full = tuple(int(x) for x in m.groups()[:4])
    assert full == (12, 60, 7, 5), f"docs/modules.md full counts changed unexpectedly: {full}"
    assert int(m.group(5)) == sum(full), "docs/modules.md total is not the sum of its counts"

    m = re.search(r"registers (\d+)/(\d+)/(\d+)/(\d+) \((\d+)\)", docs)
    assert m, "docs/modules.md reduced-build counts not found"
    reduced = tuple(int(x) for x in m.groups()[:4])
    assert reduced == (11, 59, 7, 5), f"docs/modules.md reduced counts changed unexpectedly: {reduced}"
    assert int(m.group(5)) == sum(reduced), "docs/modules.md reduced total is not the sum"

    readme = read("README.md")
    rows = {
        name: (win, linux)
        for name, win, linux in re.findall(
            r"^\|\s*(Scan|Probe|Output|Generate)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", readme, re.M
        )
    }
    assert len(rows) == 4, "README.md module count table is incomplete"
    assert tuple(int(rows[k][0]) for k in ("Scan", "Probe", "Output", "Generate")) == reduced, (
        "README.md Windows module counts disagree with docs/modules.md reduced counts"
    )
    assert tuple(int(rows[k][1]) for k in ("Scan", "Probe", "Output", "Generate")) == full, (
        "README.md full-Linux module counts disagree with docs/modules.md full counts"
    )

    # The binary must be one of the two documented profiles.
    actual = tuple(caps[k] for k in ("scan", "probe", "output", "generate"))
    assert actual == full or actual == reduced, (
        "binary reports %r modules; documentation only describes %r (full) and %r (reduced)"
        % (actual, full, reduced)
    )


def check_module_names(binary_names):
    docs = read("docs/modules.md")
    documented = set(re.findall(r"^\|\s*`([A-Za-z0-9_.-]+)`\s*\|", docs, re.M))
    assert documented, "no module names found in docs/modules.md tables"

    binary = set()
    for kind, names in binary_names.items():
        assert len(names) == len(set(names)), f"duplicate {kind} module names in --list output"
        binary |= set(names)

    missing_from_docs = sorted(binary - documented)
    assert not missing_from_docs, (
        "modules registered in the binary but absent from docs/modules.md: %s"
        % ", ".join(missing_from_docs)
    )

    absent_optional = {n for n in documented - binary if n in OPTIONAL_MODULES}
    unexpected_absent = sorted(documented - binary - OPTIONAL_MODULES)
    assert not unexpected_absent, (
        "docs/modules.md names that are neither built nor documented optional modules: %s"
        % ", ".join(unexpected_absent)
    )
    if absent_optional:
        print(f"surface: optional modules absent from this build: {', '.join(sorted(absent_optional))}")


def check_usage(binary):
    out = run(binary, "--usage")
    scans = set(re.findall(r"-scan\s+([A-Za-z0-9_.-]+)", out))
    probes = set(re.findall(r"-probe\s+([A-Za-z0-9_.-]+)", out))
    # Placeholders from the synopsis and the "list" word after -list-scan are
    # not module names.
    scans -= {"SCANMODULE", "list"}
    probes -= {"PROBEMODULE"}
    assert scans, "--usage has no -scan example"
    assert probes, "--usage has no -probe example"

    known = {}
    for kind, flag in (("scan", "--list-scan"), ("probe", "--list-probe")):
        known[kind] = set(re.findall(r"^\s*\d+\.([A-Za-z0-9_.-]+)\s*$", run(binary, flag), re.M))
    bad = sorted(scans - known["scan"])
    assert not bad, "--usage references unknown scan modules: %s" % ", ".join(bad)
    bad = sorted(probes - known["probe"])
    assert not bad, "--usage references unknown probe modules: %s" % ", ".join(bad)

    # Current entry points that must be discoverable from the usage screen.
    for flag in (
        "check",
        "explain-target",
        "list-if",
        "list-capabilities",
        "mcp",
        "gui",
    ):
        assert ("-" + flag) in out or ("--" + flag) in out, (
            f"--usage does not mention --{flag}"
        )


def check_help_count(binary):
    out = run(binary, "--help")
    m = re.search(r"contains \[(\d+)\] global parameters", out)
    assert m, "--help does not print the global parameter count"
    count = int(m.group(1))
    docs = read("docs/help-i18n.md")
    m = re.search(r"all (\d+) global parameter descriptions", docs)
    assert m, "docs/help-i18n.md does not state the global parameter count"
    assert int(m.group(1)) == count, (
        "docs/help-i18n.md says %s parameters, --help reports %s" % (m.group(1), count)
    )


def check_mcp_tools():
    source = read("src/util-scan/mcp-server.c")
    start = source.index("static const char *tools_json")
    end = source.index('"]}"', start) + 3
    block = source[start:end]
    tools = set(re.findall(r'\\"name\\":\\"([A-Za-z0-9_.-]+)\\"', block))
    assert len(tools) >= 10, "could not parse MCP tool list from mcp-server.c"

    docs = read("docs/mcp-server.md")
    section = docs.split("## Tools", 1)
    assert len(section) == 2, "docs/mcp-server.md has no ## Tools section"
    section = section[1].split("\n## ", 1)[0]
    documented = set(re.findall(r"^\|\s*`([A-Za-z0-9_.-]+)`\s*\|", section, re.M))
    assert documented, "docs/mcp-server.md Tools table has no tool names"

    assert tools == documented, (
        "MCP tool surface drift: source-only=%s docs-only=%s"
        % (sorted(tools - documented), sorted(documented - tools))
    )


def check_gui_routes():
    source = read("src/util-scan/gui.c")
    routes = set(re.findall(r'strcmp\(path,\s*"(/api/[A-Za-z0-9_./-]+)"\)', source))
    assert routes, "could not parse GUI API routes from gui.c"
    docs = read("docs/gui.md")
    missing = sorted(r for r in routes if r not in docs)
    assert not missing, "GUI routes not documented in docs/gui.md: %s" % ", ".join(missing)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--binary",
        default=os.environ.get("XTATE_BIN", os.path.join(ROOT, "bin", "xtate")),
    )
    args = ap.parse_args()
    binary = args.binary
    if not os.path.exists(binary) and os.path.exists(binary + ".exe"):
        binary += ".exe"
    if not os.path.exists(binary):
        print(f"surface consistency: SKIP (binary not found: {binary})")
        return 0

    check_generated_version()
    data, caps = capability_counts(binary)
    check_module_counts(binary, caps)
    names = module_names(binary)
    check_module_names(names)
    check_usage(binary)
    check_help_count(binary)
    check_mcp_tools()
    check_gui_routes()

    print(
        "surface consistency: PASS (version %s, modules %d/%d/%d/%d)"
        % (
            data.get("version", "?"),
            caps["scan"],
            caps["probe"],
            caps["output"],
            caps["generate"],
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
