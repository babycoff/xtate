#!/usr/bin/env python3
"""Static contract checks for the Xtate Agent Skill.

This is intentionally independent from the MCP runtime suite: Agent Skills are
installed into third-party hosts, so a stale/renamed tool or a nested
start_scan example is a release-blocking documentation bug even when the server
itself works. The MCP contract tests cover the live JSON-RPC behavior; this file
covers what an agent host actually reads.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKILL = os.path.join(ROOT, "skills", "xtate")
TOOLS = {
    "capabilities", "iface.list", "list_modules", "describe_probe",
    "explain_target", "check", "preflight", "validate_config",
    "start_scan", "job_list", "job_status", "job_result_manifest",
    "job.records", "job_cancel",
}
STALE = {
    "get_scan_status", "get_results", "stop_scan", "scan_status",
    "list_scans", "read_results", "read_scan_results",
}
START_FIELDS = {
    "scan", "probe", "targets", "include_file", "ports", "scan_args",
    "probe_args", "global_args", "rate", "timeout_sec", "result_path",
    "interface", "chunk_size", "quota_bytes", "compression", "index",
    "dry_run", "authorized",
}


def read(rel):
    with open(os.path.join(SKILL, rel), encoding="utf-8") as f:
        return f.read()


def links(text):
    return re.findall(r"\[[^\]]*\]\(([^)]+)\)", text)


def main():
    files = ["SKILL.md", "references/tools.md", "references/safety.md",
             "references/troubleshooting.md"]
    for rel in files:
        assert os.path.isfile(os.path.join(SKILL, rel)), rel
        text = read(rel)
        assert text.strip(), rel
        for target in links(text):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            path = os.path.normpath(os.path.join(SKILL, os.path.dirname(rel), target))
            assert os.path.isfile(path), f"broken link {rel}: {target}"
        for stale in STALE:
            assert stale not in text, f"stale tool {stale} in {rel}"

    skill = read("SKILL.md")
    assert skill.startswith("---\n")
    fm = skill.split("---", 2)[1]
    m_name = re.search(r"^name:\s*([^\s]+)\s*$", fm, re.M)
    m_desc = re.search(r"^description:\s*(.+)$", fm, re.M)
    assert m_name and m_name.group(1) == "xtate"
    assert m_desc and m_desc.group(1).startswith("Use when "), m_desc.group(1) if m_desc else None
    assert "authorized: true" in skill
    assert "job.records" in skill
    assert "include_file" in skill
    assert "route_groups" in skill
    assert "nested under another `arguments`" in skill
    assert "timeout_sec" in skill

    tools_text = read("references/tools.md")
    for name in TOOLS:
        assert f"`{name}`" in tools_text, f"missing tool {name}"
    for name in START_FIELDS:
        assert f"`{name}`" in tools_text, f"missing start field {name}"

    # Every fenced JSON block must parse. This catches stale snippets with
    # comments/trailing ellipses before they reach an agent host.
    all_text = "\n".join(read(rel) for rel in files)
    for block in re.findall(r"```json\n(.*?)```", all_text, re.S):
        try:
            obj = json.loads(block)
        except json.JSONDecodeError as e:
            raise AssertionError(f"invalid JSON fence: {e}\n{block}")
        if isinstance(obj, dict) and "scan" in obj:
            assert "arguments" not in obj, f"nested start_scan example: {obj}"
            assert obj.get("authorized") is True, f"start_scan example not authorized: {obj}"
            assert "timeout_sec" in obj, f"start_scan example missing timeout_sec: {obj}"
            unknown = set(obj) - START_FIELDS
            assert not unknown, f"unknown start_scan fields: {unknown}"
    print("Agent Skill contract tests: PASS")


if __name__ == "__main__":
    main()
