#!/usr/bin/env python3
"""MCP protocol/contract tests that are independent of the broad integration suite.

These tests focus on the things an Agent Skill depends on:
  * tools/list schemas match the documented flat/`config` shapes
  * JSON-RPC framing survives invalid input and partial writes
  * array/string preflight normalization
  * unknown fields and nested start_scan are rejected by the contract, not by
    the authorization check
  * control tokens are JSON-escaped (quotes/backslashes)
  * read-only `check` really reaches the check path, and missing targets fail
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

BIN = os.environ["XTATE_BIN"]
TARGET = "127.0.0.1" if os.name == "nt" else "203.0.113.1"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATE = os.path.join(ROOT, "mcp-contract-state")
EP = ("\\\\.\\pipe\\xtate-mcp-contract-" + str(os.getpid())) if os.name == "nt" else os.path.join(tempfile.mkdtemp(), "ctl.sock")


def start_control(token, endpoint, state):
    env = dict(os.environ, XTATE_CONTROL_TOKEN=token, XTATE_STATE_DIR=state)
    p = subprocess.Popen([BIN, "--control-plane=" + endpoint], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    return p


def start_mcp(token, endpoint, state, extra_env=None):
    env = dict(os.environ, XTATE_CONTROL_TOKEN=token, XTATE_STATE_DIR=state)
    if extra_env:
        env.update(extra_env)
    p = subprocess.Popen([BIN, "--mcp", "--control-connect=" + endpoint], env=env,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
    return p


def rpc(p, obj):
    p.stdin.write(json.dumps(obj, ensure_ascii=False) + "\n")
    p.stdin.flush()
    line = p.stdout.readline()
    assert line, "MCP closed stdout"
    return json.loads(line)


def call(p, name, args, rid=1):
    return rpc(p, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                   "params": {"name": name, "arguments": args}})


def text(result):
    return result["result"]["content"][0]["text"]


def main():
    shutil.rmtree(STATE, ignore_errors=True)
    os.makedirs(STATE, exist_ok=True)
    token = "contract-token"
    ctl = start_control(token, EP, STATE)
    mp = start_mcp(token, EP, STATE)
    try:
        init = rpc(mp, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})["result"]
        assert init["protocolVersion"] == "2024-11-05"
        assert init["serverInfo"]["name"] == "xtate"
        assert "instructions" in init and len(init["instructions"]) > 100

        ping = rpc(mp, {"jsonrpc": "2.0", "id": "p", "method": "ping"})
        assert ping["id"] == "p" and ping["result"] == {}

        tools = rpc(mp, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        names = {t["name"] for t in tools}
        expected = {"capabilities", "iface.list", "list_modules", "describe_probe",
                    "explain_target", "check", "preflight", "validate_config",
                    "start_scan", "job_list", "job_status", "job_result_manifest",
                    "job.records", "job_cancel"}
        assert names == expected, (names, expected)
        by_name = {t["name"]: t for t in tools}
        start_schema = by_name["start_scan"]["inputSchema"]
        assert "arguments" not in start_schema.get("properties", {})
        assert set(start_schema.get("required", [])) == {"scan", "authorized"}
        assert "target" in by_name["check"]["inputSchema"].get("required", [])
        for t in tools:
            assert t.get("description")
            assert isinstance(t.get("inputSchema"), dict)
            assert isinstance(t.get("annotations"), dict)

        # A malformed line must not kill the server; the next valid request works.
        mp.stdin.write('{"jsonrpc":"2.0"\n')
        mp.stdin.flush()
        bad = json.loads(mp.stdout.readline())
        assert "error" in bad
        assert rpc(mp, {"jsonrpc": "2.0", "id": 3, "method": "ping"})["result"] == {}

        # Two requests in one write and a split write both stay framed.
        mp.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "ping"}) + "\n" +
                       json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"}) + "\n")
        mp.stdin.flush()
        assert json.loads(mp.stdout.readline())["id"] == 4
        assert json.loads(mp.stdout.readline())["id"] == 5
        part = json.dumps({"jsonrpc": "2.0", "id": 6, "method": "ping"})
        mp.stdin.write(part[:12]); mp.stdin.flush(); time.sleep(0.1)
        mp.stdin.write(part[12:] + "\n"); mp.stdin.flush()
        assert json.loads(mp.stdout.readline())["id"] == 6

        # Tool argument/contract errors must be stable and actionable.
        missing = call(mp, "explain_target", {}, 10)
        assert missing["result"]["isError"]
        assert "target is required" in text(missing)
        chk = call(mp, "check", {"target": TARGET}, 11)
        assert not chk["result"]["isError"], chk
        assert '"route_groups"' in text(chk), text(chk)

        # preflight accepts both forms and rejects unknown fields/include_file.
        a = call(mp, "preflight", {"config": {"scan": "tcp-syn", "targets": TARGET, "ports": "1"}}, 12)
        b = call(mp, "preflight", {"config": {"scan": "tcp-syn", "targets": [TARGET], "ports": [1]}}, 13)
        assert not a["result"]["isError"] and not b["result"]["isError"]
        aj, bj = json.loads(text(a)), json.loads(text(b))
        assert aj["ok"] and bj["ok"]
        assert (aj["targets"], aj["ports"]) == (bj["targets"], bj["ports"]) == (1, 1)
        badfield = call(mp, "preflight", {"config": {"scan": "tcp-syn", "targets": TARGET,
                                                     "bogus": 1}}, 14)
        assert json.loads(text(badfield))["ok"] is False
        inc = call(mp, "preflight", {"config": {"scan": "tcp-syn", "include_file": "targets.txt"}}, 15)
        assert json.loads(text(inc))["ok"] is False
        assert "include_file" in text(inc)

        # validate_config/start_scan reject unknown fields; nested arguments is
        # a contract error (unknown field), not an authorization error.
        v = call(mp, "validate_config", {"config": {"scan": "tcp-syn", "targets": [TARGET],
                                                     "nope": True}}, 16)
        assert v["result"]["isError"] and "unknown field" in text(v).lower()
        nested = call(mp, "start_scan", {"arguments": {"scan": "tcp-syn",
                                                       "targets": [TARGET],
                                                       "authorized": True}}, 17)
        assert nested["result"]["isError"]
        assert "unknown field: arguments" in text(nested), text(nested)
        noauth = call(mp, "start_scan", {"scan": "tcp-syn", "targets": [TARGET],
                                         "ports": [1]}, 18)
        assert noauth["result"]["isError"] and "authorization" in text(noauth).lower()
        badrec = call(mp, "job.records", {"job_id": "job-nope"}, 19)
        assert badrec["result"]["isError"]

        # Oversize tools/call is rejected before parsing and does not wedge stdin.
        oversized = "x" * 9000
        big = call(mp, "validate_config", {"config": {"scan": "tcp-syn",
                                                      "targets": [oversized]}}, 20)
        assert big["result"]["isError"] and "too large" in text(big).lower(), big
        assert rpc(mp, {"jsonrpc": "2.0", "id": 21, "method": "ping"})["result"] == {}
    finally:
        try:
            mp.terminate()
        except Exception:
            pass
        ctl.terminate()
        ctl.wait(timeout=5)
        shutil.rmtree(STATE, ignore_errors=True)

    # The control token is attacker/user-controlled in local setups. Quotes and
    # backslashes must be JSON-escaped, not pasted into the control request.
    special = 'tok"en\\with\\slashes'
    ep2 = ("\\\\.\\pipe\\xtate-mcp-contract-token-" + str(os.getpid())) if os.name == "nt" else os.path.join(tempfile.mkdtemp(), "ctl.sock")
    st2 = os.path.join(ROOT, "mcp-contract-token-state")
    shutil.rmtree(st2, ignore_errors=True); os.makedirs(st2, exist_ok=True)
    ctl2 = start_control(special, ep2, st2)
    mp2 = start_mcp(special, ep2, st2)
    try:
        rpc(mp2, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        jl = call(mp2, "job_list", {}, 2)
        assert not jl["result"]["isError"], jl
    finally:
        mp2.terminate(); ctl2.terminate()
        try:
            ctl2.wait(timeout=5)
        except Exception:
            pass
        shutil.rmtree(st2, ignore_errors=True)

    print("MCP contract tests: PASS")


if __name__ == "__main__":
    main()
