#!/usr/bin/env python3
import json, os, subprocess, sys, tempfile, time
BIN = os.environ["XTATE_BIN"]; TOKEN = "mcp-test-token"
ep = ("\\\\.\\pipe\\xtate-mcp-test-" + str(os.getpid())) if sys.platform == "win32" else os.path.join(tempfile.mkdtemp(), "ctl.sock")
env = dict(os.environ, XTATE_CONTROL_TOKEN=TOKEN)
ctlp = subprocess.Popen([BIN, "--control-plane=" + ep], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)
mp = subprocess.Popen([BIN, "--mcp", "--control-connect=" + ep], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
def rpc(obj):
    mp.stdin.write(json.dumps(obj) + "\n"); mp.stdin.flush()
    line = mp.stdout.readline()
    if not line: raise AssertionError("MCP closed stdout")
    return json.loads(line)
try:
    init = rpc({"jsonrpc":"2.0","id":1,"method":"initialize"})["result"]
    assert init["serverInfo"]["name"] == "xtate"
    assert len(init["instructions"]) > 200
    assert "tools" in init["capabilities"]
    mp.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"})+"\n"); mp.stdin.flush()
    tools = rpc({"jsonrpc":"2.0","id":2,"method":"tools/list"})["result"]["tools"]
    names = {t["name"] for t in tools}
    for n in ["list_modules","describe_probe","explain_target","check","validate_config","start_scan","job_list","job_status","job_result_manifest","job_cancel"]: assert n in names, n
    for t in tools:
        assert t.get("description"); assert "inputSchema" in t
    res = rpc({"jsonrpc":"2.0","id":3,"method":"resources/list"})["result"]["resources"]
    assert any(r["uri"].endswith("/docs/overview") for r in res)
    mods = rpc({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"describe_probe","arguments":{"name":"doh-h2"}}})
    assert not mods["result"]["isError"]
    exp = rpc({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"explain_target","arguments":{"target":"198.18.0.48,8.8.8.8"}}})
    assert not exp["result"]["isError"]
    text = exp["result"]["content"][0]["text"]; assert '"route_groups"' in text and '"groups"' in text
    bad = rpc({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":["127.0.0.1"]}}})
    assert bad["result"]["isError"]
    out = os.path.join(tempfile.mkdtemp(), "mcp.ndjson")
    started = rpc({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":["127.0.0.1"],"ports":[1],"result_path":out,"authorized":True}}})
    assert not started["result"]["isError"], started
    job = json.loads(started["result"]["content"][0]["text"])["result"]["job_id"]
    time.sleep(1)
    st = rpc({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"job_status","arguments":{"job_id":job}}}); assert not st["result"]["isError"]
    man = rpc({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"job_result_manifest","arguments":{"job_id":job}}}); assert not man["result"]["isError"]
    lst = rpc({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"job_list","arguments":{}}}); assert not lst["result"]["isError"]
    mex = rpc({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"explain_target","arguments":{"target":"8.8.8.8,2001:4860:4860::8888"}}})
    rg = json.loads(mex["result"]["content"][0]["text"])["route_groups"]
    if rg > 1:
        mixed = rpc({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":["8.8.8.8","2001:4860:4860::8888"],"result_path":out,"authorized":True}}})
        assert mixed["result"]["isError"]
    print("MCP server tests: PASS")
finally:
    mp.terminate(); ctlp.terminate()
