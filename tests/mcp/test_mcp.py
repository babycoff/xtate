#!/usr/bin/env python3
import json, os, subprocess, sys, tempfile, time
BIN = os.environ["XTATE_BIN"]; TOKEN = "mcp-test-token"
ep = ("\\\\.\\pipe\\xtate-mcp-test-" + str(os.getpid())) if sys.platform == "win32" else os.path.join(tempfile.mkdtemp(), "ctl.sock")
env = dict(os.environ, XTATE_CONTROL_TOKEN=TOKEN)
ctlp = subprocess.Popen([BIN, "--control-plane=" + ep], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)
mp = subprocess.Popen([BIN, "--mcp", "--control-connect=" + ep], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding="utf-8", text=True)
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
    unk = rpc({"jsonrpc":"2.0","id":30,"method":"no/such/method"})
    assert "error" in unk
    mp.stdin.write(json.dumps({"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}})+"\n"); mp.stdin.flush()
    nt = json.loads(mp.stdout.readline()); assert nt["result"]["isError"]
    badargs = rpc({"jsonrpc":"2.0","id":32,"method":"tools/call","params":{"name":"validate_config","arguments":{}}})
    assert badargs["result"]["isError"]
    badjob = rpc({"jsonrpc":"2.0","id":33,"method":"tools/call","params":{"name":"job_status","arguments":{"job_id":"job-nope"}}})
    assert badjob["result"]["isError"]
    badres = rpc({"jsonrpc":"2.0","id":34,"method":"resources/read","params":{"uri":"xtate://nope"}})
    assert "error" in badres
    res = rpc({"jsonrpc":"2.0","id":3,"method":"resources/list"})["result"]["resources"]
    assert any(r["uri"].endswith("/docs/overview") for r in res)
    mods = rpc({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"describe_probe","arguments":{"name":"doh-h2"}}})
    assert not mods["result"]["isError"]
    exp = rpc({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"explain_target","arguments":{"target":"198.18.0.48,8.8.8.8"}}})
    assert not exp["result"]["isError"]
    text = exp["result"]["content"][0]["text"]; assert '"route_groups"' in text and '"groups"' in text
    bad = rpc({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":["127.0.0.1"]}}})
    assert bad["result"]["isError"]
    out = os.environ.get("XTATE_TEST_OUT", "mcp-test.ndjson")
    started = rpc({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":["8.8.8.8"],"ports":[53],"result_path":out,"authorized":True}}})
    assert not started["result"]["isError"], started
    job = json.loads(started["result"]["content"][0]["text"])["result"]["job_id"]
    time.sleep(4)
    st = rpc({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"job_status","arguments":{"job_id":job}}}); assert not st["result"]["isError"]
    stj = json.loads(st["result"]["content"][0]["text"])["result"]
    assert stj["state"] == "completed", stj
    assert stj["exit_code"] == 0
    assert os.path.exists(out)
    assert "log_path" in stj and "stderr_tail" in stj
    man = rpc({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"job_result_manifest","arguments":{"job_id":job}}}); assert not man["result"]["isError"]
    lst = rpc({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"job_list","arguments":{}}}); assert not lst["result"]["isError"]
    mex = rpc({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"explain_target","arguments":{"target":"8.8.8.8,2001:4860:4860::8888"}}})
    rg = json.loads(mex["result"]["content"][0]["text"])["route_groups"]
    if rg > 1:
        mixed = rpc({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":["8.8.8.8","2001:4860:4860::8888"],"result_path":out,"authorized":True}}})
        assert mixed["result"]["isError"]
    rr = rpc({"jsonrpc":"2.0","id":13,"method":"resources/read","params":{"uri":"xtate://docs/overview"}})
    assert rr["result"]["contents"][0]["text"]
    pr = rpc({"jsonrpc":"2.0","id":14,"method":"prompts/get","params":{"name":"plan-safe-scan"}})
    assert pr["result"]["messages"]
    badenv = dict(os.environ, XTATE_CONTROL_TOKEN="wrong-token")
    mp_bad = subprocess.Popen([BIN, "--mcp", "--control-connect=" + ep], env=badenv,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, encoding="utf-8", text=True)
    try:
        mp_bad.stdin.write(json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"job_list","arguments":{}}})+"\n")
        mp_bad.stdin.flush()
        bad = json.loads(mp_bad.stdout.readline())
        assert "UNAUTHORIZED" in bad["result"]["content"][0]["text"]
    finally:
        mp_bad.terminate()
    blocked = "C:/Windows/System32/xtate/mcp.ndjson" if sys.platform == "win32" else "/proc/xtate/mcp.ndjson"
    bw = rpc({"jsonrpc":"2.0","id":35,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":["8.8.8.8"],"result_path":blocked,"authorized":True}}})
    assert bw["result"]["isError"]
    cj = rpc({"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"start_scan","arguments":{
        "scan":"tcp-syn","targets":["127.0.0.1"],"ports":[1],
        "result_path":out,"authorized":True}}})
    cid = json.loads(cj["result"]["content"][0]["text"])["result"]["job_id"]
    cc = rpc({"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"job_cancel","arguments":{"job_id":cid}}})
    assert not cc["result"]["isError"]
    out2 = os.environ.get("XTATE_TEST_CHUNK", "mcp-chunk.ndjson")
    cs = rpc({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"start_scan","arguments":{
        "scan":"tcp-syn","targets":["8.8.8.8"],"ports":[53],
        "result_path":out2,"chunk_size":100,"index":True,"quota_bytes":100000,
        "authorized":True}}})
    assert not cs["result"]["isError"]
    cid2 = json.loads(cs["result"]["content"][0]["text"])["result"]["job_id"]
    time.sleep(1)
    st2 = rpc({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"job_status","arguments":{"job_id":cid2}}})
    st2t = st2["result"]["content"][0]["text"]
    assert "JOB_NOT_FOUND" not in st2t, st2t
    assert not st2["result"]["isError"]
    mm = rpc({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"job_result_manifest","arguments":{"job_id":cid2}}})
    mt = mm["result"]["content"][0]["text"]
    assert "manifest_path" in mt, mt
    stobj = json.loads(st2t)["result"]
    if stobj.get("state") == "completed":
        assert os.path.exists(out2 + ".manifest.json")
    print("MCP server tests: PASS")
finally:
    mp.terminate(); ctlp.terminate()








