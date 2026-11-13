#!/usr/bin/env python3
import json, os, subprocess, sys, tempfile, time
BIN = os.environ["XTATE_BIN"]; TOKEN = "mcp-test-token"
# Linux loopback has no MAC address; TEST-NET-3 routes through the normal interface.
SCAN_TARGET = "127.0.0.1" if os.name == "nt" else "203.0.113.1"
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
    vernoise = subprocess.check_output([BIN, "--version"], text=True, encoding="utf-8", errors="replace")
    assert init["serverInfo"]["version"] in vernoise, (init["serverInfo"], vernoise)
    assert len(init["instructions"]) > 200
    assert "tools" in init["capabilities"]
    mp.stdin.write(json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"})+"\n"); mp.stdin.flush()
    tools = rpc({"jsonrpc":"2.0","id":2,"method":"tools/list"})["result"]["tools"]
    names = {t["name"] for t in tools}
    for n in ["capabilities","list_modules","describe_probe","explain_target","check","preflight","validate_config","start_scan","job_list","job_status","job_result_manifest","job_cancel"]: assert n in names, n
    caps = rpc({"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"capabilities","arguments":{}}})
    assert not caps["result"]["isError"]
    ctext = caps["result"]["content"][0]["text"]
    assert '"modules"' in ctext and '"version"' in ctext, ctext[:200]
    pf = rpc({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"preflight","arguments":{"config":{"scan":"tcp-syn","targets":SCAN_TARGET,"ports":"1"}}}})
    assert not pf["result"]["isError"], pf
    pfj = json.loads(pf["result"]["content"][0]["text"])
    assert pfj["ok"] is True and pfj["targets"] == 1 and pfj["ports"] == 1, pfj
    pfbad = rpc({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"preflight","arguments":{"config":{"scan":"tcp-syn","targets":SCAN_TARGET,"ports":"U:53"}}}})
    assert not pfbad["result"]["isError"]
    assert json.loads(pfbad["result"]["content"][0]["text"])["ok"] is False
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
    traversal = rpc({"jsonrpc":"2.0","id":35,"method":"resources/read","params":{"uri":"xtate://docs/../README.md"}})
    assert "error" in traversal
    schema = rpc({"jsonrpc":"2.0","id":36,"method":"resources/read","params":{"uri":"xtate://schemas/scan-request"}})
    sc = schema["result"]["contents"][0]
    assert sc["mimeType"] == "application/json", sc
    assert "\"$schema\"" in sc["text"], sc["text"][:80]
    res = rpc({"jsonrpc":"2.0","id":3,"method":"resources/list"})["result"]["resources"]
    assert any(r["uri"].endswith("/docs/overview") for r in res)
    mods = rpc({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"describe_probe","arguments":{"name":"doh-h2"}}})
    assert not mods["result"]["isError"]
    exp = rpc({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"explain_target","arguments":{"target":"198.18.0.48,8.8.8.8"}}})
    assert not exp["result"]["isError"]
    text = exp["result"]["content"][0]["text"]; assert '"route_groups"' in text and '"groups"' in text
    bad = rpc({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":[SCAN_TARGET]}}})
    assert bad["result"]["isError"]
    out = os.environ.get("XTATE_TEST_OUT", "mcp-test.ndjson")
    started = rpc({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":[SCAN_TARGET],"ports":[1],"rate":1500,"result_path":out,"authorized":True}}})
    assert not started["result"]["isError"], started
    job = json.loads(started["result"]["content"][0]["text"])["result"]["job_id"]
    time.sleep(4)
    st = rpc({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"job_status","arguments":{"job_id":job}}}); assert not st["result"]["isError"]
    stj = json.loads(st["result"]["content"][0]["text"])["result"]
    assert stj["state"] == "completed", stj
    assert stj["exit_code"] == 0
    assert os.path.exists(out)
    assert "log_path" in stj and "stderr_tail" in stj
    with open(stj["log_path"], encoding="utf-8", errors="replace") as lf:
        log_text = lf.read()
    assert "Rate:       1500 packets/sec" in log_text, log_text[:400]
    man = rpc({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"job_result_manifest","arguments":{"job_id":job}}}); assert not man["result"]["isError"]
    lst = rpc({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"job_list","arguments":{}}}); assert not lst["result"]["isError"]
    mex = rpc({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"explain_target","arguments":{"target":"8.8.8.8,2001:4860:4860::8888"}}})
    rg = json.loads(mex["result"]["content"][0]["text"])["route_groups"]
    if rg > 1:
        mixed = rpc({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"start_scan","arguments":{"scan":"tcp-syn","targets":["8.8.8.8","2001:4860:4860::8888"],"result_path":out,"authorized":True}}})
        assert mixed["result"]["isError"]
    rr = rpc({"jsonrpc":"2.0","id":13,"method":"resources/read","params":{"uri":"xtate://docs/overview"}})
    assert rr["result"]["contents"][0]["text"]
    other = tempfile.mkdtemp()
    detached = subprocess.run([BIN, "--mcp"], cwd=other, text=True, timeout=20,
        encoding="utf-8", errors="replace",
        input=json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize"})+"\n"+
              json.dumps({"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"xtate://docs/overview"}})+"\n",
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert detached.stdout.strip(), "MCP produced no output from a different cwd"
    assert "contents" in detached.stdout, "MCP resources depend on the working directory"
    pr = rpc({"jsonrpc":"2.0","id":14,"method":"prompts/get","params":{"name":"plan-safe-scan"}})
    assert pr["result"]["messages"]
    badprompt = rpc({"jsonrpc":"2.0","id":15,"method":"prompts/get","params":{"name":"no-such-prompt"}})
    assert "error" in badprompt
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
        "scan":"tcp-syn","targets":[SCAN_TARGET],"ports":[1],
        "result_path":out,"authorized":True}}})
    cid = json.loads(cj["result"]["content"][0]["text"])["result"]["job_id"]
    cc = rpc({"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"job_cancel","arguments":{"job_id":cid}}})
    assert not cc["result"]["isError"]
    out2 = os.environ.get("XTATE_TEST_CHUNK", "mcp-chunk.ndjson")
    cs = rpc({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"start_scan","arguments":{
        "scan":"tcp-syn","targets":[SCAN_TARGET],"ports":[1],
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
    base = os.environ.get("XTATE_TEST_DIR", ".")
    udir = os.path.join(base, "P1 测试")
    os.makedirs(udir, exist_ok=True)
    uout = os.path.join(udir, "scan file.ndjson")
    ur = rpc({"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"start_scan","arguments":{
        "scan":"tcp-syn","targets":[SCAN_TARGET],"ports":[1],
        "result_path":uout,"authorized":True}}})
    assert not ur["result"]["isError"], ur
    ujid = json.loads(ur["result"]["content"][0]["text"])["result"]["job_id"]
    time.sleep(4)
    ust = rpc({"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"job_status","arguments":{"job_id":ujid}}})
    ustj = json.loads(ust["result"]["content"][0]["text"])["result"]
    assert ustj["state"] == "completed", ustj
    assert os.path.exists(uout)
    noenv = {k: v for k, v in os.environ.items() if k != "XTATE_CONTROL_TOKEN"}
    mp_nt = subprocess.Popen([BIN, "--mcp", "--control-connect=" + ep], env=noenv,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, encoding="utf-8", text=True)
    try:
        mp_nt.stdin.write(json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"job_list","arguments":{}}})+"\n")
        mp_nt.stdin.flush()
        ntr = json.loads(mp_nt.stdout.readline())
        assert ntr["result"]["isError"]
        assert "UNAUTHORIZED" in ntr["result"]["content"][0]["text"]
    finally:
        mp_nt.terminate()
    c1 = rpc({"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"start_scan","arguments":{
        "scan":"tcp-syn","targets":[SCAN_TARGET],"ports":[1],
        "result_path":out + ".c1.ndjson","authorized":True}}})
    c2 = rpc({"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"start_scan","arguments":{
        "scan":"tcp-syn","targets":[SCAN_TARGET],"ports":[1],
        "result_path":out + ".c2.ndjson","authorized":True}}})
    assert not c1["result"]["isError"] and not c2["result"]["isError"]
    j1 = json.loads(c1["result"]["content"][0]["text"])["result"]["job_id"]
    j2 = json.loads(c2["result"]["content"][0]["text"])["result"]["job_id"]
    time.sleep(5)
    for jid in (j1, j2):
        stx = rpc({"jsonrpc":"2.0","id":44,"method":"tools/call","params":{"name":"job_status","arguments":{"job_id":jid}}})
        assert json.loads(stx["result"]["content"][0]["text"])["result"]["state"] == "completed"
    p1 = rpc({"jsonrpc":"2.0","id":45,"method":"tools/call","params":{"name":"job_list","arguments":{"offset":0,"limit":1}}})
    assert not p1["result"]["isError"]
    pl = json.loads(p1["result"]["content"][0]["text"])
    assert "result" in pl
    print("MCP server tests: PASS")
finally:
    mp.terminate(); ctlp.terminate()









