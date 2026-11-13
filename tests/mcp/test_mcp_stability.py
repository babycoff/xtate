#!/usr/bin/env python3
import json, os, shutil, subprocess, sys, tempfile, time
BIN = os.environ["XTATE_BIN"]; TOKEN = "mcp-stab-token"
ep = ("\\\\.\\pipe\\xtate-mcp-stab-" + str(os.getpid())) if sys.platform == "win32" else os.path.join(tempfile.mkdtemp(), "ctl.sock")
state_dir = os.path.join(os.getcwd(), "mcp-stab-state")
shutil.rmtree(state_dir, ignore_errors=True)
os.makedirs(state_dir, exist_ok=True)
env = dict(os.environ, XTATE_CONTROL_TOKEN=TOKEN, XTATE_STATE_DIR=state_dir)
def start_ctl():
    p = subprocess.Popen([BIN, "--control-plane=" + ep], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1); return p
ctl = start_ctl()
mp = subprocess.Popen([BIN, "--mcp", "--control-connect=" + ep], env=env,
                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                      stderr=subprocess.DEVNULL, encoding="utf-8", text=True)
def rpc(obj):
    mp.stdin.write(json.dumps(obj) + "\n"); mp.stdin.flush()
    line = mp.stdout.readline()
    assert line, "MCP closed stdout"
    return json.loads(line)
def call(name, args):
    return rpc({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}})["result"]
def text(r): return r["content"][0]["text"]
try:
    rpc({"jsonrpc":"2.0","id":1,"method":"initialize"})
    out = os.environ.get("XTATE_TEST_OUT", "stab.ndjson")
    longargs = {"scan":"tcp-syn","targets":["1.1.1.1","8.8.8.8"],
                "ports":list(range(1,201)),"rate":1,
                "result_path":out+".timeout.ndjson","timeout_sec":1,"authorized":True}
    tr = call("start_scan", longargs); assert not tr["isError"], tr
    tid = json.loads(text(tr))["result"]["job_id"]
    time.sleep(5)
    ts = json.loads(text(call("job_status", {"job_id":tid})))["result"]
    assert ts["state"] in ("timed_out","cancelled","failed"), ts
    cargs = dict(longargs); cargs["result_path"] = out+".cancel.ndjson"; cargs["timeout_sec"] = 60
    cr = call("start_scan", cargs); assert not cr["isError"], cr
    cid = json.loads(text(cr))["result"]["job_id"]
    cc = call("job_cancel", {"job_id":cid}); assert not cc["isError"]
    time.sleep(2)
    cs = json.loads(text(call("job_status", {"job_id":cid})))["result"]
    assert cs["state"] in ("cancelled","completed","failed","timed_out"), cs
    for i in range(5): call("job_list", {"offset":0,"limit":10})
    targets = ["10.%d.%d.%d" % (i//65536%256, i//256%256, i%256) for i in range(100)]
    v = call("validate_config", {"config":{"scan":"tcp-syn","targets":targets}})
    assert not v["isError"], v
    assert json.loads(text(v))["valid"] is True
    bigfile = out + ".targets.txt"
    with open(bigfile, "w", encoding="utf-8") as f:
        for i in range(2000):
            f.write("10.%d.%d.%d\n" % (i//65536%256, i//256%256, i%256))
    bv = call("validate_config", {"config":{"scan":"tcp-syn","include_file":bigfile}})
    assert not bv["isError"], bv
    assert json.loads(text(bv))["valid"] is True
    ex = json.loads(text(call("explain_target", {"target":"8.8.8.8"})))
    iface = ex["groups"][0]["interface"]
    fr = call("start_scan", {"scan":"tcp-syn","include_file":bigfile,
                             "ports":[53],"rate":10000,"interface":iface,
                             "result_path":out+".large.ndjson","timeout_sec":2,
                             "authorized":True})
    assert not fr["isError"], fr
    mp.stdin.write('{"jsonrpc":"2.0"\n'); mp.stdin.flush()
    line = mp.stdout.readline(); assert line
    json.loads(line)
    if sys.platform == "win32":
        ctl.terminate(); ctl.wait(timeout=5)
        ctl = start_ctl()
        jl = call("job_list", {}); assert not jl["isError"], jl
    mp2 = subprocess.Popen([BIN, "--mcp", "--control-connect=" + ep], env=env,
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, encoding="utf-8", text=True)
    try:
        mp2.stdin.write(json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"job_list","arguments":{}}})+"\n")
        mp2.stdin.flush()
        r2 = json.loads(mp2.stdout.readline())
        assert "result" in r2
    finally:
        mp2.terminate()
    print("MCP stability tests: PASS")
finally:
    shutil.rmtree(state_dir, ignore_errors=True)
    mp.terminate(); ctl.terminate()
