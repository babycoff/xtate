#!/usr/bin/env python3
import json, os, shutil, subprocess, tempfile, time, sys
BIN=os.environ["XTATE_BIN"]; TOKEN="test-token"
if sys.platform=="win32":
    ep="\\\\.\\pipe\\xtate-test-"+str(os.getpid())
else:
    ep=os.path.join(tempfile.mkdtemp(),"ctl.sock")
state_dir=os.path.join(os.getcwd(),"control-test-state")
shutil.rmtree(state_dir,ignore_errors=True); os.makedirs(state_dir,exist_ok=True)
base_env=dict(os.environ,XTATE_CONTROL_TOKEN=TOKEN,XTATE_STATE_DIR=state_dir)
p=subprocess.Popen([BIN,"--control-plane="+ep],env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        if sys.platform!="win32" and os.path.exists(ep): break
        time.sleep(0.1)
    def rpc(obj, token=True):
        e=dict(os.environ)
        if token: e["XTATE_CONTROL_TOKEN"]=TOKEN
        r=subprocess.run([BIN,"--control-connect="+ep,"--control-request="+json.dumps(obj)],env=e,text=True,capture_output=True,timeout=10)
        return r.returncode,json.loads(r.stdout)
    rc,o=rpc({"id":1,"method":"ping"},False); assert o["error"]["code"]=="UNAUTHORIZED"
    rc,o=rpc({"id":2,"method":"ping"}); assert o["result"]["pong"] is True
    rc,o=rpc({"id":3,"method":"job.list"}); assert o["result"]["jobs"]==[]
    req=os.path.join(tempfile.mkdtemp(),"req.json"); res=req+".ndjson"
    open(req,"w").write('{"scan":"tcp-syn","targets":["127.0.0.1"],"ports":[1]}')
    rc,o=rpc({"id":4,"method":"job.start","params":{"scan":"tcp-syn","targets":["127.0.0.1"],"ports":[1],"result_path":res}}); assert "job_id" in o["result"]
    rc,o=rpc({"id":5,"method":"job.list"}); assert o["result"]["jobs"]
    # A nested subprobe value containing spaces must survive the JSON -> argv
    # conversion as one -subprobe-arg token.  dry_run makes this a parsing-only
    # job (--list-target), so it needs no raw-socket privilege.
    nested_res=req+".nested.ndjson"
    rc,o=rpc({"id":6,"method":"job.start","params":{
        "scan":"tcp-state","targets":["127.0.0.1"],"ports":[443],
        "probe":"tls-state",
        "probe_args":{"subprobe":"http-state",
                      "subprobe-arg":"--max-body=4096 --user-agent='a b' "
                                     "--header='X-Test: a\"b'"},
        "dry_run":True,"timeout_sec":20,"result_path":nested_res}})
    assert "job_id" in o.get("result",{}), o
    jid=o["result"]["job_id"]; state=""
    for _ in range(100):
        rc,o=rpc({"id":7,"method":"job.status","job_id":jid})
        state=o["result"]["state"]
        if state in ("completed","failed","cancelled","timed_out"): break
        time.sleep(0.1)
    assert state=="completed", o
    # Rates are positive doubles: fractional and multi-million values must
    # survive JSON -> control request -> worker argv.  dry_run keeps this
    # packet-free and privilege-free.
    for rid, rate in ((60, 0.5), (61, 1000000)):
        rrate=req+".rate%d.ndjson"%rid
        rc,o=rpc({"id":rid,"method":"job.start","params":{
            "scan":"tcp-syn","targets":["127.0.0.1"],"ports":[1],
            "rate":rate,"dry_run":True,"timeout_sec":20,"result_path":rrate}})
        assert "job_id" in o.get("result",{}), o
        rjid=o["result"]["job_id"]; rstate=""
        for _ in range(100):
            rc,o=rpc({"id":rid+1,"method":"job.status","job_id":rjid})
            rstate=o["result"]["state"]
            if rstate in ("completed","failed","cancelled","timed_out"): break
            time.sleep(0.1)
        assert rstate=="completed", o
    print("control plane: PASS")
finally:
    shutil.rmtree(state_dir,ignore_errors=True)
    p.terminate(); p.wait(timeout=5)
