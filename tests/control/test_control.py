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
    print("control plane: PASS")
finally:
    shutil.rmtree(state_dir,ignore_errors=True)
    p.terminate(); p.wait(timeout=5)
