#!/usr/bin/env python3
import json, os, socket, subprocess, tempfile, time
BIN=os.environ["XTATE_BIN"]; TOKEN="test-token"
sock=os.path.join(tempfile.mkdtemp(),"ctl.sock")
p=subprocess.Popen([BIN,"--control-plane="+sock],env=dict(os.environ,XTATE_CONTROL_TOKEN=TOKEN),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        if os.path.exists(sock): break
        time.sleep(0.1)
    def rpc(o):
        s=socket.socket(socket.AF_UNIX); s.connect(sock); s.sendall((json.dumps(o)+"\n").encode()); d=s.recv(65536); s.close(); return json.loads(d)
    assert rpc({"id":1,"method":"ping"})["error"]["code"]=="UNAUTHORIZED"
    assert rpc({"id":2,"method":"ping","token":TOKEN})["result"]["pong"] is True
    assert rpc({"id":3,"method":"job.list","token":TOKEN})["result"]["jobs"]==[]
    print("control unix: PASS")
finally:
    p.terminate(); p.wait(timeout=5)
