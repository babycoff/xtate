#!/usr/bin/env python3
"""Smoke tests for the loopback GUI control-plane client.

The GUI is a browser page plus a tiny HTTP bridge.  These tests exercise the
contract without a browser: the page is served, the session token is required,
cross-host requests are rejected, and job methods are forwarded to the real
control plane.
"""

import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def binary():
    value = os.environ.get("XTATE_BIN")
    if value:
        return value
    name = "xtate.exe" if os.name == "nt" else "xtate"
    return os.path.join("bin", name)


def unique_endpoint():
    if os.name == "nt":
        return "\\\\.\\pipe\\xtate-gui-test-%d" % os.getpid()
    return os.path.join(tempfile.gettempdir(), "xtate-gui-test-%d.sock" % os.getpid())


def http_json(port, path, token=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {}
    if token:
        headers["X-Xtate-GUI-Token"] = token
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body)
        headers["Content-Type"] = "application/json"
        conn.request("POST", path, data, headers)
    else:
        conn.request("GET", path, headers=headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, data


def wait_port(port):
    for _ in range(80):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    exe = binary()
    if not os.path.exists(exe):
        print("missing binary:", exe, file=sys.stderr)
        return 1

    endpoint = unique_endpoint()
    state_dir = os.path.join(os.getcwd(), "gui-test-state")
    shutil.rmtree(state_dir, ignore_errors=True)
    env = os.environ.copy()
    env["XTATE_CONTROL_TOKEN"] = "gui-test-token"
    env["XTATE_STATE_DIR"] = state_dir
    control = subprocess.Popen(
        [exe, "--control-plane=" + endpoint],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    gui = None
    try:
        gui = subprocess.Popen(
            [exe, "--gui", "--control-connect=" + endpoint,
             "--gui-listen=127.0.0.1:0", "--gui-no-open"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        first = gui.stdout.readline()
        second = gui.stdout.readline()
        third = gui.stdout.readline()
        output = first + second + third
        match = re.search(r"http://127\.0\.0\.1:(\d+)/", output)
        token_match = re.search(r"GUI session token: ([0-9a-f]+)", output)
        if not match or not token_match:
            print("GUI did not start:\n" + output, file=sys.stderr)
            return 1
        port = int(match.group(1))
        token = token_match.group(1)
        if not wait_port(port):
            print("GUI port did not become ready", file=sys.stderr)
            return 1

        # A bare page request is rejected; the printed bootstrap URL sets a
        # session cookie, after which the page is served.
        status, _ = http_json(port, "/")
        if status != 403:
            print("GUI page without token was not rejected:", status, file=sys.stderr)
            return 1
        status, _ = http_json(port, "/?token=" + token)
        if status != 303:
            print("GUI bootstrap did not redirect:", status, file=sys.stderr)
            return 1
        status, page = http_json(port, "/", token)
        text = page.decode("utf-8", "replace")
        if status != 200 or "Xtate control plane" not in text:
            print("GUI page failed:", status, text[:200], file=sys.stderr)
            return 1
        if "__XTATE_GUI_TOKEN__" in text or token not in text:
            print("GUI token was not injected", file=sys.stderr)
            return 1
        if 'id="module-params"' not in text or "scan_args" not in text:
            print("GUI module parameter editor is missing", file=sys.stderr)
            return 1
        if 'id="rate" type="number" min="1" max="10000" value="100"' not in text:
            print("GUI rate default is not 100 pps", file=sys.stderr)
            return 1
        if ('id="subprobe"' not in text or "collectProbeArgs" not in text
                or "probeHasSubprobe" not in text
                or 'option value=""' not in text
                or 'm.name !== "null"' not in text):
            print("GUI nested probe editor is missing", file=sys.stderr)
            return 1
        if 'id="live-records"' not in text or "/api/results" not in text:
            print("GUI result records browser is missing", file=sys.stderr)
            return 1
        if ('id="global-params"' not in text or "global_args" not in text
                or 'data-lang-set="zh"' not in text or "const ZH" not in text):
            print("GUI global parameters or language switch is missing",
                  file=sys.stderr)
            return 1

        # Info and job.list require the session token.
        status, body = http_json(port, "/api/info", token)
        if status != 200 or json.loads(body.decode())["endpoint"] != endpoint:
            print("GUI info failed:", status, body[:200], file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/rpc", token,
            {"id": 1, "method": "job.list", "limit": 10, "offset": 0})
        if status != 200 or "jobs" not in json.loads(body.decode()).get("result", {}):
            print("GUI job.list failed:", status, body[:200], file=sys.stderr)
            return 1

        # Structured backend data for the 3.0 scan console.
        status, body = http_json(port, "/api/system", token)
        system = json.loads(body.decode()) if status == 200 else {}
        if (status != 200 or not isinstance(system.get("modules"), dict)
                or not system["modules"].get("scan")
                or not isinstance(system.get("capabilities"), dict)
                or "zstd" not in system["capabilities"]):
            print("GUI system failed:", status, body[:300], file=sys.stderr)
            return 1
        status, body = http_json(port, "/api/interfaces", token)
        interfaces = json.loads(body.decode()) if status == 200 else {}
        if status != 200 or not interfaces.get("interfaces"):
            print("GUI interfaces failed:", status, body[:300], file=sys.stderr)
            return 1
        first_if = interfaces["interfaces"][0]
        for key in ("name", "description", "state", "raw_capable"):
            if key not in first_if:
                print("GUI interface field missing:", key, file=sys.stderr)
                return 1
        status, body = http_json(port, "/api/modules", token)
        catalog = json.loads(body.decode()) if status == 200 else {}
        if status != 200 or not any(m.get("name") == "tcp-syn"
                                    for m in catalog.get("modules", [])):
            print("GUI modules failed:", status, body[:300], file=sys.stderr)
            return 1
        status, body = http_json(port, "/api/modules?lang=zh", token)
        catalog_zh = json.loads(body.decode()) if status == 200 else {}
        tcp_syn_zh = next((m for m in catalog_zh.get("modules", [])
                           if m.get("name") == "tcp-syn"), {})
        if (status != 200 or "扫描" not in tcp_syn_zh.get("short_description", "")):
            print("GUI localized modules failed:", status, body[:300],
                  file=sys.stderr)
            return 1
        status, body = http_json(port, "/api/options?lang=en", token)
        options = json.loads(body.decode()) if status == 200 else {}
        if (status != 200 or len(options.get("options", [])) < 20
                or options["options"][0].get("name") != "seed"):
            print("GUI global options failed:", status, body[:300],
                  file=sys.stderr)
            return 1
        status, body = http_json(port, "/api/options?lang=zh", token)
        options_zh = json.loads(body.decode()) if status == 200 else {}
        if (status != 200 or not options_zh.get("options")
                or "种子" not in options_zh["options"][0].get("description", "")):
            print("GUI localized global options failed:", status, body[:300],
                  file=sys.stderr)
            return 1
        status, body = http_json(port, "/api/system")
        if status != 403:
            print("system endpoint without token was not rejected:",
                  status, body[:200], file=sys.stderr)
            return 1

        # The scan console must get authoritative counts and route data from
        # the server before it allows Start.
        status, body = http_json(
            port, "/api/preflight", token,
            {"targets": "127.0.0.1", "ports": "80,443",
             "scan": "tcp-syn", "rate": 1000, "timeout_sec": 300})
        preflight = json.loads(body.decode()) if status == 200 else {}
        if (status != 200 or not preflight.get("ok")
                or preflight.get("targets") != 1
                or preflight.get("ports") != 2
                or preflight.get("attempts") != 2):
            print("GUI preflight failed:", status, body[:300], file=sys.stderr)
            return 1
        # A nested probe is sent as a flat probe_args object.  Keep the outer
        # tls-state arguments and carry the inner probe in subprobe/subprobe-arg.
        status, body = http_json(
            port, "/api/preflight", token,
            {"targets": "127.0.0.1", "ports": "443",
             "scan": "tcp-state", "probe": "tls-state",
             "rate": 1000, "timeout_sec": 300,
             "probe_args": {"subprobe": "http-state",
                            "subprobe-arg": "--all-banner --max-body=4096"}})
        nested = json.loads(body.decode()) if status == 200 else {}
        if status != 200 or not nested.get("ok"):
            print("GUI nested-probe preflight failed:", status, body[:500],
                  file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/preflight", token,
            {"targets": "not-a-target", "ports": "80",
             "scan": "tcp-syn", "probe": "http"})
        bad = json.loads(body.decode()) if status == 200 else {}
        if status != 200 or bad.get("ok") or not bad.get("errors"):
            print("GUI invalid preflight was accepted:", status, body[:300],
                  file=sys.stderr)
            return 1
        # A TCP scan must not look ready with only UDP ports: the scan engine
        # filters by ip_proto and would otherwise send zero packets.
        status, body = http_json(
            port, "/api/preflight", token,
            {"targets": "127.0.0.1", "ports": "U:53",
             "scan": "tcp-syn", "rate": 1000, "timeout_sec": 300})
        udp_ports = json.loads(body.decode()) if status == 200 else {}
        if status != 200 or udp_ports.get("ok"):
            print("TCP preflight accepted UDP-only ports:", status, body[:300],
                  file=sys.stderr)
            return 1
        # ICMP-style scans have no ports; preflight must still count the
        # addresses and stay ready without a ports field.
        status, body = http_json(
            port, "/api/preflight", token,
            {"targets": "127.0.0.1", "scan": "icmp-echo",
             "rate": 1000, "timeout_sec": 300})
        icmp = json.loads(body.decode()) if status == 200 else {}
        if (status != 200 or not icmp.get("ok")
                or icmp.get("targets") != 1
                or icmp.get("ports") != 0
                or icmp.get("attempts") != 1):
            print("no-port preflight failed:", status, body[:300],
                  file=sys.stderr)
            return 1
        # Unknown modules and probe-type mismatches must be rejected by the
        # same catalog used by the scanner.
        for case in (
            {"targets": "127.0.0.1", "ports": "80", "scan": "bogus",
             "rate": 1000, "timeout_sec": 300},
            {"targets": "127.0.0.1", "ports": "80", "scan": "zbanner",
             "rate": 1000, "timeout_sec": 300},
            {"targets": "127.0.0.1", "ports": "80", "scan": "tcp-syn",
             "probe": "http", "rate": 1000, "timeout_sec": 300},
        ):
            status, body = http_json(port, "/api/preflight", token, case)
            rejected = json.loads(body.decode()) if status == 200 else {}
            if status != 200 or rejected.get("ok"):
                print("invalid preflight was accepted:", case, status,
                      body[:300], file=sys.stderr)
                return 1
        status, body = http_json(
            port, "/api/preflight", None,
            {"targets": "127.0.0.1", "ports": "80",
             "scan": "tcp-syn"})
        if status != 403:
            print("preflight without token was not rejected:", status,
                  body[:200], file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/preflight", token,
            {"targets": "127.0.0.1", "ports": "80", "scan": "tcp-syn",
             "rate": 1000, "timeout_sec": 300,
             "global_args": {"seed": "123"}})
        with_global = json.loads(body.decode()) if status == 200 else {}
        if status != 200 or not with_global.get("ok"):
            print("preflight rejected a valid global argument:", status,
                  body[:300], file=sys.stderr)
            return 1
        for bad_global in ({"seed": "abc"}, {"repeat": True}):
            status, body = http_json(
                port, "/api/preflight", token,
                {"targets": "127.0.0.1", "ports": "80", "scan": "tcp-syn",
                 "rate": 1000, "timeout_sec": 300,
                 "global_args": bad_global})
            rejected_global = json.loads(body.decode()) if status == 200 else {}
            if status != 200 or rejected_global.get("ok"):
                print("preflight accepted an unsafe global argument:",
                      bad_global, status, body[:300], file=sys.stderr)
                return 1

        # Missing token and a non-loopback Host must be rejected.
        status, body = http_json(
            port, "/api/rpc", None,
            {"id": 2, "method": "job.list", "limit": 10, "offset": 0})
        if status != 403:
            print("missing token was not rejected:", status, body[:200],
                  file=sys.stderr)
            return 1
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        raw.sendall(b"GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
        reply = raw.recv(256)
        raw.close()
        if b"403" not in reply.split(b"\r\n", 1)[0]:
            print("cross-host request was not rejected:", reply[:100],
                  file=sys.stderr)
            return 1

        # job.start needs params.authorized=true in addition to the token.
        status, body = http_json(
            port, "/api/rpc", token,
            {"id": 3, "method": "job.start",
             "params": {"scan": "tcp-syn", "targets": ["127.0.0.1"],
                        "ports": [1], "dry_run": True}})
        if status != 403:
            print("unauthorized job.start was not rejected:", status,
                  body[:200], file=sys.stderr)
            return 1

        status, body = http_json(
            port, "/api/rpc", token,
            {"id": 4, "method": "job.start",
             "params": {"scan": "tcp-syn", "targets": ["127.0.0.1"],
                        "ports": [1], "dry_run": True, "authorized": True},
             "timeout_sec": 20, "compression": "none", "index": False})
        if status != 200:
            print("GUI job.start failed:", status, body[:300], file=sys.stderr)
            return 1
        started = json.loads(body.decode())
        if "result" not in started:
            print("GUI job.start returned no job:", body[:500], file=sys.stderr)
            return 1
        job_id = started["result"]["job_id"]

        state = ""
        job_result_path = ""
        for _ in range(50):
            status, body = http_json(
                port, "/api/rpc", token,
                {"id": 5, "method": "job.status", "job_id": job_id})
            st = json.loads(body.decode())["result"]
            state = st["state"]
            job_result_path = st.get("result") or job_result_path
            if state in ("completed", "failed", "cancelled", "timed_out"):
                break
            time.sleep(0.1)
        if not job_result_path:
            print("GUI job returned no result path", file=sys.stderr)
            return 1
        if state not in ("completed", "failed"):
            print("GUI job did not settle:", state, file=sys.stderr)
            return 1

        # A GUI-started job without an explicit result_path gets an isolated
        # timestamped run folder under the managed state directory.
        route_if = (preflight.get("routes") or [{}])[0].get("interface", "")
        status, body = http_json(
            port, "/api/rpc", token,
            {"id": 41, "method": "job.start",
             "params": {"scan": "tcp-syn", "targets": ["127.0.0.1"],
                        "ports": [1], "dry_run": True, "authorized": True,
                        "interface": route_if},
             "timeout_sec": 20, "compression": "none", "index": False})
        started2 = json.loads(body.decode()) if status == 200 else {}
        job2 = started2.get("result", {}).get("job_id")
        if status != 200 or not job2:
            print("GUI default result job failed:", status, body[:300],
                  file=sys.stderr)
            return 1
        result_path2 = ""
        for _ in range(50):
            status, body = http_json(
                port, "/api/rpc", token,
                {"id": 42, "method": "job.status", "job_id": job2})
            status2 = json.loads(body.decode()) if status == 200 else {}
            result_path2 = status2.get("result", {}).get("result", "") or ""
            state2 = status2.get("result", {}).get("state", "")
            if state2 in ("completed", "failed", "cancelled", "timed_out"):
                break
            time.sleep(0.1)
        if state2 not in ("completed", "failed") or "/runs/" not in result_path2.replace("\\", "/"):
            print("GUI default result path is not per-run:", state2,
                  result_path2, file=sys.stderr)
            return 1

        # Result records are served from the completed job's NDJSON file with
        # bounded paging.  The dry-run job above only lists targets, so write
        # representative result records to exercise the reader deterministically.
        records = [
            {"host": "127.0.0.1", "port": 80, "classification": "open"},
            {"host": "127.0.0.1", "port": 443, "classification": "open"},
            {"host": "127.0.0.1", "port": 8080, "classification": "closed"},
        ]
        with open(job_result_path, "w", encoding="utf-8") as out:
            out.write(json.dumps(records[0]) + "\n")
            out.write("{not-json}\n")
            out.write(json.dumps(records[1]) + "\n")
            out.write(json.dumps(records[2]) + "\n")
        status, body = http_json(
            port, "/api/results?job_id=%s&offset=0&limit=2" % job_id, token)
        page = json.loads(body.decode()) if status == 200 else {}
        if (status != 200 or page.get("count") != 2
                or page.get("next_offset") != 2
                or page.get("records", [{}])[0].get("port") != 80):
            print("GUI result records failed:", status, body[:300],
                  file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/results?job_id=%s&offset=2&limit=2" % job_id, token)
        page = json.loads(body.decode()) if status == 200 else {}
        if status != 200 or page.get("count") != 1 or page.get("next_offset") != 3:
            print("GUI result records paging failed:", status, body[:300],
                  file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/results?job_id=../../etc/passwd&offset=0&limit=2", token)
        if status != 400:
            print("GUI invalid job id was not rejected:", status, body[:200],
                  file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/results?job_id=job-999&offset=0&limit=2", token)
        if status != 404:
            print("GUI unknown job result was not 404:", status, body[:200],
                  file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/results?job_id=%s&offset=0&limit=2" % job_id)
        if status != 403:
            print("GUI result records without token were allowed:", status,
                  body[:200], file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/open", token, {"job_id": "../../etc/passwd", "kind": "log"})
        if status != 400:
            print("GUI open invalid job id was not rejected:", status,
                  body[:200], file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/open", token, {"job_id": job_id, "kind": "bogus"})
        if status != 400:
            print("GUI open invalid kind was not rejected:", status,
                  body[:200], file=sys.stderr)
            return 1
        status, body = http_json(
            port, "/api/open", token, {"job_id": "job-999", "kind": "log"})
        if status != 404:
            print("GUI open unknown job was not 404:", status, body[:200],
                  file=sys.stderr)
            return 1

        # Without --control-connect, --gui starts a private control plane.
        auto_env = env.copy()
        auto_env.pop("XTATE_CONTROL_TOKEN", None)
        auto = subprocess.Popen(
            [exe, "--gui", "--gui-listen=127.0.0.1:0", "--gui-no-open"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=auto_env, text=True, encoding="utf-8", errors="replace",
            bufsize=1)
        try:
            auto_output = "".join(auto.stdout.readline() for _ in range(3))
            auto_match = re.search(r"http://127\.0\.0\.1:(\d+)/", auto_output)
            auto_token = re.search(r"GUI session token: ([0-9a-f]+)", auto_output)
            auto_endpoint_match = re.search(r"Control endpoint: (.+)", auto_output)
            if not auto_match or not auto_token or not auto_endpoint_match:
                print("private GUI did not start:\n" + auto_output,
                      file=sys.stderr)
                return 1
            auto_port = int(auto_match.group(1))
            auto_tok = auto_token.group(1)
            auto_endpoint = auto_endpoint_match.group(1).strip()
            if not wait_port(auto_port):
                print("private GUI port did not become ready", file=sys.stderr)
                return 1
            status, body = http_json(auto_port, "/api/info", auto_tok)
            info = json.loads(body.decode()) if status == 200 else {}
            private_endpoint = info.get("endpoint", "")
            if "xtate-ui-" not in private_endpoint:
                print("private GUI did not use a private control plane:",
                      status, body[:200], file=sys.stderr)
                return 1
            # A private control plane must reject a client without its
            # ephemeral token even though the endpoint is local.
            probe = subprocess.run(
                [exe, "--control-ping=" + auto_endpoint],
                env=auto_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", timeout=10)
            if "UNAUTHORIZED" not in probe.stdout:
                print("private control plane accepted a tokenless client:",
                      probe.stdout[:200], probe.stderr[:200], file=sys.stderr)
                return 1
            status, body = http_json(
                auto_port, "/api/rpc", auto_tok,
                {"id": 6, "method": "job.list", "limit": 10, "offset": 0})
            if status != 200 or "jobs" not in json.loads(body.decode()).get("result", {}):
                print("private GUI job.list failed:", status, body[:200],
                      file=sys.stderr)
                return 1
        finally:
            auto.terminate()
            try:
                auto.wait(timeout=5)
            except subprocess.TimeoutExpired:
                auto.kill()
                auto.wait()

        node = shutil.which("node")
        if node:
            for name in ("nested_probe_js_test.js", "input_validation_js_test.js"):
                js_test = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
                checked = subprocess.run([node, js_test], capture_output=True,
                                         text=True, timeout=30)
                if checked.returncode != 0:
                    print(name + " failed:", checked.stdout,
                          checked.stderr, file=sys.stderr)
                    return 1
        print("GUI tests: PASS")
        return 0
    finally:
        for proc in (gui, control):
            if proc is None:
                continue
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        if os.name != "nt" and os.path.exists(endpoint):
            os.unlink(endpoint)
        for suffix in ("", ".manifest.json", ".index.json", ".log"):
            path = "gui-test-result.ndjson" + suffix
            if os.path.exists(path):
                os.unlink(path)
        shutil.rmtree(state_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
