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
    env = os.environ.copy()
    env["XTATE_CONTROL_TOKEN"] = "gui-test-token"
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

        # Page is served without the API token, but contains the injected
        # session token for its own same-origin fetch calls.
        status, page = http_json(port, "/")
        text = page.decode("utf-8", "replace")
        if status != 200 or "Xtate control plane" not in text:
            print("GUI page failed:", status, text[:200], file=sys.stderr)
            return 1
        if "__XTATE_GUI_TOKEN__" in text or token not in text:
            print("GUI token was not injected", file=sys.stderr)
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
             "result_path": "gui-test-result.ndjson",
             "timeout_sec": 20, "compression": "none", "index": False})
        if status != 200:
            print("GUI job.start failed:", status, body[:300], file=sys.stderr)
            return 1
        job_id = json.loads(body.decode())["result"]["job_id"]

        state = ""
        for _ in range(50):
            status, body = http_json(
                port, "/api/rpc", token,
                {"id": 5, "method": "job.status", "job_id": job_id})
            state = json.loads(body.decode())["result"]["state"]
            if state in ("completed", "failed", "cancelled", "timed_out"):
                break
            time.sleep(0.1)
        if state not in ("completed", "failed"):
            print("GUI job did not settle:", state, file=sys.stderr)
            return 1

        # --gui must not silently run without an endpoint.
        proc = subprocess.run(
            [exe, "--gui", "--gui-no-open"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=env, timeout=15)
        if proc.returncode == 0 or "requires --control-connect" not in (proc.stderr + proc.stdout):
            print("missing --control-connect was not rejected", file=sys.stderr)
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


if __name__ == "__main__":
    sys.exit(main())
