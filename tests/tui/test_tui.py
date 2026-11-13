#!/usr/bin/env python3
"""Smoke tests for the --tui control-plane client.

These tests are intentionally non-TTY: they exercise the snapshot path, which
uses the same control protocol as the interactive dashboard and is portable to
Windows Named Pipes and Unix sockets. The interactive key loop is covered by a
manual terminal smoke test.
"""

import os
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
        return "\\\\.\\pipe\\xtate-tui-test-%d" % os.getpid()
    return os.path.join(tempfile.gettempdir(), "xtate-tui-test-%d.sock" % os.getpid())


def main():
    exe = binary()
    if not os.path.exists(exe):
        print("missing binary:", exe, file=sys.stderr)
        return 1

    endpoint = unique_endpoint()
    env = os.environ.copy()
    env.pop("XTATE_CONTROL_TOKEN", None)
    server = subprocess.Popen(
        [exe, "--control-plane=" + endpoint],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        # Wait until the control plane accepts a request. The snapshot itself is
        # the readiness probe; a refused connection exits non-zero.
        last = None
        for _ in range(50):
            proc = subprocess.run(
                [exe, "--tui", "--control-connect=" + endpoint],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                timeout=15,
            )
            last = proc
            if proc.returncode == 0:
                break
            time.sleep(0.1)
        proc = last
        if proc is None or proc.returncode != 0:
            print("TUI snapshot failed:", proc, file=sys.stderr)
            return 1
        expected = "Xtate TUI control endpoint: " + endpoint
        if expected not in proc.stdout:
            print("missing endpoint line:\n" + proc.stdout, file=sys.stderr)
            return 1
        if "job(s) shown" not in proc.stdout:
            print("missing job summary:\n" + proc.stdout, file=sys.stderr)
            return 1
        if "JOB ID" not in proc.stdout or "STATE" not in proc.stdout:
            print("missing table header:\n" + proc.stdout, file=sys.stderr)
            return 1

        # --tui must not silently run without an endpoint.
        proc = subprocess.run(
            [exe, "--tui"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=15,
        )
        if proc.returncode == 0:
            print("--tui without --control-connect unexpectedly succeeded",
                  file=sys.stderr)
            return 1
        if "requires --control-connect" not in (proc.stderr + proc.stdout):
            print("unexpected missing-endpoint message:\n" + proc.stderr,
                  file=sys.stderr)
            return 1

        print("TUI tests: PASS")
        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        if os.name != "nt" and os.path.exists(endpoint):
            os.unlink(endpoint)


if __name__ == "__main__":
    sys.exit(main())
