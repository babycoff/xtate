#!/usr/bin/env python3
import os, subprocess, tempfile
BIN = os.environ["XTATE_BIN"]
d = tempfile.mkdtemp(prefix="xtate-gen-")
def run(gen, arg, lines, name):
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(lines)
    iface = subprocess.run([BIN, "--explain-target=8.8.8.8"], capture_output=True, text=True).stdout
    iface = [l.split("Interface:")[1].strip() for l in iface.splitlines() if "Interface:" in l][0]
    out = os.path.join(d, gen + ".ndjson")
    cmd = [BIN, "--generate", gen, "--gen-arg", arg.replace("FILE", path),
           "-scan", "tcp-syn", "-if", iface, "-rate", "100", "-wait", "0",
           "-o", out, "--no-status"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         encoding="utf-8", text=True)
    try:
        _, err = p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill(); p.communicate()
        raise AssertionError(gen + " hung")
    assert p.returncode == 0, (gen, p.returncode, err[-400:])
    assert name + ":2" in err, (gen, err[-400:])

run("ip-stream", "--ip-file FILE --default-port 1", "127.0.0.1\nBAD\n# comment\n127.0.0.2\n", "ip.txt")
run("addr-stream", "--address-file FILE", "127.0.0.1 1\nBAD 1\n127.0.0.2 2\n", "addr.txt")
run("ip-list", "--ip-file FILE --default-port 1", "127.0.0.1\nBAD\n127.0.0.2\n", "iplist.txt")
run("addr-list", "--address-file FILE", "127.0.0.1 1\nBAD 1\n127.0.0.2 2\n", "addrlist.txt")
def run_raw(gen, arg, lines, name, extra_env=None):
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(lines)
    iface = subprocess.run([BIN, "--explain-target=8.8.8.8"], capture_output=True, text=True).stdout
    iface = [l.split("Interface:")[1].strip() for l in iface.splitlines() if "Interface:" in l][0]
    env = dict(os.environ); env.update(extra_env or {})
    cmd = [BIN, "--generate", gen, "--gen-arg", arg.replace("FILE", path),
           "-scan", "tcp-syn", "-if", iface, "-wait", "0",
           "-o", os.path.join(d, name + ".out"), "--no-status"]
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)

cases = [
    ("ip-stream", "--ip-file FILE --default-port 1"),
    ("addr-stream", "--address-file FILE"),
    ("ip-list", "--ip-file FILE --default-port 1"),
    ("addr-list", "--address-file FILE"),
]
for gen, base in cases:
    p = run_raw(gen, base, "BAD\nBAD2\n", gen + "-allbad.txt")
    assert p.returncode != 0, (gen, "all invalid", p.returncode)
    p = run_raw(gen, base + " --strict-errors", "127.0.0.1\nBAD\n", gen + "-strict.txt")
    assert p.returncode != 0, (gen, "strict", p.returncode)
    p = run_raw(gen, base + " --max-errors 1", "127.0.0.1\nBAD\nBAD2\n", gen + "-max.txt")
    assert p.returncode != 0, (gen, "max-errors", p.returncode)
    p = run_raw(gen, base + " --max-error-rate 10", "127.0.0.1\nBAD\n", gen + "-rate.txt")
    assert p.returncode != 0, (gen, "max-error-rate", p.returncode)
print("Generate input tests: PASS")
