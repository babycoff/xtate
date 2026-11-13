#!/usr/bin/env python3
import os, subprocess, tempfile
BIN = os.environ["XTATE_BIN"]
# Linux loopback has no MAC address; use the default-route interface there.
PROBE_TARGET = "127.0.0.1" if os.name == "nt" else "8.8.8.8"
d = tempfile.mkdtemp(prefix="xtate-gen-")
def gen_iface():
    out = subprocess.run([BIN, "--explain-target=" + PROBE_TARGET],
                         capture_output=True, text=True).stdout
    return [l.split("Interface:")[1].strip() for l in out.splitlines() if "Interface:" in l][0]
def run(gen, arg, lines, name):
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(lines)
    iface = gen_iface()
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
    iface = gen_iface()
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

# a rejected option value must say what is wrong, not just "sub param parsing" (F7)
for gen, base in cases:
    p = run_raw(gen, base + " --max-errors nope", "127.0.0.1\n", gen + "-bad-max.txt")
    assert p.returncode != 0, (gen, "bad max-errors accepted", p.returncode)
    assert "max-errors" in p.stderr, (gen, p.stderr[-400:])
    p = run_raw(gen, base + " --max-error-rate 101", "127.0.0.1\n", gen + "-bad-rate.txt")
    assert p.returncode != 0, (gen, "bad max-error-rate accepted", p.returncode)
    assert "max-error-rate" in p.stderr, (gen, p.stderr[-400:])

# a file whose targets are all rejected must name the file (F9)
p = run_raw("addr-stream", "--address-file FILE", "BAD 1\nBAD2 1\n", "addr-allbad.txt")
assert p.returncode != 0, ("addr-stream", "all invalid", p.returncode)
assert "addr-allbad.txt" in p.stderr, p.stderr[-400:]

# overlong lines are consumed and counted by the shared reader (F8)
long_line = "9" * 400
p = run_raw("ip-stream", "--ip-file FILE --default-port 1",
            "127.0.0.1\n" + long_line + "\n127.0.0.2\n", "ip-long.txt")
assert p.returncode == 0, ("ip-stream", "long line", p.returncode, p.stderr[-400:])
assert "target line too long" in p.stderr, p.stderr[-400:]
p = run_raw("ip-stream", "--ip-file FILE --default-port 1 --max-errors 1",
            "127.0.0.1\n" + long_line + "\n127.0.0.2\n", "ip-long-max.txt")
assert p.returncode != 0, ("ip-stream", "long line not counted", p.returncode)
# a blank-only file has no rejected line, so it is not an all-invalid failure (F8)
p = run_raw("ip-stream", "--ip-file FILE --default-port 1", "\n\n\n", "ip-blank.txt")
assert p.returncode == 0, ("ip-stream", "blank only", p.returncode, p.stderr[-400:])

# lines skipped for an un-scannable range must count against the error policy (F17)
for gen, base, big, ok in [
    ("ip-stream", "--ip-file FILE --default-port 1", "::/1", "127.0.0.1"),
    ("addr-stream", "--address-file FILE", "::/1 1", "127.0.0.1 1"),
]:
    p = run_raw(gen, base, big + "\n" + ok + "\n", gen + "-big.txt")
    assert p.returncode == 0, (gen, "big range", p.returncode, p.stderr[-400:])
    assert "range too large" in p.stderr, (gen, p.stderr[-400:])
    p = run_raw(gen, base + " --max-errors 1", big + "\n" + ok + "\n", gen + "-big-max.txt")
    assert p.returncode != 0, (gen, "big range not counted", p.returncode)
print("Generate input tests: PASS")
