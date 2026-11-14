#!/usr/bin/env bash
# Focused CLI/parameter-parser checks.  These do not start a scan.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
if [[ ! -x "$BIN" ]]; then
    echo "SKIP: executable not found: $BIN" >&2
    exit 0
fi

fail=0
run_fail() {
    local name="$1"
    shift
    set +e
    out="$("$BIN" "$@" 2>&1)"
    rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        echo "FAIL: $name (expected nonzero)" >&2
        printf '%s\n' "$out" >&2
        fail=$((fail + 1))
    elif [[ "$out" != *"unknown"* && "$out" != *"missing"* && "$out" != *"invalid"* && "$out" != *"error"* && "$out" != *"non-digit"* && "$out" != *"failed"* ]]; then
        echo "FAIL: $name (no explicit error text)" >&2
        printf '%s\n' "$out" >&2
        fail=$((fail + 1))
    else
        echo "PASS: $name"
    fi
}

run_ok() {
    local name="$1"
    shift
    set +e
    out="$("$BIN" "$@" 2>&1)"
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
        echo "FAIL: $name" >&2
        printf '%s\n' "$out" >&2
        fail=$((fail + 1))
    else
        echo "PASS: $name"
    fi
}

# Unknown global option.
run_fail "unknown option" --definitely-not-a-real-option --list-probe

# Trailing argument without a value.  This used to increment past argv.
run_fail "missing rate value" --rate
run_fail "missing probe-arg value" --probe-arg
run_fail "missing scan-arg value" --scan-arg
run_fail "missing output-arg value" --output-arg
run_fail "missing gen-arg value" --gen-arg
run_fail "bare double dash" --
run_fail "positional token" --list-probe stray-token
run_fail "bad rate suffix" --rate=4x --list-probe
run_fail "bad wait value" --wait=abc --list-probe
run_fail "negative rate" --rate -1 --list-probe

# Existing module/help paths should remain usable without a scan.
run_ok "list probes" --list-probe
run_ok "rate equals form" --rate=100 --list-probe
run_ok "rate colon form" --rate:100 --list-probe
run_ok "rate fractional" --rate=0.5 --list-probe
run_ok "rate millions" --rate=1000000 --list-probe
run_fail "rate zero" --rate=0 --list-probe
run_fail "rate trailing junk" --rate=4x --list-probe
run_ok "nested probe argument token" --list-probe -probe-arg "-subprobe h2 -subprobe-arg --path=/h2"
run_ok "nested probe argument list" --list-probe -probe-arg "-subprobe http-state -subprobe-arg '--max-body=4096 --user-agent=probe'"
run_fail "nested probe rejects tcp subprobe" --offline -ip 127.0.0.1 -p 443 -scan tcp-state -probe tls-state -probe-arg "-subprobe http"
run_fail "nested probe rejects udp subprobe" --offline -ip 127.0.0.1 -p 443 -scan tcp-state -probe tls-state -probe-arg "-subprobe dns"
run_fail "nested probe rejects recursive tls-state" --offline -ip 127.0.0.1 -p 443 -scan tcp-state -probe tls-state -probe-arg "-subprobe tls-state"
run_ok "probe help" --help-probe ssh
run_ok "scan help" --help-scan zbanner

# QUIC/TCP probe compatibility is enforced by the backend, not only the GUI.
if "$BIN" --list-scan 2>/dev/null | grep -q "quic-state"; then
    run_fail "quic-state rejects tls-state" --offline -ip 127.0.0.1 -p U:443 -scan quic-state -probe tls-state --wait 1
fi
if "$BIN" --list-probe 2>/dev/null | grep -q "http3-state"; then
    run_fail "tcp-state rejects http3-state" --offline -ip 127.0.0.1 -p 443 -scan tcp-state -probe http3-state --wait 1
    run_fail "nested probe rejects http3-state" --offline -ip 127.0.0.1 -p 443 -scan tcp-state -probe tls-state -probe-arg "-subprobe http3-state" --wait 1
fi

# Language validation.
run_fail "invalid language" --lang nope --version

# Interactive-mode parser and compatibility checks.
if [[ -f "$ROOT/tests/config/test_interactive.sh" ]]; then
    if ! XTATE_BIN="$BIN" bash "$ROOT/tests/config/test_interactive.sh"; then
        fail=$((fail + 1))
    fi
fi

if [[ "$fail" -ne 0 ]]; then
    echo "$fail parser check(s) failed" >&2
    exit 1
fi
