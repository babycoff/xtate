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
run_ok "duplicate rate" --rate 100 --rate 200 --list-probe
run_ok "nested probe argument token" --list-probe -probe-arg "-subprobe h2 -subprobe-arg --path=/h2"
run_ok "probe help" --help-probe ssh
run_ok "scan help" --help-scan zbanner

# Language validation.
run_fail "invalid language" --lang nope --version

if [[ "$fail" -ne 0 ]]; then
    echo "$fail parser check(s) failed" >&2
    exit 1
fi
