#!/usr/bin/env bash
# Non-TTY interactive-mode checks. No packets are sent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
if [[ ! -x "$BIN" ]]; then
    echo "SKIP: executable not found: $BIN" >&2
    exit 0
fi

fail=0
run_session() {
    local name="$1"
    local input="$2"
    local needle="$3"
    set +e
    out="$(printf '%b' "$input" | "$BIN" --lang en -interactive 2>&1)"
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
        echo "FAIL: $name (exit $rc)" >&2
        printf '%s\n' "$out" >&2
        fail=$((fail + 1))
    elif [[ "$out" != *"$needle"* ]]; then
        echo "FAIL: $name (missing: $needle)" >&2
        printf '%s\n' "$out" >&2
        fail=$((fail + 1))
    else
        echo "PASS: $name"
    fi
}

run_session "compatible tls-state" \
    'set-scan tcp-state\nset-probe tls-state\ncheck\nexit\n' \
    'probe:   tls-state'
run_session "incompatible probe rejected" \
    'set-scan tcp-state\nset-probe http\nexit\n' \
    'requires a state probe'
run_session "set-scan clears incompatible probe" \
    'set-scan tcp-state\nset-probe tls-state\nset-scan tcp-syn\nexit\n' \
    'was cleared'
run_session "structured subprobe" \
    'set-scan tcp-state\nset-probe tls-state\nset-subprobe close-state\nset-subprobe-arg --max-body=4096 --method=POST\necho\nexit\n' \
    "-subprobe close-state -subprobe-arg '--max-body=4096 --method=POST'"
run_session "subprobe rejects tcp" \
    'set-scan tcp-state\nset-probe tls-state\nset-subprobe http\nexit\n' \
    'state probe'
run_session "fractional rate" \
    'set-scan tcp-syn\nset rate = 0.5\ncheck\nexit\n' \
    'rate:    0.5 packets/sec'
run_session "history usage" \
    'history\nexit\n' \
    'usage: history clear'
run_session "history clear" \
    'history clear\nexit\n' \
    'history cleared'

if [[ "$fail" -ne 0 ]]; then
    echo "$fail interactive check(s) failed" >&2
    exit 1
fi
exit 0
