#!/usr/bin/env bash
# Optional PTY smoke test for interactive-mode terminal restoration.
# Requires util-linux `script` (Linux). Windows/Git Bash skips it.
set -euo pipefail

BIN="${XTATE_BIN:-./bin/xtate}"
if [[ ! -x "$BIN" && -x "${BIN}.exe" ]]; then
    BIN="${BIN}.exe"
fi
if [[ -f "$BIN" ]]; then
    BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
fi
if ! command -v script >/dev/null 2>&1; then
    echo "SKIP: util-linux script not available"
    exit 0
fi

tmp="${XTATE_TEST_TMP:-$PWD/.xtate-tty-test.$$}"
mkdir -p "$tmp/home"
trap 'rm -rf "$tmp"' EXIT

export HOME="$tmp/home"
cd "$tmp"

run_pty() {
    local input="$1"
    local out="$2"
    printf '%b' "$input" |
        timeout 10 script -qec 'sh -c "\"$XTATE_BIN\" -interactive; stty -a"' /dev/null \
            >"$out" 2>&1 || true
}

check() {
    if eval "$2"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1" >&2
        exit 1
    fi
}

out="$tmp/quit.log"
XTATE_BIN="$BIN" run_pty 'quit\ny\n' "$out"
check "quit exits under a PTY" "grep -q 'icanon' \"$out\""
check "terminal is restored (icanon present)" "grep -q 'icanon' \"$out\""

out="$tmp/eof.log"
XTATE_BIN="$BIN" run_pty '' "$out"
check "EOF exits under a PTY" "grep -q 'icanon' \"$out\""

out="$tmp/completion.log"
XTATE_BIN="$BIN" run_pty \
  'set-scan tcp-syn\nset scan-module-args = --\t\nset lang = \t\nquit\ny\n' \
  "$out"
check "module argument completion" "grep -q -- '--send-rst' \"$out\""
check "value completion" "grep -q 'zh-CN' \"$out\""
check "completion PTY restores terminal" "grep -q 'icanon' \"$out\""

echo "PASS: interactive PTY terminal restoration"
