#!/usr/bin/env bash
# Interactive-mode smoke tests. They use non-TTY script mode so they can run
# on Linux and Windows (Git Bash) without a terminal emulator.
set -euo pipefail

BIN="${XTATE_BIN:-./bin/xtate}"
if [[ ! -x "$BIN" && -x "${BIN}.exe" ]]; then
    BIN="${BIN}.exe"
fi
if [[ -f "$BIN" ]]; then
    BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
fi
if [[ ! -x "$BIN" ]]; then
    echo "SKIP: xtate binary not found (set XTATE_BIN)" >&2
    exit 0
fi

# Keep the test directory inside the workspace: on Windows the DSH sandbox
# permits writes under the project but not arbitrary %TEMP% paths.
tmp="${XTATE_TEST_TMP:-$PWD/.xtate-interactive-test.$$}"
mkdir -p "$tmp"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

fail=0
check() {
    if eval "$2"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1" >&2
        fail=$((fail + 1))
    fi
}

out="$(printf 'help\nquit\n' | "$BIN" --lang zh -interactive 2>&1 || true)"
check "no null-language error" "! printf '%s' \"\$out\" | grep -q 'invalid language'"
check "help is Chinese" "printf '%s' \"\$out\" | grep -q '交互模式'"
check "command list is present" "printf '%s' \"\$out\" | grep -q 'set-scan'"
check "non-TTY quit does not print startup banner" \
      "! printf '%s' \"\$out\" | grep -q 'God is Stateless'"
check "quit saves recover.conf" "test -f recover.conf"

rm -f recover.conf
out="$(printf 'help set\nshow\nquit\n' | "$BIN" --lang zh -interactive 2>&1 || true)"
check "help <command>" "printf '%s' \"\$out\" | grep -q '设置全局参数'"
check "show prints configuration" "printf '%s' \"\$out\" | grep -q 'rate = 100'"

out="$(printf 'set rate = 321\nshow diff\nshow all\nquit\n' | "$BIN" --lang zh -interactive 2>&1 || true)"
check "show diff shows changed rate" "printf '%s' \"\$out\" | grep -q 'rate = 321'"
check "show all includes defaults" "printf '%s' \"\$out\" | grep -q 'wait = 10'"

rm -f recover.conf
out="$(printf 'list-param rate\nquit\n' | "$BIN" --lang zh -interactive 2>&1 || true)"
check "list-param filter matches rate" "printf '%s' \"\$out\" | grep -q -- '--rate'"
check "list-param filter excludes generate"       "! printf '%s' \"\$out\" | grep -q -- '--generate-module'"

out="$(printf 'hep\nquit\n' | "$BIN" -interactive 2>&1 || true)"
check "unknown command suggests help" "printf '%s' \"\$out\" | grep -q 'did you mean'"

rm -f recover.conf
out="$(printf 'set rate = 123\nquit\n' | "$BIN" -interactive 2>&1 || true)"
check "set accepts spaces" "printf '%s' \"\$out\" | grep -q 'set param successfully'"
check "set value persisted" "grep -q 'rate = 123' recover.conf"

rm -f recover.conf
out="$(printf 'exit\n' | "$BIN" -interactive 2>&1 || true)"
check "exit does not save" "test ! -e recover.conf"

if [[ "$fail" -ne 0 ]]; then
    echo "$fail interactive check(s) failed" >&2
    exit 1
fi
echo "PASS: interactive script mode"
