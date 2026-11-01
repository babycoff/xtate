#!/usr/bin/env bash
# Small deterministic checks for the help i18n framework.
# Usage: XTATE_BIN=/path/to/xtate bash tests/i18n/test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
if [[ ! -x "$BIN" ]]; then
    echo "SKIP: executable not found: $BIN" >&2
    exit 0
fi

fail=0
check() {
    local name="$1"
    shift
    if "$@"; then
        echo "PASS: $name"
    else
        echo "FAIL: $name" >&2
        fail=$((fail + 1))
    fi
}

out="$("$BIN" --lang zh --usage)"
check "zh usage welcome" grep -q "欢迎使用 Xtate" <<<"$out"
check "zh usage examples" grep -q "Xtate 基础用法示例" <<<"$out"
check "zh usage translated example" grep -q "使用 TcpSyn 扫描模块" <<<"$out"

help_out="$("$BIN" --lang zh --help)"
check "zh help basic section" grep -q "基础参数" <<<"$help_out"
check "zh help target section" grep -q "目标设置" <<<"$help_out"
check "zh help lang entry" grep -q -- "--lang, language" <<<"$help_out"

scan_out="$("$BIN" --lang zh --help-scan tcp-syn)"
check "zh scan label" grep -q "扫描模块名称：" <<<"$scan_out"

en_out="$("$BIN" --lang en --usage)"
check "en fallback" grep -q "Welcome to Xtate!" <<<"$en_out"
check "en examples" grep -q "basic use examples" <<<"$en_out"

env_out="$(XTATE_LANG=zh "$BIN" --usage)"
check "XTATE_LANG=zh" grep -q "欢迎使用 Xtate" <<<"$env_out"

set +e
"$BIN" --lang nope --version >/dev/null 2>&1
bad_rc=$?
set -e
check "invalid language fails" test "$bad_rc" -ne 0

if [[ "$fail" -ne 0 ]]; then
    echo "$fail i18n check(s) failed" >&2
    exit 1
fi
