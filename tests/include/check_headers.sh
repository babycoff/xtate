#!/usr/bin/env bash
# Verify that every project header can be included on its own.
# This is deliberately strict: only the repository root is on -I.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CC="${CC:-cc}"
if ! command -v "$CC" >/dev/null 2>&1; then
    echo "SKIP: C compiler not found: $CC"
    exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
total=0
while IFS= read -r header; do
    rel="${header#"$ROOT"/}"
    total=$((total + 1))
    {
        printf '#include "%s"\n' "$rel"
        printf 'int main(void) { return 0; }\n'
    } >"$tmp/t.c"
    if ! "$CC" -std=gnu99 -fsyntax-only -D_GNU_SOURCE -I "$ROOT" \
            "$tmp/t.c" >"$tmp/err" 2>&1; then
        echo "FAIL: $rel" >&2
        head -8 "$tmp/err" >&2
        fail=$((fail + 1))
    fi
done < <(find "$ROOT/src" -name '*.h' | sort)

if ((fail != 0)); then
    echo "$fail/$total header(s) are not self-contained" >&2
    exit 1
fi
echo "PASS: $total headers are self-contained"
