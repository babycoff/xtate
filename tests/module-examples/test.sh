#!/usr/bin/env bash
# Compile-check the module templates.  They are examples, not registered
# modules; this catches API/signature drift without growing the module list.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for src in "$ROOT"/examples/modules/*.c; do
    out="$TMP/$(basename "$src" .c).o"
    "$CC" -std=c99 -Wall -Wextra -fsyntax-only "$src" -o "$out"
    echo "PASS: $(basename "$src")"
done

echo "PASS: module templates compile"
