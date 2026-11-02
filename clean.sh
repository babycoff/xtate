#!/usr/bin/env bash
#
# Remove Xtate Linux/macOS build trees and project-local binaries, mirroring
# scripts/clean-windows.ps1. Keep the bin/.gitignore sentinel.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=====Cleaning Xtate Linux build outputs"
echo "  Source      : $ROOT"

removed=0
shopt -s nullglob
for dir in "$ROOT"/build "$ROOT"/build-*; do
    [[ -d "$dir" ]] || continue
    rm -rf "$dir"
    echo "  removed: ${dir#"$ROOT"/}"
    removed=$((removed + 1))
done
shopt -u nullglob

BIN_DIR="$ROOT/bin"
if [[ -d "$BIN_DIR" ]]; then
    shopt -s nullglob
    for file in "$BIN_DIR"/xtate*; do
        [[ -f "$file" ]] || continue
        rm -f "$file"
        echo "  removed: bin/$(basename "$file")"
        removed=$((removed + 1))
    done
    shopt -u nullglob
fi

if ((removed == 0)); then
    echo "Nothing to clean."
else
    echo "=====Clean succeeded"
fi
