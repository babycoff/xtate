#!/usr/bin/env bash
# Run the local benchmark inside the Linux builder image.
# Useful from Windows/Git Bash or from a host without a compatible Linux
# binary. XTATE_BIN must point at a Linux executable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_BENCH_IMAGE:-xtate-builder:24.04}"
OUT="${XTATE_BENCH_OUT:-$ROOT/bench-results/$(date +%Y%m%d-%H%M%S)}"
QUICK="${XTATE_BENCH_QUICK:-0}"

if [[ ! -f "$BIN" ]]; then
    echo "xtate binary not found: $BIN" >&2
    exit 1
fi
mkdir -p "$OUT"

if command -v cygpath >/dev/null 2>&1; then
    ROOT_HOST="$(cygpath -w "$ROOT")"
    BIN_HOST="$(cygpath -w "$BIN")"
    OUT_HOST="$(cygpath -w "$OUT")"
else
    ROOT_HOST="$ROOT"
    BIN_HOST="$BIN"
    OUT_HOST="$OUT"
fi

MSYS_NO_PATHCONV=1 docker run --rm \
    -v "$ROOT_HOST:/src:ro" \
    -v "$BIN_HOST:/xtate:ro" \
    -v "$OUT_HOST:/out" \
    -w /tmp \
    "$IMAGE" bash -lc "
        set -e
        rm -rf /tmp/xtate-bench-root
        mkdir -p /tmp/xtate-bench-root/tests
        cp -a /src/tests/. /tmp/xtate-bench-root/tests/
        find /tmp/xtate-bench-root/tests -name '*.sh' \
            -exec sed -i 's/\r$//' {} +
        args=''
        if [[ '$QUICK' == '1' ]]; then args='--quick'; fi
        XTATE_BIN=/xtate XTATE_BENCH_OUT=/out \
            bash /tmp/xtate-bench-root/tests/bench/run.sh \$args
    "
