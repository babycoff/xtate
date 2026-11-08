#!/usr/bin/env bash
# ASan + UBSan build and smoke tests for Linux/clang.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${SANITIZER_BUILD:-$ROOT/tests/sanitizers/build}"
CC="${CC:-clang}"
PYTHON="${PYTHON:-python3}"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "SKIP: $CC not available" >&2
    exit 0
fi

FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"
GEN="Ninja"
if ! command -v ninja >/dev/null 2>&1; then
    GEN="Unix Makefiles"
fi
cmake -S "$ROOT" -B "$BUILD" -G "$GEN" \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="$FLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build "$BUILD" -j 4

BIN="$BUILD/xtate"
if [[ -x "$BUILD/xtate_debug" ]]; then BIN="$BUILD/xtate_debug"; fi

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:strict_string_checks=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

"$BIN" --selftest

if [[ "${SANITIZER_SKIP_PCAP:-0}" != "1" ]]; then
    for suite in zbanner http-pcap tcp-syn-pcap http-state-pcap h2c-pcap udp-pcap; do
        XTATE_BIN="$BIN" bash "$ROOT/tests/$suite/run.sh"
    done
fi

echo "PASS: ASan/UBSan smoke"
