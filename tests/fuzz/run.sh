#!/usr/bin/env bash
# Short libFuzzer run for the packet preprocessor and target-range parser.
#
# Requires clang with libFuzzer support (the Linux CI has it). The harnesses
# stub LOG and link only the parser objects, so no Npcap/OpenSSL is needed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CC="${CC:-clang}"
FUZZ_TIME="${FUZZ_SECONDS:-15}"
BUILD="${FUZZ_BUILD:-$ROOT/tests/fuzz/build}"
CORPUS="$ROOT/tests/fuzz/corpus"
ARTIFACTS="$ROOT/tests/fuzz/artifacts"

mkdir -p "$BUILD" "$ARTIFACTS" "$CORPUS/preprocess" "$CORPUS/target-parse"
mkdir -p "$ROOT/tests/fuzz/corpus/preprocess" "$ROOT/tests/fuzz/corpus/target-parse"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "SKIP: $CC not available (install clang to run the fuzzers)" >&2
    exit 0
fi

COMMON=(
    -g -O1
    -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer
    -ffunction-sections -fdata-sections
    -I"$ROOT/src"
    -Wl,--gc-sections
)

echo "==> building preprocess_fuzz"
"$CC" "${COMMON[@]}" \
    "$ROOT/tests/fuzz/preprocess_fuzz.c" \
    "$ROOT/src/proto/proto-preprocess.c" \
    -o "$BUILD/preprocess_fuzz"

echo "==> building target_parse_fuzz"
"$CC" "${COMMON[@]}" \
    "$ROOT/tests/fuzz/target_parse_fuzz.c" \
    "$ROOT/src/target/target-parse.c" \
    "$ROOT/src/target/target-ipaddress.c" \
    -o "$BUILD/target_parse_fuzz"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

echo "==> fuzzing preprocessor for ${FUZZ_TIME}s"
"$BUILD/preprocess_fuzz" \
    -max_total_time="$FUZZ_TIME" \
    -max_len=65535 \
    -timeout=5 \
    -artifact_prefix="$ARTIFACTS/preprocess-" \
    "$CORPUS/preprocess"

echo "==> fuzzing target parser for ${FUZZ_TIME}s"
"$BUILD/target_parse_fuzz" \
    -max_total_time="$FUZZ_TIME" \
    -max_len=4096 \
    -timeout=5 \
    -artifact_prefix="$ARTIFACTS/target-" \
    "$CORPUS/target-parse"

echo "fuzz smoke passed"
