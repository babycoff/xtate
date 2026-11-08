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
WORK_CORPUS="${FUZZ_WORK_CORPUS:-$ROOT/tests/fuzz/corpus-working}"
ARTIFACTS="$ROOT/tests/fuzz/artifacts"

mkdir -p "$BUILD" "$ARTIFACTS" \
    "$CORPUS/preprocess" "$CORPUS/target-parse" "$CORPUS/targetset" "$CORPUS/targetfile" \
    "$CORPUS/h3-qpack" "$CORPUS/h2-hpack" \
    "$WORK_CORPUS/preprocess" "$WORK_CORPUS/target-parse" \
    "$WORK_CORPUS/targetset" "$WORK_CORPUS/targetfile" \
    "$WORK_CORPUS/h3-qpack" "$WORK_CORPUS/h2-hpack"

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

TARGET_SRC=(
    "$ROOT/src/target/target-set.c"
    "$ROOT/src/target/target-parse.c"
    "$ROOT/src/target/target-ipaddress.c"
    "$ROOT/src/target/target-rangev4.c"
    "$ROOT/src/target/target-rangev6.c"
    "$ROOT/src/target/target-rangeport.c"
    "$ROOT/src/util-data/fine-malloc.c"
)
echo "==> building h3_qpack_fuzz"
"$CC" "${COMMON[@]}" -ffunction-sections -fdata-sections \
    -DHTTP3_FUZZ \
    "$ROOT/tests/fuzz/h3_qpack_fuzz.c" \
    -Wl,--gc-sections \
    -o "$BUILD/h3_qpack_fuzz"

echo "==> building h2_hpack_fuzz"
"$CC" "${COMMON[@]}" -ffunction-sections -fdata-sections \
    -DH2_FUZZ \
    "$ROOT/tests/fuzz/h2_hpack_fuzz.c" \
    -Wl,--gc-sections \
    -o "$BUILD/h2_hpack_fuzz"

echo "==> building targetfile_fuzz"
"$CC" "${COMMON[@]}" \
    "$ROOT/tests/fuzz/targetfile_fuzz.c" \
    "${TARGET_SRC[@]}" \
    -o "$BUILD/targetfile_fuzz"

echo "==> building targetset_fuzz"
"$CC" "${COMMON[@]}" \
    "$ROOT/tests/fuzz/targetset_fuzz.c" \
    "${TARGET_SRC[@]}" \
    -o "$BUILD/targetset_fuzz"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

echo "==> fuzzing preprocessor for ${FUZZ_TIME}s"
"$BUILD/preprocess_fuzz" \
    -max_total_time="$FUZZ_TIME" \
    -max_len=65535 \
    -timeout=5 \
    -artifact_prefix="$ARTIFACTS/preprocess-" \
    "$WORK_CORPUS/preprocess" "$CORPUS/preprocess"

echo "==> fuzzing target parser for ${FUZZ_TIME}s"
"$BUILD/target_parse_fuzz" \
    -max_total_time="$FUZZ_TIME" \
    -max_len=4096 \
    -timeout=5 \
    -artifact_prefix="$ARTIFACTS/target-" \
    "$WORK_CORPUS/target-parse" "$CORPUS/target-parse"

echo "==> fuzzing target-set parser for ${FUZZ_TIME}s"
"$BUILD/targetset_fuzz" \
    -max_total_time="$FUZZ_TIME" \
    -max_len=1024 \
    -timeout=5 \
    -artifact_prefix="$ARTIFACTS/targetset-" \
    "$WORK_CORPUS/targetset" "$CORPUS/targetset"

echo "==> fuzzing HTTP/3 QPACK frames for ${FUZZ_TIME}s"
"$BUILD/h3_qpack_fuzz" \
    -max_total_time="$FUZZ_TIME" \
    -max_len=65536 \
    -timeout=5 \
    -artifact_prefix="$ARTIFACTS/h3-qpack-" \
    "$WORK_CORPUS/h3-qpack" "$CORPUS/h3-qpack"

echo "==> fuzzing HTTP/2 HPACK for ${FUZZ_TIME}s"
"$BUILD/h2_hpack_fuzz" \
    -max_total_time="$FUZZ_TIME" \
    -max_len=65536 \
    -timeout=5 \
    -artifact_prefix="$ARTIFACTS/h2-hpack-" \
    "$WORK_CORPUS/h2-hpack" "$CORPUS/h2-hpack"

echo "==> fuzzing target-file parser for ${FUZZ_TIME}s"
"$BUILD/targetfile_fuzz" \
    -max_total_time="$FUZZ_TIME" \
    -max_len=4096 \
    -timeout=5 \
    -artifact_prefix="$ARTIFACTS/targetfile-" \
    "$WORK_CORPUS/targetfile" "$CORPUS/targetfile"

echo "fuzz smoke passed"
