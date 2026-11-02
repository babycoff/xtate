#!/usr/bin/env bash
#
# Build Xtate on Linux/macOS. Similar in shape to scripts/build-windows.ps1:
# choose one compiler and one configuration, keep other outputs, and write
# project-local binaries to bin/.
#
# Usage:
#   ./build.sh                         # interactive if stdin is a terminal
#   ./build.sh --compiler clang --config release
#   ./build.sh --compiler gcc --config debug
#   ./build.sh debug clang             # legacy positional form
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPILER=""
CONFIG=""

usage() {
    cat <<'EOF'
Usage: ./build.sh [options] [legacy: debug|release] [legacy: gcc|clang]

Options:
  -c, --compiler gcc|clang   Compiler to use (default: gcc)
  -C, --config release|debug Build configuration (default: release)
      --debug                Shorthand for --config debug
      --release              Shorthand for --config release
  -h, --help                 Show this help

No options and an interactive terminal: choose compiler and configuration.
No options and redirected stdin: GCC Release (for scripts/CI).
EOF
}

choose() {
    local title="$1"
    shift
    local -a labels=("$@")
    local default=0
    echo >&2
    echo "$title" >&2
    for i in "${!labels[@]}"; do
        printf '  [%d] %s\n' "$((i + 1))" "${labels[$i]}" >&2
    done
    while true; do
        printf 'Select [1-%d] (default %d): ' "${#labels[@]}" "$((default + 1))" >&2
        read -r answer || true
        if [[ -z "${answer:-}" ]]; then
            echo "$default"
            return
        fi
        if [[ "$answer" =~ ^[0-9]+$ ]] &&
           ((answer >= 1 && answer <= ${#labels[@]})); then
            echo "$((answer - 1))"
            return
        fi
        echo "Invalid choice." >&2
    done
}

while (($# > 0)); do
    case "$1" in
        -c|--compiler)
            [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
            COMPILER="$2"
            shift 2
            ;;
        -C|--config)
            [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
            CONFIG="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --debug)
            CONFIG="debug"
            shift
            ;;
        --release)
            CONFIG="release"
            shift
            ;;
        debug|release)
            CONFIG="$1"
            shift
            ;;
        gcc|clang)
            COMPILER="$1"
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$COMPILER" ]]; then
    if [[ -t 0 ]]; then
        idx=$(choose "Select compiler" "GCC (default)" "Clang")
        COMPILER=$([[ "$idx" == "0" ]] && echo gcc || echo clang)
    else
        COMPILER="gcc"
    fi
fi

if [[ -z "$CONFIG" ]]; then
    if [[ -t 0 ]]; then
        idx=$(choose "Select configuration" "Release (default)" "Debug")
        CONFIG=$([[ "$idx" == "0" ]] && echo release || echo debug)
    else
        CONFIG="release"
    fi
fi

case "$COMPILER" in
    gcc) CC_BIN="${CC:-gcc}" ;;
    clang) CC_BIN="${CC:-clang}" ;;
    *) echo "unsupported compiler: $COMPILER (use gcc or clang)" >&2; exit 2 ;;
esac
if ! command -v "$CC_BIN" >/dev/null 2>&1; then
    echo "compiler not found: $CC_BIN" >&2
    exit 1
fi

case "$CONFIG" in
    release) BUILD_TYPE="Release" ;;
    debug) BUILD_TYPE="Debug" ;;
    *) echo "unsupported configuration: $CONFIG (use release or debug)" >&2; exit 2 ;;
esac

BUILD_DIR="$ROOT/build-$COMPILER-$CONFIG"
BIN_DIR="$ROOT/bin"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

echo "=====Xtate Linux build"
echo "  Source      : $ROOT"
echo "  Compiler    : $COMPILER ($CC_BIN)"
echo "  Configuration: $BUILD_TYPE"
echo "  Build dir   : $BUILD_DIR"
echo "  Project bin : $BIN_DIR"

rm -rf "$BUILD_DIR"
mkdir -p "$BIN_DIR"
cmake -S "$ROOT" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_C_COMPILER="$CC_BIN" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build "$BUILD_DIR" -j "$JOBS"

case "$CONFIG" in
    debug) EXE_NAME="xtate_debug" ;;
    *) EXE_NAME="xtate" ;;
esac
EXE_PATH="$BUILD_DIR/$EXE_NAME"
if [[ ! -f "$EXE_PATH" ]]; then
    echo "expected executable not found: $EXE_PATH" >&2
    exit 1
fi

PER_TOOLCHAIN="$BIN_DIR/xtate-$COMPILER-$CONFIG"
install -m 755 "$EXE_PATH" "$PER_TOOLCHAIN"
if [[ "$CONFIG" == "debug" ]]; then
    install -m 755 "$EXE_PATH" "$BIN_DIR/xtate_debug"
else
    install -m 755 "$EXE_PATH" "$BIN_DIR/xtate"
fi

echo "=====Build succeeded"
echo "  $PER_TOOLCHAIN"
if [[ "$CONFIG" == "debug" ]]; then
    echo "  $BIN_DIR/xtate_debug"
else
    echo "  $BIN_DIR/xtate"
fi
