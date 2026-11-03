#!/usr/bin/env bash
# Xtate local benchmark: target ingestion and offline transmit path.
#
# This suite is intentionally Linux-oriented. It does not scan the public
# Internet. Use docker.sh when the host is Windows or lacks a Linux binary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=lib.sh
source "$ROOT/tests/bench/lib.sh"

usage() {
    cat <<'EOF'
usage: tests/bench/run.sh [--quick|--huge] [--out DIR] [--case NAME]

  --quick       use 100k target lines instead of 1M
  --huge        use 10M target lines (parser cases only)
  --out DIR     result directory (default: bench-results/<timestamp>)
  --case NAME   run one case: parse-inline, parse-ranges, syn-offline-1m,
                syn-offline-16m
EOF
}

QUICK=0
HUGE=0
CASE=""
while (($#)); do
    case "$1" in
        --quick) QUICK=1; shift ;;
        --huge) HUGE=1; shift ;;
        --out) OUT=$2; shift 2 ;;
        --case) CASE=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ "$HUGE" == "1" ]]; then
    MODE="huge"
    INLINE_COUNT=10000000
elif [[ "$QUICK" == "1" ]]; then
    MODE="quick"
    INLINE_COUNT=100000
else
    MODE="full"
    INLINE_COUNT=1000000
fi

OUT="${OUT:-$ROOT/bench-results/$(date +%Y%m%d-%H%M%S)}"
DATA="${XTATE_BENCH_DATA:-$OUT/data}"
RESULTS="${XTATE_BENCH_RESULTS:-$OUT/results.jsonl}"
mkdir -p "$OUT" "$DATA"
: >"$RESULTS"

if [[ ! -f "$BIN" ]]; then
    echo "xtate binary not found: $BIN (set XTATE_BIN)" >&2
    exit 1
fi
if [[ ! -x "$BIN" ]]; then
    echo "xtate binary is not executable: $BIN" >&2
    exit 1
fi

echo "Xtate benchmark"
echo "  binary      : $BIN"
echo "  output      : $OUT"
echo "  mode        : $MODE"
echo

bash "$ROOT/tests/bench/gen-targets.sh" "$DATA" "$MODE"

want() {
    [[ -z "$CASE" || "$CASE" == "$1" ]]
}

# Parser: target ingestion + range listing, no packet transmission.
if want parse-inline; then
    run_case parse-inline "$INLINE_COUNT" \
        -iL "$DATA/inline-$INLINE_COUNT.txt" -p 80 -list-range \
        --no-resume-file
fi

if want parse-ranges; then
    run_case parse-ranges "$INLINE_COUNT" \
        -iL "$DATA/ranges-$INLINE_COUNT.txt" -p 80 -list-range \
        --no-resume-file
fi

# Transmit path without raw sockets. This is useful for relative comparisons
# of target generation, template construction and the Tx loop.
if [[ "$HUGE" == "1" ]]; then
    run_case parse-sparse "$INLINE_COUNT" \
        -iL "$DATA/sparse-$INLINE_COUNT.txt" -p 80 -list-range \
        --no-resume-file
    print_summary
    exit 0
fi

if want syn-offline-1m; then
    run_case syn-offline-1m 1048576 \
        -ip 10.0.0.0/12 -p 80 -scan tcp-syn \
        --offline --rate 50000000 --wait 0 --no-status \
        --no-resume-file -out null
fi

if want syn-offline-16m; then
    run_case syn-offline-16m 16777216 \
        -ip 10.0.0.0/8 -p 80 -scan tcp-syn \
        --offline --rate 50000000 --wait 0 --no-status \
        --no-resume-file -out null
fi

print_summary
