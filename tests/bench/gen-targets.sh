#!/usr/bin/env bash
# Generate deterministic target files for the parser benchmark.
set -euo pipefail

data="${1:?usage: gen-targets.sh DATA_DIR [quick|full]}"
mode="${2:-full}"
mkdir -p "$data"

case "$mode" in
    quick) count=100000 ;;
    full)  count=1000000 ;;
    huge)  count=10000000 ;;
    *) echo "unknown mode: $mode" >&2; exit 2 ;;
esac

inline="$data/inline-$count.txt"
ranges="$data/ranges-$count.txt"

if [[ ! -s "$inline" ]]; then
    awk -v n="$count" 'BEGIN {
        for (i = 0; i < n; i++) {
            printf "10.%d.%d.%d\n",
                int(i / 65536) % 256, int(i / 256) % 256, i % 256;
        }
    }' >"$inline"
fi

if [[ ! -s "$ranges" ]]; then
    awk -v n="$count" 'BEGIN {
        for (i = 0; i < n; i++) {
            printf "10.%d.%d.%d-10.%d.%d.%d\n",
                int(i / 65536) % 256, int(i / 256) % 256, i % 256,
                int(i / 65536) % 256, int(i / 256) % 256, i % 256;
        }
    }' >"$ranges"
fi

if [[ "$mode" == "huge" ]]; then
    sparse="$data/sparse-$count.txt"
    if [[ ! -s "$sparse" ]]; then
        # Descending addresses force the RangeList to append instead of
        # merging the previous range, exposing sparse-list memory and sort cost.
        awk -v n="$count" 'BEGIN {
            for (i = 0; i < n; i++) {
                v = n - 1 - i;
                printf "10.%d.%d.%d\n",
                    int(v / 65536) % 256, int(v / 256) % 256, v % 256;
            }
        }' >"$sparse"
    fi
fi

printf 'generated %s (%s lines) and %s (%s lines)\n' \
    "$inline" "$(wc -l <"$inline")" "$ranges" "$(wc -l <"$ranges")"
