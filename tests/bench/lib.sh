#!/usr/bin/env bash
# Shared helpers for the local benchmark harness. Linux-oriented: this
# benchmark intentionally measures the Linux scanner path.

ROOT="${XTATE_BENCH_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
OUT="${XTATE_BENCH_OUT:-$ROOT/bench-results/$(date +%Y%m%d-%H%M%S)}"
DATA="${XTATE_BENCH_DATA:-$OUT/data}"
RESULTS="$OUT/results.jsonl"
MODE="${XTATE_BENCH_MODE:-full}"

now_ns() {
    date +%s%N
}

rss_kb() {
    local file="$1"
    if [[ -s "$file" ]]; then
        awk '{print $2}' "$file" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

run_case() {
    local name="$1"
    local targets="$2"
    shift 2

    mkdir -p "$OUT"
    local stdout="$OUT/$name.stdout"
    local stderr="$OUT/$name.stderr"
    local rssfile="$OUT/$name.rss"
    local start end elapsed rc bytes rss

    : >"$rssfile"
    start="$(now_ns)"
    set +e
    if [[ -x /usr/bin/time ]]; then
        /usr/bin/time -f '%e %M' -o "$rssfile" "$BIN" "$@" \
            >"$stdout" 2>"$stderr"
        rc=$?
    else
        # Portable peak-RSS fallback: sample VmHWM while the scanner runs.
        "$BIN" "$@" >"$stdout" 2>"$stderr" &
        local pid=$!
        local peak=0
        while kill -0 "$pid" 2>/dev/null; do
            local cur
            cur=$(awk '/^VmHWM:/ {print $2}' "/proc/$pid/status" 2>/dev/null                 || true)
            if [[ -n "$cur" ]] && ((cur > peak)); then
                peak=$cur
            fi
            sleep 0.02
        done
        wait "$pid"
        rc=$?
        printf '0 %s\n' "$peak" >"$rssfile"
    fi
    set -e
    end="$(now_ns)"
    elapsed=$(((end - start) / 1000000))
    bytes=$(wc -c <"$stdout")
    rss=$(rss_kb "$rssfile")

    printf '{"case":"%s","targets":%s,"elapsed_ms":%s,"rc":%s,"rss_kb":%s,"stdout_bytes":%s}\n' \
        "$name" "$targets" "$elapsed" "$rc" "$rss" "$bytes" >>"$RESULTS"

    printf '%-28s %8s ms  rss=%8s KiB  rc=%s\n' \
        "$name" "$elapsed" "$rss" "$rc"

    if ((rc != 0)); then
        echo "FAILED: $name (see $stderr)" >&2
        tail -20 "$stderr" >&2 || true
        return "$rc"
    fi
}

print_summary() {
    echo
    echo "results: $RESULTS"
    awk -F'[:,}]' '
        /"case"/ {
            case_name=$2; gsub(/"/, "", case_name);
            elapsed=0; targets=0; rss=0;
            for (i = 1; i <= NF; i++) {
                if ($i ~ /elapsed_ms/) elapsed=$(i+1);
                if ($i ~ /"targets"/) targets=$(i+1);
                if ($i ~ /rss_kb/) rss=$(i+1);
            }
            if (elapsed > 0)
                printf "  %-28s %8s ms  %8s targets  %8s KiB\n",
                    case_name, elapsed, targets, rss;
        }
    ' "$RESULTS"
}
