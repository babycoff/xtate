#!/usr/bin/env bash
#
# Large-batch local regression: thousands of results through real scan/output
# paths, without sending a single packet outside the Docker bridge network.
#
# Defaults:
#   5 target containers x 100 address aliases = 500 targets
#   20 endpoints per target (8080 open, 1..19 closed) = 10000 results
#
# Usage:
#   XTATE_BIN=/path/to/xtate-linux bash tests/large-batch/run.sh
#
# Optional environment:
#   XTATE_LAB_IMAGE   builder image (default xtate-builder:24.04)
#   BATCH_BLOCKS      target containers (default 5)
#   BATCH_ALIASES     aliases per container (default 100)
#   BATCH_RATE        packets per second (default 500)
#   BATCH_OUT         output directory (default ../reports/docker/out/large-batch)
#
# This test intentionally does NOT scan the Internet. It only uses a dedicated
# Docker bridge and 172.18.0.0/16 aliases inside it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
BLOCKS="${BATCH_BLOCKS:-5}"
ALIASES="${BATCH_ALIASES:-100}"
RATE="${BATCH_RATE:-500}"
OUT_DIR="${BATCH_OUT:-$ROOT/../reports/docker/out/large-batch}"
PORTS="${BATCH_PORTS:-8080,1-19}"
ENDPOINTS="${BATCH_ENDPOINTS:-20}"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required" >&2
    exit 1
fi

if command -v cygpath >/dev/null 2>&1; then
    BIN="$(cygpath -w "$BIN")"
    OUT_DIR="$(cygpath -w "$OUT_DIR")"
fi

# Windows checkouts do not carry the Unix execute bit; Docker will execute the
# mounted Linux binary, so accept a regular file there.
if [[ ! -f "$BIN" ]]; then
    echo "xtate binary not found: $BIN" >&2
    echo "set XTATE_BIN to a Linux build" >&2
    exit 1
fi
mkdir -p "$OUT_DIR"

NET="xtate-large-$$"
TARGETS=()
cleanup() {
    for name in "${TARGETS[@]:-}"; do
        docker rm -f "$name" >/dev/null 2>&1 || true
    done
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> creating isolated network $NET"
docker network create "$NET" >/dev/null

# Docker may choose a different private subnet if another test network already
# owns 172.18.0.0/16. Derive the alias base from the network that was actually
# created instead of assuming 172.18.
SUBNET="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$NET")"
NET_PREFIX="$(printf '%s' "$SUBNET" | cut -d/ -f1 | awk -F. '{print $1"."$2}')"
PREFIX_LEN="${SUBNET#*/}"
if [[ -z "$NET_PREFIX" || -z "$PREFIX_LEN" ]]; then
    echo "could not determine Docker subnet for $NET" >&2
    exit 1
fi
echo "==> network subnet $SUBNET (alias prefix $NET_PREFIX)"

echo "==> starting $BLOCKS target containers (${ALIASES} aliases each)"
for ((b = 0; b < BLOCKS; b++)); do
    name="xtate-large-target-$b"
    start=$((10 + b * ALIASES))
    end=$((start + ALIASES - 1))
    TARGETS+=("$name")
    docker run -d --name "$name" --network "$NET" --cap-add NET_ADMIN "$IMAGE" bash -lc "
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq python3 iproute2 >/dev/null 2>&1
        for i in \$(seq $start $end); do
            /sbin/ip addr add $NET_PREFIX.\$((i / 256)).\$((i % 256))/$PREFIX_LEN dev eth0 2>/dev/null || true
        done
        python3 -u -m http.server 8080" >/dev/null
done

wait_tcp() {
    local host="$1"
    local port="$2"
    for _ in $(seq 1 180); do
        if docker exec "$host" bash -c "timeout 1 bash -c '</dev/tcp/127.0.0.1/$port'" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

for name in "${TARGETS[@]}"; do
    wait_tcp "$name" 8080 || {
        echo "target $name did not start" >&2
        docker logs "$name" >&2 || true
        exit 1
    }
    alias_count=$(docker exec "$name" sh -c "/sbin/ip -4 addr show eth0 | grep -c 'inet '" | tr -d '\r')
    expected_aliases=$((ALIASES + 1))
    if [[ "$alias_count" -lt "$expected_aliases" ]]; then
        echo "target $name has $alias_count addresses; expected $expected_aliases" >&2
        exit 1
    fi
done

# Ranges are non-overlapping and all inside the isolated /16.
{
    for ((b = 0; b < BLOCKS; b++)); do
        start=$((10 + b * ALIASES))
        end=$((start + ALIASES - 1))
        for ((i = start; i <= end; i++)); do
            printf '%s.%d.%d\n' "$NET_PREFIX" "$((i / 256))" "$((i % 256))"
        done
    done
} > "$OUT_DIR/targets.txt"

TARGET_COUNT=$((BLOCKS * ALIASES))
EXPECTED=$((TARGET_COUNT * ENDPOINTS))

echo "==> $TARGET_COUNT targets, $EXPECTED expected results, rate $RATE pps"

run_scan() {
    local name="$1"
    local module="$2"
    local handlers="$3"
    local out="/out/$name"
    local host_out="$OUT_DIR/$name"
    echo "--- $name (output=$module, handlers=$handlers)"
    docker run --rm \
        --cap-add NET_RAW --cap-add NET_ADMIN \
        --network "$NET" \
        -v "$BIN:/xtate:ro" \
        -v "$OUT_DIR:/out" \
        "$IMAGE" bash -lc "
            /xtate -iL /out/targets.txt -p '$PORTS' \
              -scan tcp-syn -scan-arg '--send-rst' \
              -rx-handler-count $handlers -rate $RATE --wait 2 --no-status \
              -show info -show failed \
              -output-module $module -output-file $out"
    test -s "$host_out" || {
        echo "output file is empty: $host_out" >&2
        return 1
    }
}

run_scan large-ndjson ndjson 1
run_scan large-csv csv 4
run_scan large-bson bson 1
run_scan large-text text 1

# ndjson: exact record count and open/closed split.
lines=$(wc -l < "$OUT_DIR/large-ndjson" | tr -d ' ')
open=$(grep -c '"classification":"open"' "$OUT_DIR/large-ndjson" || true)
closed=$(grep -c '"classification":"closed"' "$OUT_DIR/large-ndjson" || true)
echo "ndjson: lines=$lines open=$open closed=$closed"
[[ "$lines" -eq "$EXPECTED" ]]
[[ "$open" -eq "$TARGET_COUNT" ]]
[[ "$closed" -eq $((TARGET_COUNT * (ENDPOINTS - 1))) ]]

# csv: one header plus one row per result.
csv_lines=$(wc -l < "$OUT_DIR/large-csv" | tr -d ' ')
echo "csv: lines=$csv_lines"
[[ "$csv_lines" -eq $((EXPECTED + 1)) ]]

# bson: non-empty binary stream (no BSON parser required here).
bson_bytes=$(wc -c < "$OUT_DIR/large-bson" | tr -d ' ')
echo "bson: bytes=$bson_bytes"
[[ "$bson_bytes" -gt 1000 ]]

# text: one line per result.
text_lines=$(wc -l < "$OUT_DIR/large-text" | tr -d ' ')
echo "text: lines=$text_lines"
[[ "$text_lines" -eq "$EXPECTED" ]]

# Optional: JSON validity of every ndjson record (host Python if available).
if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    PYTHON=python3
    command -v python3 >/dev/null 2>&1 || PYTHON=python
    "$PYTHON" - "$OUT_DIR/large-ndjson" <<'PY'
import json, sys
path = sys.argv[1]
count = 0
with open(path, encoding="utf-8") as fh:
    for line in fh:
        json.loads(line)
        count += 1
print("json: parsed", count, "records")
PY
fi

echo "==> large-batch test passed"
