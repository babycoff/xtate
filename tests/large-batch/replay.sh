#!/usr/bin/env bash
#
# Deterministic high-rate replay test: generate a pcap of valid tcp-syn replies,
# then feed it to xtate through the receive path. No packets leave the machine.
#
# Default:
#   1000 targets x 1000 ports = 1000000 open results
#   output modules: ndjson, csv, bson, text
#   default handlers: 4
#
# Usage:
#   XTATE_BIN=/path/to/xtate-linux bash tests/large-batch/replay.sh [options]
#   bash tests/large-batch/replay.sh --help
#
# Requirements:
#   Docker, a Linux xtate binary, and Python 3 on the host (to generate the
#   fixture). The scanner container runs with --network none.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
TARGETS="${BATCH_TARGETS:-1000}"
PORTS="${BATCH_PORTS:-1-1000}"
SEED="${BATCH_SEED:-123}"
SOURCE_PORT="${BATCH_SOURCE_PORT:-40000}"
PCAP_PPS="${BATCH_PCAP_PPS:-20000}"
IP_ME="${BATCH_IP_ME:-192.0.2.1}"
OUT_DIR="${BATCH_OUT:-$ROOT/../reports/docker/out/large-batch-replay}"
HANDLERS="${BATCH_HANDLERS:-4}"
DISPATCH_BUF="${BATCH_DISPATCH_BUF:-65536}"

usage() {
    cat <<EOF
Usage: $0 [options]

  --bin PATH          Linux xtate binary (default XTATE_BIN)
  --image IMAGE       Docker builder image (default $IMAGE)
  --targets N         target IPs in the fixture (default $TARGETS)
  --ports RANGE       inclusive port range (default $PORTS)
  --pps N             replay pacing in packets/second (default $PCAP_PPS)
  --handlers N        receive handler count (default $HANDLERS, power of 2)
  --dispatch-buf N    dispatch queue size (default $DISPATCH_BUF)
  --seed N            cookie/seed (default $SEED)
  --source-port N     source port (default $SOURCE_PORT)
  --ip-me ADDR        scanner source address (default $IP_ME)
  --out DIR           output directory (default $OUT_DIR)
  -h, --help          show this help

The generated pcap is local; the scanner container uses --network none.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin) BIN="$2"; shift 2 ;;
        --image) IMAGE="$2"; shift 2 ;;
        --targets) TARGETS="$2"; shift 2 ;;
        --ports) PORTS="$2"; shift 2 ;;
        --pps) PCAP_PPS="$2"; shift 2 ;;
        --handlers) HANDLERS="$2"; shift 2 ;;
        --dispatch-buf) DISPATCH_BUF="$2"; shift 2 ;;
        --seed) SEED="$2"; shift 2 ;;
        --source-port) SOURCE_PORT="$2"; shift 2 ;;
        --ip-me) IP_ME="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required" >&2
    exit 1
fi
if [[ ! -f "$BIN" ]]; then
    echo "xtate binary not found: $BIN" >&2
    exit 1
fi
PYTHON=python3
command -v python3 >/dev/null 2>&1 || PYTHON=python
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python 3 is required to generate the pcap fixture" >&2
    exit 1
fi

if command -v cygpath >/dev/null 2>&1; then
    BIN="$(cygpath -w "$BIN")"
    OUT_DIR="$(cygpath -w "$OUT_DIR")"
    HOST_OUT="$(cygpath -u "$OUT_DIR")"
else
    HOST_OUT="$OUT_DIR"
fi
mkdir -p "$OUT_DIR"

TARGET_FILE="$OUT_DIR/targets.txt"
PCAP="$OUT_DIR/replay.pcap"
{
    for ((i = 1; i <= TARGETS; i++)); do
        printf '10.0.%d.%d\n' "$((i / 256))" "$((i % 256))"
    done
} > "$TARGET_FILE"

echo "==> generating $TARGETS targets x ports $PORTS"
"$PYTHON" "$ROOT/tests/large-batch/make_pcap.py" \
    --out "$PCAP" \
    --targets "$TARGET_FILE" \
    --ports "$PORTS" \
    --ip-me "$IP_ME" \
    --source-port "$SOURCE_PORT" \
    --seed "$SEED" \
    --pps "$PCAP_PPS"

EXPECTED=$((TARGETS * ($(echo "$PORTS" | awk -F- '{print $2 - $1 + 1}'))))
echo "==> expected $EXPECTED open results (pcap pacing $PCAP_PPS pps)"

run_replay() {
    local name="$1"
    local module="$2"
    local handlers="$3"
    local out="/out/$name"
    local host_out="$OUT_DIR/$name"
    echo "--- $name (output=$module, handlers=$handlers)"
    docker run --rm --network none \
        -v "$BIN:/xtate:ro" \
        -v "$OUT_DIR:/out" \
        "$IMAGE" bash -lc "
            /xtate -iL /out/targets.txt -p '$PORTS' \
              -scan tcp-syn \
              --adapter file:/out/replay.pcap \
              --source-ip $IP_ME \
              --source-mac 02-00-00-00-00-01 \
              --router-mac 02-00-00-00-00-02 \
              -source-port $SOURCE_PORT-$(($SOURCE_PORT + 15)) \
              -seed $SEED -rx-handler-count $handlers \
              --dispatch-buf-count $DISPATCH_BUF \
              --wait 2 --no-status -show info -show failed \
              -output-module $module -output-file $out"
    test -s "$host_out" || {
        echo "output file is empty: $host_out" >&2
        return 1
    }
}

run_replay replay-ndjson ndjson "$HANDLERS"
run_replay replay-csv csv "$HANDLERS"
run_replay replay-bson bson "$HANDLERS"
run_replay replay-text text "$HANDLERS"

lines=$(wc -l < "$HOST_OUT/replay-ndjson" | tr -d ' ')
open=$(grep -c '"classification":"open"' "$HOST_OUT/replay-ndjson" || true)
closed=$(grep -c '"classification":"closed"' "$HOST_OUT/replay-ndjson" || true)
echo "ndjson: lines=$lines open=$open closed=$closed"
[[ "$lines" -eq "$EXPECTED" ]]
[[ "$open" -eq "$EXPECTED" ]]
[[ "$closed" -eq 0 ]]

csv_lines=$(wc -l < "$HOST_OUT/replay-csv" | tr -d ' ')
echo "csv: lines=$csv_lines"
[[ "$csv_lines" -eq $((EXPECTED + 1)) ]]

bson_bytes=$(wc -c < "$HOST_OUT/replay-bson" | tr -d ' ')
echo "bson: bytes=$bson_bytes"
[[ "$bson_bytes" -gt 1000 ]]

text_lines=$(wc -l < "$HOST_OUT/replay-text" | tr -d ' ')
echo "text: lines=$text_lines"
[[ "$text_lines" -eq "$EXPECTED" ]]

echo "==> replay test passed"
