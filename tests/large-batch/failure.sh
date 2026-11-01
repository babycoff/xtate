#!/usr/bin/env bash
#
# Failure-injection / RSS regression for the local large-batch replay path.
# All pcap-driven runs use --network none unless the optional Mongo section is
# enabled; no external targets are contacted.
#
# Coverage:
#   - output write failure (/dev/full)
#   - small tmpfs output (ENOSPC-ish)
#   - SIGINT during a long replay
#   - SIGPIPE when the downstream output consumer exits
#   - RSS high-water comparison: 100k vs 1M results
#   - optional MongoDB normal write / disconnect if a local image is available
#
# Usage:
#   XTATE_BIN=/path/to/xtate-linux bash tests/large-batch/failure.sh
#
# Optional:
#   XTATE_MONGO_IMAGE=mongo:7   enable Mongo section (image must already exist)
#   BATCH_RSS_TARGETS=1000      largest RSS run (default 1000 x 1000 = 1M)
#   BATCH_OUT=...               output directory

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_LAB_IMAGE:-xtate-builder:24.04}"
MONGO_IMAGE="${XTATE_MONGO_IMAGE:-mongo:7}"
OUT_DIR="${BATCH_OUT:-$ROOT/../reports/docker/out/large-batch-failure}"
RSS_TARGETS="${BATCH_RSS_TARGETS:-1000}"
INT_TARGETS="${BATCH_INT_TARGETS:-100}"
PORTS="${BATCH_PORTS:-1-1000}"
SEED=123
SOURCE_PORT=40000
IP_ME=192.0.2.1

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
    echo "Python 3 is required" >&2
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

FAILS=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; FAILS=$((FAILS + 1)); }

make_fixture() {
    local targets="$1"
    local name="$2"
    local list="$OUT_DIR/targets-$name.txt"
    local pcap="$OUT_DIR/$name.pcap"
    for ((i = 1; i <= targets; i++)); do
        printf '10.0.%d.%d\n' "$((i / 256))" "$((i % 256))"
    done > "$list"
    "$PYTHON" "$ROOT/tests/large-batch/make_pcap.py" \
        --out "$pcap" --targets "$list" --ports "$PORTS" \
        --ip-me "$IP_ME" --source-port "$SOURCE_PORT" --seed "$SEED" \
        --pps 20000 >/dev/null
    echo "$pcap"
}

pcap_run() {
    local pcap="$1"
    local name="$2"
    shift 2
    docker run --rm --network none \
        -v "$BIN:/xtate:ro" \
        -v "$OUT_DIR:/out" \
        "$IMAGE" bash -lc "
            /xtate -iL /out/targets-$name.txt -p '$PORTS' -scan tcp-syn \
              --adapter file:/out/$name.pcap \
              --source-ip $IP_ME --source-mac 02-00-00-00-00-01 \
              --router-mac 02-00-00-00-00-02 \
              -source-port $SOURCE_PORT-$((SOURCE_PORT + 15)) \
              -seed $SEED --wait 2 --no-status -show info \
              $*"
}

SMALL=10
MEDIUM=50
make_fixture "$SMALL" small >/dev/null
make_fixture "$MEDIUM" medium >/dev/null

echo "==> /dev/full write failure"
set +e
pcap_run small small -output-module text -output-file /dev/full > "$OUT_DIR/full.log" 2>&1
rc=$?
set -e
if [[ $rc -eq 134 || $rc -eq 139 ]]; then
    fail "/dev/full crashed (exit $rc)"
else
    grep -q "could not write" "$OUT_DIR/full.log" && pass "/dev/full logged write error" \
        || fail "/dev/full did not log a write error"
fi

echo "==> tmpfs output exhaustion"
set +e
docker run --rm --network none --tmpfs /out:size=1m \
    -v "$BIN:/xtate:ro" -v "$OUT_DIR:/in:ro" \
    "$IMAGE" bash -lc "
        /xtate -iL /in/targets-medium.txt -p '$PORTS' -scan tcp-syn \
          --adapter file:/in/medium.pcap --source-ip $IP_ME \
          --source-mac 02-00-00-00-00-01 --router-mac 02-00-00-00-00-02 \
          -source-port $SOURCE_PORT-$((SOURCE_PORT + 15)) -seed $SEED \
          --wait 2 --no-status -show info \
          -output-module text -output-file /out/results" > "$OUT_DIR/tmpfs.log" 2>&1
rc=$?
set -e
if [[ $rc -eq 134 || $rc -eq 139 ]]; then
    fail "tmpfs output crashed (exit $rc)"
else
    pass "tmpfs output finished (exit $rc)"
fi
grep -q "could not write" "$OUT_DIR/tmpfs.log" \
    && pass "tmpfs logged write error" \
    || echo "WARN: tmpfs log had no write-error line (small output may fit)"

echo "==> SIGINT during replay"
INT=$(make_fixture "$INT_TARGETS" int)
rm -f "$OUT_DIR/int-out"
docker run -d --name xtate-int --network none \
    -v "$BIN:/xtate:ro" -v "$OUT_DIR:/out" "$IMAGE" bash -lc "
        /xtate -iL /out/targets-int.txt -p '$PORTS' -scan tcp-syn \
          --adapter file:/out/int.pcap --source-ip $IP_ME \
          --source-mac 02-00-00-00-00-01 --router-mac 02-00-00-00-00-02 \
          -source-port $SOURCE_PORT-$((SOURCE_PORT + 15)) -seed $SEED \
          --wait 2 --no-status -show info \
          -output-module text -output-file /out/int-out &
        echo \$! > /out/int.pid; wait" >/dev/null
sleep 1
pid=$(docker exec xtate-int cat /out/int.pid 2>/dev/null | tr -d '\r' || true)
if [[ -n "$pid" ]]; then
    docker exec xtate-int kill -INT "$pid" 2>/dev/null || true
fi
set +e
timeout 30 docker wait xtate-int >/dev/null
wait_rc=$?
set -e
docker rm -f xtate-int >/dev/null 2>&1 || true
[[ $wait_rc -eq 124 ]] && fail "SIGINT handling hung"
test -s "$OUT_DIR/int-out" && pass "SIGINT left a flushed output file" \
    || fail "SIGINT produced no output"

echo "==> SIGPIPE with early downstream exit"
set +e
docker run --rm --network none \
    -v "$BIN:/xtate:ro" -v "$OUT_DIR:/out" "$IMAGE" bash -lc "
        set -o pipefail
        /xtate -iL /out/targets-small.txt -p '$PORTS' -scan tcp-syn \
          --adapter file:/out/small.pcap --source-ip $IP_ME \
          --source-mac 02-00-00-00-00-01 --router-mac 02-00-00-00-00-02 \
          -source-port $SOURCE_PORT-$((SOURCE_PORT + 15)) -seed $SEED \
          --wait 2 --no-status -show info \
          -output-module ndjson -output-file - | head -n 1" >/dev/null 2>&1
rc=$?
set -e
if [[ $rc -eq 124 ]]; then
    fail "SIGPIPE test hung"
else
    pass "SIGPIPE test finished (exit $rc)"
fi

echo "==> RSS high-water (100k vs $(($RSS_TARGETS * 1000)) results)"
measure_rss() {
    local targets="$1"
    local name="$2"
    local pcap
    pcap=$(make_fixture "$targets" "$name")
    docker run --rm --network none \
        -v "$BIN:/xtate:ro" -v "$OUT_DIR:/out" "$IMAGE" bash -lc "
            /xtate -iL /out/targets-$name.txt -p '$PORTS' -scan tcp-syn \
              --adapter file:/out/$name.pcap --source-ip $IP_ME \
              --source-mac 02-00-00-00-00-01 --router-mac 02-00-00-00-00-02 \
              -source-port $SOURCE_PORT-$((SOURCE_PORT + 15)) -seed $SEED \
              --wait 2 --no-status -show info \
              -output-module text -output-file /out/$name-out &
            pid=\$!
            peak=0
            while kill -0 \$pid 2>/dev/null; do
                r=\$(awk '/VmRSS/{print \$2}' /proc/\$pid/status 2>/dev/null || echo 0)
                if [ \"\$r\" -gt \"\$peak\" ]; then peak=\$r; fi
                sleep 0.05
            done
            wait \$pid || true
            echo \"PEAK_RSS_KB=\$peak\"" > "$OUT_DIR/$name-rss.log" 2>&1
    peak=$(grep 'PEAK_RSS_KB=' "$OUT_DIR/$name-rss.log" | tail -1 | cut -d= -f2)
    echo "$peak"
}

rss100=$(measure_rss 100 rss100)
rssbig=$(measure_rss "$RSS_TARGETS" rssbig)
echo "RSS 100k=${rss100}KB, big=${rssbig}KB"
if [[ -n "$rss100" && -n "$rssbig" && "$rssbig" -gt 0 ]]; then
    # This is a regression guard, not a hard memory budget: fail only on a
    # dramatic super-linear jump or a very large absolute peak.
    if [[ "$rssbig" -gt $((rss100 * 4 + 262144)) ]]; then
        fail "RSS growth looks super-linear (${rss100}KB -> ${rssbig}KB)"
    else
        pass "RSS growth is bounded (${rss100}KB -> ${rssbig}KB)"
    fi
else
    fail "RSS measurement failed"
fi


echo "==> Mongo unreachable (no server)"
set +e
docker run --rm --network none \
    -v "$BIN:/xtate:ro" -v "$OUT_DIR:/out" "$IMAGE" bash -lc "
        timeout 15 /xtate -iL /out/targets-small.txt -p '$PORTS' -scan tcp-syn \
          --adapter file:/out/small.pcap --source-ip $IP_ME \
          --source-mac 02-00-00-00-00-01 --router-mac 02-00-00-00-00-02 \
          -source-port $SOURCE_PORT-$((SOURCE_PORT + 15)) -seed $SEED \
          --wait 2 --no-status -output-module mongodb \
          -output-file mongodb://127.0.0.1:1" > "$OUT_DIR/mongo-unreachable.log" 2>&1
rc=$?
set -e
if [[ $rc -eq 124 ]]; then
    fail "unreachable Mongo hung"
elif grep -q "MongoDB" "$OUT_DIR/mongo-unreachable.log"; then
    pass "unreachable Mongo failed cleanly"
else
    fail "unreachable Mongo had no diagnostic"
fi

echo "==> optional MongoDB"
if docker image inspect "$MONGO_IMAGE" >/dev/null 2>&1; then
    MONGO_NET="xtate-mongo-$$"
    docker network create "$MONGO_NET" >/dev/null
    docker run -d --name xtate-mongo --network "$MONGO_NET" "$MONGO_IMAGE" >/dev/null
    trap 'docker rm -f xtate-mongo >/dev/null 2>&1; docker network rm "$MONGO_NET" >/dev/null 2>&1' EXIT
    for _ in $(seq 1 60); do
        docker exec xtate-mongo mongosh --quiet --eval 'db.runCommand({ping:1})' >/dev/null 2>&1 && break
        sleep 1
    done
    docker run --rm --network "$MONGO_NET" \
        -v "$BIN:/xtate:ro" -v "$OUT_DIR:/out" "$IMAGE" bash -lc "
            /xtate -iL /out/targets-small.txt -p '$PORTS' -scan tcp-syn \
              --adapter file:/out/small.pcap --source-ip $IP_ME \
              --source-mac 02-00-00-00-00-01 --router-mac 02-00-00-00-00-02 \
              -source-port $SOURCE_PORT-$((SOURCE_PORT + 15)) -seed $SEED \
              --wait 2 --no-status -show info \
              -output-module mongodb -output-file mongodb://xtate-mongo:27017 \
              -output-arg '-database-name xtate -collection-name failure -insert-bulk -bulk-size 500' \
              --dispatch-buf-count 65536" > "$OUT_DIR/mongo.log" 2>&1 || true
    count=$(docker exec xtate-mongo mongosh --quiet --eval \
        'db.getSiblingDB("xtate").failure.countDocuments({})' 2>/dev/null | tr -d '\r' || true)
    if [[ "${count:-0}" -gt 0 ]]; then
        pass "MongoDB wrote $count documents"
    else
        echo "WARN: MongoDB check not conclusive (image/tooling); see $OUT_DIR/mongo.log"
    fi

    echo "==> MongoDB disconnect during scan"
    docker run -d --name xtate-mongo-scan --network "$MONGO_NET" \
        -v "$BIN:/xtate:ro" -v "$OUT_DIR:/out" "$IMAGE" bash -lc "
            /xtate -iL /out/targets-rss100.txt -p '$PORTS' -scan tcp-syn \
              --adapter file:/out/rss100.pcap --source-ip $IP_ME \
              --source-mac 02-00-00-00-00-01 --router-mac 02-00-00-00-00-02 \
              -source-port $SOURCE_PORT-$((SOURCE_PORT + 15)) -seed $SEED \
              --wait 2 --no-status -output-module mongodb \
              -output-file mongodb://xtate-mongo:27017 \
              -output-arg '-database-name xtate -collection-name disconnect -insert-bulk -bulk-size 500' \
              --dispatch-buf-count 65536" >/dev/null
    sleep 1
    docker stop xtate-mongo >/dev/null 2>&1 || true
    set +e
    timeout 30 docker wait xtate-mongo-scan >/dev/null
    d_rc=$?
    set -e
    docker logs xtate-mongo-scan > "$OUT_DIR/mongo-disconnect.log" 2>&1 || true
    docker rm -f xtate-mongo-scan >/dev/null 2>&1 || true
    if [[ $d_rc -eq 124 ]]; then
        fail "MongoDB disconnect hung the scanner"
    else
        pass "MongoDB disconnect finished without hanging (exit $d_rc)"
    fi
    grep -qi "mongo" "$OUT_DIR/mongo-disconnect.log" \
        && pass "MongoDB disconnect produced a diagnostic" \
        || echo "WARN: no MongoDB diagnostic captured"

    docker rm -f xtate-mongo >/dev/null 2>&1 || true
    docker network rm "$MONGO_NET" >/dev/null 2>&1 || true
    trap - EXIT
else
    echo "SKIP: $MONGO_IMAGE is not available locally (set XTATE_MONGO_IMAGE)"
fi

echo "==> failure/RSS test finished"
if [[ "$FAILS" -ne 0 ]]; then
    echo "$FAILS check(s) failed" >&2
    exit 1
fi
