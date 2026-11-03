#!/usr/bin/env bash
# Local lab benchmark for the real packet path.
#
# This is a Linux/Docker-only benchmark. It creates a private bridge network,
# a multi-port HTTP target and an optional packet sink, then runs the scanner
# from a second container on the same bridge. It never touches the public
# Internet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/bin/xtate}"
IMAGE="${XTATE_BENCH_LAB_IMAGE:-${XTATE_LAB_IMAGE:-xtate-builder:24.04}}"
OUT="${XTATE_BENCH_OUT:-$ROOT/bench-results/lab-$(date +%Y%m%d-%H%M%S)}"
QUICK="${XTATE_BENCH_QUICK:-0}"
CASE_FILTER="${XTATE_BENCH_CASE:-all}"
CN="${XTATE_CN_MIRROR:-0}"
NET="xtate-bench-$$"
TARGET="xtate-bench-target-$$"
SCANNER="xtate-bench-scanner-$$"
HTTP_FIRST=10000
TARGET_ALIAS_FIRST=10
TARGET_ALIAS_LAST=15
if [[ "$QUICK" == "1" ]]; then
    HTTP_LAST=10255
    CLOSED_FIRST=51000
    CLOSED_LAST=51255
    TX_FIRST=31000
    TX_LAST=31255
else
    HTTP_LAST=30047
    CLOSED_FIRST=51000
    CLOSED_LAST=65535
    TX_FIRST=31000
    TX_LAST=50999
fi

if [[ ! -f "$BIN" ]]; then
    echo "xtate binary not found: $BIN" >&2
    exit 1
fi

if command -v cygpath >/dev/null 2>&1; then
    # Git Bash must not rewrite Docker-side paths such as /xtate.
    export MSYS_NO_PATHCONV=1
    BIN_HOST="$(cygpath -w "$BIN")"
    ROOT_HOST="$(cygpath -w "$ROOT")"
    OUT_HOST="$(cygpath -w "$OUT")"
else
    BIN_HOST="$BIN"
    ROOT_HOST="$ROOT"
    OUT_HOST="$OUT"
fi
mkdir -p "$OUT"

cleanup() {
    docker rm -f "$SCANNER" "$TARGET" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

APT_REFRESH=""
if [[ "$CN" == "1" ]]; then
    APT_REFRESH='
        sed -i "s|http://archive.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g;
                s|http://security.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g" \
            /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true
        sed -i "s|http://archive.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g;
                s|http://security.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g" \
            /etc/apt/sources.list 2>/dev/null || true
    '
fi

echo "==> network $NET"
docker network create --subnet=172.30.0.0/24 "$NET" >/dev/null

echo "==> target container"
docker run -d --name "$TARGET" --network "$NET" \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$ROOT_HOST/tests/bench/lab-http.py:/lab-http.py:ro" \
    -v "$ROOT_HOST/tests/bench/lab-count.py:/lab-count.py:ro" \
    "$IMAGE" sleep infinity >/dev/null

docker exec "$TARGET" bash -lc "
    set -e
    $APT_REFRESH
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        python3 iptables iproute2 >/dev/null
    ulimit -n 65535
    nohup python3 /lab-http.py $HTTP_FIRST $HTTP_LAST \
        >/tmp/lab-http.log 2>&1 &
    nohup python3 /lab-count.py $TX_FIRST $TX_LAST /tmp/tx.count \
        >/tmp/lab-count.log 2>&1 &
    iptables -A INPUT -p tcp --dport $TX_FIRST:$TX_LAST -j DROP
"

echo "==> scanner container"
docker run -d --name "$SCANNER" --network "$NET" \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    -v "$BIN_HOST:/xtate:ro" \
    -v "$OUT_HOST:/bench-out" \
    "$IMAGE" sleep infinity >/dev/null

docker exec "$SCANNER" bash -lc "
    set -e
    $APT_REFRESH
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables >/dev/null
    iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
"

TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET")"
if [[ -z "$TARGET_IP" ]]; then
    echo "could not determine target IP" >&2
    exit 1
fi
TARGET_PREFIX="${TARGET_IP%.*}"
for i in $(seq "$TARGET_ALIAS_FIRST" "$TARGET_ALIAS_LAST"); do
    docker exec "$TARGET" ip addr add "$TARGET_PREFIX.$i/32" \
        dev eth0 >/dev/null 2>&1 || true
done
TARGET_RANGE="$TARGET_PREFIX.2,$TARGET_PREFIX.$TARGET_ALIAS_FIRST-$TARGET_PREFIX.$TARGET_ALIAS_LAST"
echo "    target: $TARGET_IP (aliases .$TARGET_ALIAS_FIRST-.$TARGET_ALIAS_LAST)"

wait_port() {
    local port="$1"
    for _ in $(seq 1 120); do
        if docker exec "$TARGET" bash -c \
            "timeout 1 bash -c '</dev/tcp/127.0.0.1/$port'" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "target port $port did not become ready" >&2
    return 1
}
wait_port "$HTTP_FIRST"

RESULTS="$OUT/results.jsonl"
: >"$RESULTS"

target_drop_count() {
    docker exec "$TARGET" iptables -L INPUT -v -n 2>/dev/null \
        | awk '$3 == "DROP" {sum += $1} END {print sum + 0}'
}

target_tx_count() {
    docker exec "$TARGET" cat /tmp/tx.count 2>/dev/null || echo 0
}

run_case() {
    local name="$1"
    local targets="$2"
    shift 2
    local stdout="$OUT/$name.stdout"
    local stderr="$OUT/$name.stderr"
    local datafile="$OUT/$name.data"
    local start end elapsed rc packets results tcb_drop
    local before after drop_before

    rm -f "$datafile"
    before="$(target_tx_count)"
    drop_before="$(target_drop_count)"
    start="$(date +%s%N)"
    set +e
    docker exec "$SCANNER" /xtate "$@" >"$stdout" 2>"$stderr"
    rc=$?
    set -e
    end="$(date +%s%N)"
    elapsed=$(((end - start) / 1000000))
    after="$(target_tx_count)"
    packets=$((after - before))
    if ((packets <= 0)); then
        packets=$(( $(target_drop_count) - drop_before ))
    fi
    if [[ -s "$datafile" ]]; then
        results=$(wc -l <"$datafile")
    else
        results=$(grep -c 'host:' "$stdout" 2>/dev/null || true)
    fi

    tcb_drop=$(grep -ho 'drop=[0-9]*' "$stdout" "$stderr" 2>/dev/null | tail -1 | cut -d= -f2 || true)
    tcb_drop=${tcb_drop:-0}

    printf '{"case":"%s","targets":%s,"elapsed_ms":%s,"rc":%s,"target_packets":%s,"result_lines":%s,"tcb_drop":%s}\n' \
        "$name" "$targets" "$elapsed" "$rc" "$packets" "$results" "$tcb_drop" >>"$RESULTS"
    printf '%-24s %8s ms  packets=%7s  results=%6s  rc=%s\n' \
        "$name" "$elapsed" "$packets" "$results" "$rc"

    if ((rc != 0)); then
        echo "FAILED: $name (see $stderr)" >&2
        tail -20 "$stderr" >&2 || true
        return "$rc"
    fi
}

want() {
    [[ "$CASE_FILTER" == "all" || "$CASE_FILTER" == "$1" ]]
}

if want tx; then
    run_case "tx-syn-lab" "$(((TX_LAST - TX_FIRST + 1) * 7))" \
        -ip "$TARGET_RANGE" -p "$TX_FIRST-$TX_LAST" -scan tcp-syn \
        --rate 10000 --wait 2 --no-status --no-resume-file -out null
fi

if want zbanner; then
    run_case "zbanner-http-lab" "$(((HTTP_LAST - HTTP_FIRST + 1) * 7))" \
        -ip "$TARGET_RANGE" -p "$HTTP_FIRST-$HTTP_LAST" -scan zbanner -probe http \
        --rate 5000 --wait 1 --no-status --no-resume-file
fi

if want output; then
    for mod in null text csv ndjson; do
        if [[ "$mod" == "null" ]]; then
            run_case "output-$mod" "$(((CLOSED_LAST - CLOSED_FIRST + 1) * 7))" \
                -ip "$TARGET_RANGE" -p "$CLOSED_FIRST-$CLOSED_LAST" \
                -scan tcp-syn --rate 50000 --wait 0 --no-status \
                --no-resume-file -show failed -out null
        else
            run_case "output-$mod" "$(((CLOSED_LAST - CLOSED_FIRST + 1) * 7))" \
                -ip "$TARGET_RANGE" -p "$CLOSED_FIRST-$CLOSED_LAST" \
                -scan tcp-syn --rate 50000 --wait 0 --no-status \
                --no-resume-file -show failed -out "$mod" \
                -o "/bench-out/output-$mod.data"
        fi
    done
fi

if want stateful; then
    run_case "stateful-tcb-lab" "$((HTTP_LAST - HTTP_FIRST + 1))" \
        -ip "$TARGET_IP" -p "$HTTP_FIRST-$HTTP_LAST" \
        -scan tcp-state -probe http-state \
        -scan-arg "--tcb-mem=1" --rate 50000 --wait 1 \
        --no-resume-file -out null
fi

echo
echo "results: $RESULTS"
