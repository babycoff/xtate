#!/usr/bin/env bash
# ZBanner offline pcap regression matrix.
#
# The scanner reads the fixtures through the receive-only `file:` adapter, so
# this test needs no network, raw socket, or firewall.  Every fixture ends with
# an invalid trailer so the receive thread does not finish before the last
# valid response is dispatched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/xtate}"
PYTHON="${PYTHON:-python3}"
TMP="${TMPDIR:-/tmp}/xtate-zbanner-pcap.$$"
trap 'rm -rf "$TMP"' EXIT

if [[ ! -x "$BIN" ]]; then
    echo "xtate binary not found: $BIN" >&2
    exit 1
fi
mkdir -p "$TMP"

common=(
    -p 8080
    -scan zbanner
    --adapter "file:$TMP/FIXTURE"
    --source-mac 02-00-00-00-00-01
    --router-mac 02-00-00-00-00-02
    -source-port 40000-40255
    -seed 123
    --no-resume-file
    --wait 2
    --no-status
    -show info
)

gen() {
    "$PYTHON" "$ROOT/tests/zbanner/make_fixture.py" --out "$TMP/$1.pcap" "${@:2}"
}

run_fixture() {
    local name="$1"; shift
    local log="$TMP/$name.log"
    "$BIN" -ip 192.0.2.2 --source-ip 192.0.2.1 \
        "${common[@]//FIXTURE/$name.pcap}" "$@" >"$log" 2>&1
    echo "$log"
}

run_fixture6() {
    local name="$1"; shift
    local log="$TMP/$name.log"
    "$BIN" -ip 2001:db8::2 --source-ip 2001:db8::1 \
        "${common[@]//FIXTURE/$name.pcap}" "$@" >"$log" 2>&1
    echo "$log"
}

expect_grep() {
    local log="$1" pattern="$2"
    if ! grep -q "$pattern" "$log"; then
        echo "FAIL: expected '$pattern' in $log" >&2
        cat "$log" >&2
        exit 1
    fi
}

expect_no_grep() {
    local log="$1" pattern="$2"
    if grep -q "$pattern" "$log"; then
        echo "FAIL: unexpected '$pattern' in $log" >&2
        cat "$log" >&2
        exit 1
    fi
}

# 1. SYNACK only -> open.
gen synack --mode synack
log=$(run_fixture synack -probe http -probe-arg '--user-agent=a')
expect_grep "$log" '"open" because "syn-ack"'
grep -q '\[\*\]=1' "$log"

# 2. RST -> closed.
gen rst --mode rst
log=$(run_fixture rst -probe http -probe-arg '--user-agent=a')
expect_grep "$log" '"closed" because "rst"'

# 3. One banner segment -> responsed; the HTTP parser sees the body.
gen banner --mode banner --payload-len 47 --segments 1
log=$(run_fixture banner -probe http -probe-arg '--user-agent=a')
expect_grep "$log" '"responsed" because "ack with data"'
expect_grep "$log" 'http_status: 200'

# 3b. Retransmitted banner in all-banner mode: banner idx is the approximate
#     zero-based dedup repeat counter (0 -> 1); banner seqno is the TCP field.
gen retrans --mode banner --payload-len 47 --segments 1 --retransmit
log=$(run_fixture retrans -probe http -probe-arg '--user-agent=a' -scan-arg '--all-banner')
expect_grep "$log" 'banner idx: 0'
expect_grep "$log" 'banner idx: 1'

# 4. Two banner segments with all-banner limit 2: both recorded, the second is
#    the documented limit-triggering segment.
gen all2 --mode banner --payload-len 47 --segments 2
log=$(run_fixture all2 -probe http -probe-arg '--user-agent=a' -scan-arg '--all-banner --all-banner-limit 2')
expect_grep "$log" 'banner idx: 0'
expect_grep "$log" 'banner idx: 1'
expect_grep "$log" 'truncated: 1'

# 5. A banner ACK computed from the wrong payload length must not be accepted as
#    a banner. This is the negative control for the actual-length fix.
gen wrongack --mode wrong-ack --payload-len 47 --segments 1
log=$(run_fixture wrongack -probe http -probe-arg '--user-agent=a')
expect_grep "$log" '"open" because "syn-ack"'
expect_no_grep "$log" 'banner idx:'

# 6. Payload contract mismatch: Lua declares length 1 but emits 4 bytes. The
#    pcap ACK uses 4, so validation must use the actual make_payload length.
if "$BIN" --help-probe lua-tcp >/dev/null 2>&1; then
    gen mismatch --mode banner --payload-len 4 --segments 1
    log=$(run_fixture mismatch \
        -probe lua-tcp \
        -probe-arg "--script=$ROOT/tests/zbanner/lua-payload-mismatch.lua")
    expect_grep "$log" 'payload_len_declared: 1'
    expect_grep "$log" 'payload_len_actual: 4'
    expect_grep "$log" 'payload_contract_error: 1'
    expect_grep "$log" '"lua-banner" because "matched"'
else
    echo "SKIP: lua-tcp probe not built; payload mismatch fixture skipped"
fi

# 7. IPv6: SYN-ACK and banner must use the IPv6 cookie/packet path.
gen ipv6 --mode banner --payload-len 47 --segments 1 \
    --ip-version 6 --target 2001:db8::2 --ip-me 2001:db8::1
log=$(run_fixture6 ipv6 -probe http -probe-arg '--user-agent=a')
expect_grep "$log" '"open" because "syn-ack"'
expect_grep "$log" '"responsed" because "ack with data"'

# 8. Zero-window SYN-ACK -> fake-open; no banner ACK path is entered.
gen zerowin --mode synack --window 0
log=$(run_fixture zerowin -probe http -probe-arg '--user-agent=a')
expect_grep "$log" '"fake-open" because "zerowin"'
expect_no_grep "$log" 'banner idx:'

# 9. all-banner floor 2: the first segment is suppressed, later segments are
#    recorded with their approximate dedup indexes.
gen floor2 --mode banner --payload-len 47 --segments 3
log=$(run_fixture floor2 -probe http -probe-arg '--user-agent=a' -scan-arg '--all-banner --all-banner-floor 2')
expect_no_grep "$log" 'banner idx: 0'
expect_grep "$log" 'banner idx: 1'
expect_grep "$log" 'banner idx: 2'

echo "PASS: ZBanner pcap offline regression matrix"
