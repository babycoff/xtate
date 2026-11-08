#!/usr/bin/env bash
# Offline HTTP response-matching matrix: no network, no root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/xtate}"
PYTHON="${PYTHON:-python3}"
TMP="${TMPDIR:-/tmp}/xtate-http-pcap.$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"
[[ -x "$BIN" ]] || { echo "xtate binary not found: $BIN" >&2; exit 1; }

"$PYTHON" "$ROOT/tests/http-pcap/make_fixture.py" --out "$TMP/http.pcap"

run() {
    local name="$1"; local probe_args="$2"; shift 2
    local log="$TMP/$name.log"
    "$BIN" -ip 192.0.2.2 -p 8080 -scan zbanner -probe http \
        -probe-arg "--user-agent=a $probe_args" \
        --adapter "file:$TMP/http.pcap" \
        --source-ip 192.0.2.1 \
        --source-mac 02-00-00-00-00-01 \
        --router-mac 02-00-00-00-00-02 \
        -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 2 --no-status -show info -show failed \
        "$@" >"$log" 2>&1
    echo "$log"
}

expect() {
    local log="$1" pattern="$2"
    grep -q "$pattern" "$log" || {
        echo "FAIL: expected '$pattern' in $log" >&2
        cat "$log" >&2
        exit 1
    }
}

log=$(run body '--keyword=hello --match-scope=body')
expect "$log" 'http_match: 1'
expect "$log" 'http_match_scope: "body"'
expect "$log" 'http_match_kind: "keyword"'
expect "$log" '"matched"'

log=$(run header-regex '--regex=Server --match-scope=headers')
expect "$log" 'http_match: 1'
expect "$log" 'http_match_scope: "headers"'
expect "$log" 'http_match_kind: "regex"'

log=$(run case-insensitive '--keyword=SERVER --match-scope=headers --case-insensitive')
expect "$log" 'http_match: 1'

log=$(run no-match '--keyword=absent --match-scope=body')
expect "$log" 'http_match: 0'
expect "$log" '"not matched"'
expect "$log" '"no match"'
expect "$log" 'http_status: 200'

echo "PASS: HTTP pcap offline matching matrix"
