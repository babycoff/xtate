#!/usr/bin/env bash
# Recorded HTTP-state replay fixture.  The capture contains only the server
# side of a local plaintext HTTP exchange; replay is deterministic and needs no
# TLS or live target.
#
# The captured server ACKs a 91-byte HTTP request.  Pin User-Agent to a fixed
# 46-byte value so the request length stays 91 bytes across version bumps.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${XTATE_BIN:-$ROOT/xtate}"
TMP="${TMPDIR:-/tmp}/xtate-http-state-pcap.$$"
UA="xtate-pcap-fixture/1.0-xxxxxxxxxxxxxxxxxxxxxxx"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"
[[ -x "$BIN" ]] || { echo "xtate binary not found: $BIN" >&2; exit 1; }

run() {
    local name="$1"; local probe_args="$2"
    local log="$TMP/$name.log"
    "$BIN" -ip 172.20.0.2 -p 8080 -scan tcp-state -probe http-state \
        -probe-arg "--user-agent=$UA $probe_args" \
        --adapter "file:$ROOT/tests/http-state-pcap/httpstate.pcap" \
        --source-ip 172.20.0.3 \
        --source-mac 02-00-00-00-00-01 \
        --router-mac 02-00-00-00-00-02 \
        -source-port 40000-40255 -seed 123 \
        --no-resume-file --wait 2 --no-status -show info -show failed \
        >"$log" 2>&1
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

log=$(run status '')
expect "$log" 'http_status: 200'
expect "$log" 'http_body_len: 0'

log=$(run header-match '--keyword=SimpleHTTP --match-scope=headers')
expect "$log" 'http_match: 1'
expect "$log" 'http_match_scope: "headers"'

log=$(run no-match '--keyword=absent --match-scope=body')
expect "$log" 'http_match: 0'
expect "$log" '"not matched"'

echo "PASS: HTTP-state recorded pcap matrix"
