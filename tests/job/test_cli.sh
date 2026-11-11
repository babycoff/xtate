#!/usr/bin/env bash
set -euo pipefail
BIN="${XTATE_BIN:?set XTATE_BIN}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat >"$TMP/req.json" <<'JSON'
{"scan":"tcp-syn","targets":["127.0.0.1"],"ports":[1],"timeout_sec":3}
JSON
"$BIN" --job-run="$TMP/req.json" --job-result="$TMP/out.ndjson" --job-timeout=5 >"$TMP/job.txt"
grep -q '"state":"completed"' "$TMP/job.txt"
test -s "$TMP/out.ndjson"
test -s "$TMP/out.ndjson.heartbeat"
"$BIN" --job-run="$TMP/req.json" --job-result="$TMP/to.ndjson" --job-timeout=1 >"$TMP/to.txt" || true
grep -q '"state":"timed_out"' "$TMP/to.txt"
echo "job CLI: PASS"
