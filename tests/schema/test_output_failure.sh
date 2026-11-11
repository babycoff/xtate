#!/usr/bin/env bash
# End-to-end output write failure: every file output must fail and exit non-zero.
set -euo pipefail
BIN="${XTATE_BIN:-${1:-}}"
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "usage: XTATE_BIN=/path/to/xtate $0" >&2
    exit 2
fi
for module in text ndjson csv bson list; do
    set +e
    "$BIN" -ip 127.0.0.1 -p 1 -scan tcp-syn \
        --output-module "$module" --output-file /dev/full \
        --show failed --no-resume-file --wait 1 --no-status \
        >/tmp/xtate-out-fail.out 2>/tmp/xtate-out-fail.err
    rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        echo "FAIL: $module exited 0 writing /dev/full" >&2
        cat /tmp/xtate-out-fail.err >&2
        exit 1
    fi
    if ! grep -Eq "could not (write|flush|close)" /tmp/xtate-out-fail.err; then
        echo "FAIL: $module produced no output error" >&2
        cat /tmp/xtate-out-fail.err >&2
        exit 1
    fi
    echo "$module: exit=$rc output error detected"
done
echo "output failure: PASS"
