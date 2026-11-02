#!/usr/bin/env bash
# Target-address syntax tests, including sparse component ranges.
set -euo pipefail

BIN="${XTATE_BIN:-./bin/xtate}"
if [[ ! -x "$BIN" && -x "${BIN}.exe" ]]; then
    BIN="${BIN}.exe"
fi
if [[ -f "$BIN" ]]; then
    BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
fi
if [[ ! -x "$BIN" ]]; then
    echo "SKIP: xtate binary not found (set XTATE_BIN)" >&2
    exit 0
fi

tmp="${XTATE_TEST_TMP:-$PWD/.xtate-target-test.$$}"
mkdir -p "$tmp"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

fail=0
check() {
    if eval "$2"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1" >&2
        fail=$((fail + 1))
    fi
}

# IPv4: vary one octet, keep the remaining octets fixed.
out="$("$BIN" -ip "132.80-88.90.15" -p 80 -list-range 2>&1 || true)"
check "IPv4 component range count" \
      "[[ \$(printf '%s\n' \"\$out\" | grep -c '^132\.' || true) == 9 ]]"
check "IPv4 component range first" \
      "printf '%s' \"\$out\" | grep -q '132.80.90.15'"
check "IPv4 component range last" \
      "printf '%s' \"\$out\" | grep -q '132.88.90.15'"

# IPv6: vary one hextet through a compressed address.
out="$("$BIN" -ip "2001:db8:1-3::1" -p 80 -list-range 2>&1 || true)"
check "IPv6 component range count" \
      "[[ \$(printf '%s\n' \"\$out\" | grep -c '^2001:db8:' || true) == 3 ]]"
check "IPv6 component range first" \
      "printf '%s' \"\$out\" | grep -q '2001:db8:1::1'"
check "IPv6 component range last" \
      "printf '%s' \"\$out\" | grep -q '2001:db8:3::1'"

# Target files use the same syntax.
printf '%s\n' \
    '# component ranges' \
    '132.80-88.90.15' \
    '2001:db8:1-3::1' >targets.txt
out="$("$BIN" -iL targets.txt -p 80 -list-range 2>&1 || true)"
check "target file component ranges" \
      "err=\$(printf '%s' \"\$out\" | grep -c 'invalid' || true); [[ \$err == 0 ]]"
check "target file IPv4 included" \
      "printf '%s' \"\$out\" | grep -q '132.81.90.15'"
check "target file IPv6 included" \
      "printf '%s' \"\$out\" | grep -q '2001:db8:2::1'"

# Excludes use the same component syntax.
out="$("$BIN" -ip "132.80-88.90.15" -exclude "132.81-83.90.15" \
      -p 80 -list-range 2>&1 || true)"
check "component range exclude" \
      "printf '%s' \"\$out\" | grep -q '132.84.90.15'"
check "excluded component absent" \
      "! printf '%s' \"\$out\" | grep -q '132.81.90.15'"

# Cartesian products: up to four variable components.
"$BIN" -ip "1-2.3-4.5.6" -p 80 -list-target >product2.txt 2>&1 || true
check "two component ranges product count" \
      "[[ \$(grep -c '^[0-9]' product2.txt) == 4 ]]"

"$BIN" -ip "1-2.3-4.5-6.7" -p 80 -list-target >product3.txt 2>&1 || true
check "three component ranges product count" \
      "[[ \$(grep -c '^[0-9]' product3.txt) == 8 ]]"

"$BIN" -ip "1-2.3-4.5-6.7-8" -p 80 -list-target >product4.txt 2>&1 || true
check "four component ranges product count" \
      "[[ \$(grep -c '^[0-9]' product4.txt) == 16 ]]"
check "four component ranges endpoint" "grep -q '2.4.6.8' product4.txt"

"$BIN" -ip "2001:db8:1-2:3-4:5-6:7-8::1" -p 80 -list-target \
      >product6.txt 2>&1 || true
check "IPv6 four component ranges product count" \
      "[[ \$(grep -c '^[0-9]' product6.txt) == 16 ]]"

if "$BIN" -ip "0-255.0-255.0-255.0-255" -p 80 -list-target \
        >/dev/null 2>&1; then
    check "oversized product rejected" "false"
else
    check "oversized product rejected" "true"
fi

if ((fail != 0)); then
    echo "$fail target test(s) failed" >&2
    exit 1
fi
