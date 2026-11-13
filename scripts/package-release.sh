#!/usr/bin/env bash
# Package a Linux release tree and emit SHA256SUMS + build provenance.
#
# Usage: scripts/package-release.sh --binary reports/docker-out/xtate-linux \
#          --version 3.0.0-rc.7 [--out dist] [--docker-image xtate:ubuntu24-full]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY=""
VERSION=""
OUT="$ROOT/dist"
IMAGE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --docker-image) IMAGE="$2"; shift 2 ;;
        -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

[[ -n "$BINARY" && -n "$VERSION" ]] || { echo "--binary and --version are required" >&2; exit 1; }
[[ -x "$BINARY" ]] || { echo "binary is not executable: $BINARY" >&2; exit 1; }

cd "$ROOT"
STAGE_NAME="xtate-$VERSION-linux-x86_64"
STAGE="$OUT/$STAGE_NAME"
rm -rf "$STAGE"
mkdir -p "$STAGE"

cp "$BINARY" "$STAGE/xtate"
chmod 0755 "$STAGE/xtate"
for item in LICENSE README.md README.zh-CN.md docs schemas skills firewall; do
    [[ -e "$item" ]] && cp -a "$item" "$STAGE/"
done
chmod 0755 "$STAGE/firewall/"*.sh 2>/dev/null || true

"$STAGE/xtate" --list-capabilities > "$STAGE/capabilities.json"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
    echo "product=Xtate"
    echo "version=$VERSION"
    echo "platform=linux-x86_64"
    echo "commit=$COMMIT"
    echo "built_at_utc=$BUILT_AT"
    if [[ -n "$IMAGE" ]]; then
        echo "docker_image=$IMAGE"
        echo "docker_image_id=$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || echo unknown)"
    fi
} > "$STAGE/BUILD-INFO.txt"
cp "$STAGE/capabilities.json" "$OUT/capabilities-linux.json"

ARCHIVE="$OUT/$STAGE_NAME.tar.gz"
rm -f "$ARCHIVE"
tar -C "$OUT" -czf "$ARCHIVE" "$STAGE_NAME"
( cd "$OUT" && sha256sum "$(basename "$ARCHIVE")" > SHA256SUMS-linux.txt )
echo "wrote $ARCHIVE"
cat "$OUT/SHA256SUMS-linux.txt"
