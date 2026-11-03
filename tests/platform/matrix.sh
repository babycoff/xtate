#!/usr/bin/env bash
#
# Repeatable Linux compatibility matrix in Docker.
#
# Default: upstream images and distribution archives (for general users/CI).
# Mainland China: set XTATE_CN_MIRROR=1 to use DaoCloud/Aliyun mirrors.
#
# Usage:
#   bash tests/platform/matrix.sh
#   XTATE_CN_MIRROR=1 bash tests/platform/matrix.sh
#
# Requires Docker and network access. The repository is mounted read-only and
# copied inside each container, so no build trees land in the working tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then
    # Git Bash/Docker Desktop wants a Windows path for -v.
    HOST_ROOT="$(cygpath -w "$ROOT")"
else
    HOST_ROOT="$ROOT"
fi
CN="${XTATE_CN_MIRROR:-0}"
DOCKER="${DOCKER:-docker}"

if ! command -v "$DOCKER" >/dev/null 2>&1; then
    echo "SKIP: docker is not available" >&2
    exit 0
fi

if [[ "$CN" == "1" ]]; then
    DEBIAN_IMAGE="docker.m.daocloud.io/library/debian:10-slim"
    ALPINE_IMAGE="docker.m.daocloud.io/library/alpine:3.20"
    DEBIAN_MAIN="http://mirrors.aliyun.com/debian-archive/debian"
    DEBIAN_SEC="http://mirrors.aliyun.com/debian-archive/debian-security"
    ALPINE_MAIN="http://mirrors.aliyun.com/alpine/v3.20/main"
    ALPINE_COMMUNITY="http://mirrors.aliyun.com/alpine/v3.20/community"
else
    DEBIAN_IMAGE="debian:10-slim"
    ALPINE_IMAGE="alpine:3.20"
    DEBIAN_MAIN="http://archive.debian.org/debian"
    DEBIAN_SEC="http://archive.debian.org/debian-security"
    ALPINE_MAIN="https://dl-cdn.alpinelinux.org/alpine/v3.20/main"
    ALPINE_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/v3.20/community"
fi

run_debian10() {
    echo "===== Debian 10 / GCC 8 / CMake 3.13 (Make + Ninja)"
    "$DOCKER" run --rm -v "$HOST_ROOT:/src:ro" "$DEBIAN_IMAGE" bash -lc "
set -e
cat > /etc/apt/sources.list <<EOF
deb $DEBIAN_MAIN buster main
deb $DEBIAN_SEC buster/updates main
EOF
apt-get update -qq
apt-get install -y -qq build-essential cmake pkg-config libpcap-dev \
    libssl-dev ninja-build
mkdir -p /work
cp -a /src /work/xtate
cd /work/xtate
sed -i 's/\r\$//' build.sh
bash build.sh --compiler gcc --config release --generator make
./bin/xtate --selftest
rm -rf build-gcc-release-make
bash build.sh --compiler gcc --config release --generator ninja
./bin/xtate --selftest

# Exercise compile-time fallbacks for old libc interfaces.
cmake -S . -B /tmp/build-fallback -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS='-DXTATE_NO_SENDMMSG -DXTATE_NO_PTHREAD_SETNAME' >/dev/null
cmake --build /tmp/build-fallback -j 2 >/dev/null
/tmp/build-fallback/xtate --selftest
"
}

run_alpine() {
    echo "===== Alpine 3.20 / musl / GCC 13 (Ninja + static minimal)"
    "$DOCKER" run --rm -v "$HOST_ROOT:/src:ro" "$ALPINE_IMAGE" sh -c "
set -e
cat > /etc/apk/repositories <<EOF
$ALPINE_MAIN
$ALPINE_COMMUNITY
EOF
apk update >/dev/null
apk add --no-cache bash build-base cmake ninja pkgconf linux-headers \
    libpcap-dev openssl-dev >/dev/null
mkdir -p /work
cp -a /src /work/xtate
cd /work/xtate
sed -i 's/\r\$//' build.sh
bash build.sh --compiler gcc --config release --generator ninja
./bin/xtate --selftest
bash build.sh --generator ninja --static --minimal
./bin/xtate_static --selftest
file bin/xtate_static
"
}

run_debian10
run_alpine

echo "===== platform matrix passed"
