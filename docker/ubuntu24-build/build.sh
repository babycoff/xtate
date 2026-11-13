#!/usr/bin/env bash
# Build the full-feature Ubuntu 24.04 image.
#
# Usage:
#   docker/ubuntu24-build/build.sh [--mirror official|tuna|ustc|aliyun|huawei]
#                                  [--base-image IMAGE] [--tag TAG] [--no-cache]
#
# Mainland China users normally want:
#   docker/ubuntu24-build/build.sh \
#     --base-image docker.m.daocloud.io/library/ubuntu:24.04 --mirror tuna
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIRROR=official
BASE_IMAGE=ubuntu:24.04
TAG=xtate:ubuntu24-full
NO_CACHE=()

while [ $# -gt 0 ]; do
    case "$1" in
        --mirror) MIRROR="${2:?}"; shift 2 ;;
        --base-image) BASE_IMAGE="${2:?}"; shift 2 ;;
        --tag) TAG="${2:?}"; shift 2 ;;
        --no-cache) NO_CACHE=(--no-cache); shift ;;
        -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

exec docker build "${NO_CACHE[@]}" \
    -f "$ROOT/docker/ubuntu24-build/Dockerfile" \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    --build-arg "APT_MIRROR=$MIRROR" \
    -t "$TAG" \
    "$ROOT"
