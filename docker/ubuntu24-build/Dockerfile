# Full-feature Xtate build environment on Ubuntu 24.04.
#
# The image installs every optional build dependency available from Ubuntu:
# OpenSSL, PCRE2, libxml2, libbson/libmongoc, ngtcp2+GnuTLS (HTTP/3 and QUIC),
# zstd and libpcap (runtime). The result is a self-contained xtate binary with
# HTTP/3, QUIC transport, zstd chunk compression and the GUI enabled.
#
# Build from the repository root:
#   docker build -f docker/ubuntu24-build/Dockerfile \
#     --build-arg APT_MIRROR=official -t xtate:ubuntu24-full .
#
# Mainland mirrors:
#   --build-arg BASE_IMAGE=docker.m.daocloud.io/library/ubuntu:24.04
#   --build-arg APT_MIRROR=tuna|ustc|aliyun|huawei
#
# The image has no network privileges by default. Raw scans need
# --cap-add=NET_RAW --cap-add=NET_ADMIN (and the Linux firewall rules for
# stateful scans). The GUI is loopback-only by default; see docs/docker-build.md
# for the explicit host-published mode.

ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ARG APT_MIRROR=official
ARG DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    if [ "$APT_MIRROR" != "official" ]; then \
        case "$APT_MIRROR" in \
            tuna)  MIRROR=mirrors.tuna.tsinghua.edu.cn ;; \
            ustc)  MIRROR=mirrors.ustc.edu.cn ;; \
            aliyun) MIRROR=mirrors.aliyun.com ;; \
            huawei) MIRROR=repo.huaweicloud.com ;; \
            *) echo "unsupported APT_MIRROR=$APT_MIRROR" >&2; exit 1 ;; \
        esac; \
        sed -i "s|http://archive.ubuntu.com/ubuntu|http://$MIRROR/ubuntu|g; \
                s|http://security.ubuntu.com/ubuntu|http://$MIRROR/ubuntu|g; \
                s|http://ports.ubuntu.com/ubuntu-ports|http://$MIRROR/ubuntu-ports|g" \
            /etc/apt/sources.list.d/ubuntu.sources; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config git ca-certificates \
        libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev \
        libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev \
        libzstd-dev libpcap0.8 liblua5.3-dev liblua5.3-0 \
        iptables python3; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN set -eux; \
    cmake -S /src -B /src/build -G Ninja -DCMAKE_BUILD_TYPE=Release; \
    cmake --build /src/build -j"$(nproc)"; \
    /src/build/xtate --selftest; \
    /src/build/xtate --list-capabilities > /tmp/capabilities.json; \
    python3 - <<'PY'
import json
c = json.load(open('/tmp/capabilities.json'))
for key in ('raw_sockets', 'http3', 'quic_transport', 'zstd'):
    assert c.get(key) is True, (key, c)
assert c.get('modules', {}).get('scan') == 12, c
print('full-feature capabilities:', {k: c.get(k) for k in ('http3','quic_transport','zstd')})
PY

RUN set -eux; \
    install -Dm755 /src/build/xtate /usr/local/bin/xtate; \
    mkdir -p /usr/local/share/xtate; \
    cp -a /src/docs /src/schemas /src/firewall /src/lua-probes /usr/local/share/xtate/; \
    mkdir -p /data

ENV XTATE_MCP_DOCS_DIR=/usr/local/share/xtate
ENV XTATE_STATE_DIR=/data

WORKDIR /data
ENTRYPOINT ["xtate"]
CMD ["--version"]
