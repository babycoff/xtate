FROM docker.m.daocloud.io/library/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://mirrors.aliyun.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pip openssl iptables ca-certificates \
      libxml2 libbson-1.0-0 libmongoc-1.0-0 libpcap0.8 \
      libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev \
 && pip3 install --break-system-packages --no-cache-dir \
      -i https://pypi.tuna.tsinghua.edu.cn/simple aioquic \
 && rm -rf /var/lib/apt/lists/*
