FROM docker.m.daocloud.io/library/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's|http://archive.ubuntu.com/ubuntu|https://mirrors.aliyun.com/ubuntu|g; s|http://security.ubuntu.com/ubuntu|https://mirrors.aliyun.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 openssl iptables ca-certificates \
 && rm -rf /var/lib/apt/lists/*
