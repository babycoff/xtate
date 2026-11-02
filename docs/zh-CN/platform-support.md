# 平台与构建兼容性

[English](../platform-support.md) · **中文**

Xtate 是 64 位小端 C99 项目，可选依赖可以关闭；基础扫描需要 libpcap 和受支持的编译器。

## 已验证基线

| 环境 | 编译器 | CMake | 生成器 | 结果 |
|:---|:---|:---|:---|:---|
| Ubuntu 24.04 | GCC 13.3 | 3.28 | Make/Ninja | 0 warning |
| Debian 10 | GCC 8.3 | 3.13.4 | Make/Ninja | 基础构建 + selftest |
| Alpine 3.20 (musl) | GCC 13.2 | 3.29 | Ninja | 基础构建 + selftest |

CMake 最低版本为 **3.13**；当 `CMAKE_C_BYTE_ORDER` 不存在时使用
`TestBigEndian` 回退。

## Debian/CentOS 类旧系统的基础构建

只安装构建工具和 libpcap：

```bash
# Debian/Ubuntu
sudo apt install build-essential cmake pkg-config libpcap-dev

# RHEL/CentOS 系
sudo dnf install gcc make cmake pkgconf-pkg-config libpcap-devel
```

不需要任何可选依赖：

```bash
./build.sh --generator make
./build.sh --generator ninja    # 已安装 ninja 时
```

`build.sh` 有 Ninja 时自动选择 Ninja，否则回退 Unix Makefiles。构建目录包含
编译器、配置和生成器，例如 `build-gcc-release-ninja`。

## Alpine/musl

```bash
apk add bash build-base cmake ninja pkgconf linux-headers \
  libpcap-dev openssl-dev
./build.sh --generator ninja
```

`linux-headers` 提供 raw socket 初始化所需的 netlink/接口头文件；
`openssl-dev` 可选，不需要 TLS 探针时可手动传 `-DWITH_OPENSSL=OFF`。

产物是 **musl 动态链接**，不是自动静态链接。

## musl 静态实验

基础配置可以静态链接，但可选库需要静态归档：

```bash
apk add bash build-base cmake ninja pkgconf linux-headers libpcap-dev
./build.sh --generator ninja --static --minimal
file bin/xtate_static
./bin/xtate_static --selftest
```

`--minimal` 关闭 OpenSSL/PCRE2/LibXml2/libbson/libmongoc；Alpine 默认包不提供这些
可选库的静态版本。输出为 `bin/xtate_static` 和
`bin/xtate-<compiler>-<config>-static`。

关闭 OpenSSL 后，需要 libpcap 静态库（Alpine 的 `libpcap-dev` 提供）。静态二进制
仍需要 raw socket 权限和 libpcap 兼容抓包能力；静态链接不授予网络权限。

## 旧 CMake / 编译器说明

- CMake 3.13 只用于 `CONFIGURE_DEPENDS` 和 `target_link_options` 这类特性；
  未使用 `cmake_path`/file-set 等新特性。
- 没有 `CMAKE_C_BYTE_ORDER` 时使用 `TestBigEndian` 回退。
- 可选依赖缺失时以 `NOT_FOUND_*` 宏自动关闭；没有 PCRE2、LibXml2、
  libbson/libmongoc 仍可基础构建。
- 旧发行版仓库可能已 EOL。国外用户应使用上游归档（`archive.debian.org`）；
  国内用户可选择大陆镜像，例如 Debian 10 的
  `mirrors.aliyun.com/debian-archive`。不要把大陆源设为其他用户或 CI 的默认。

## 当前限制

- 不承诺很旧的发行版上完整可选依赖构建。
- 尚未把 glibc 到 musl 的交叉编译接入构建脚本；目前支持的 musl 路径是原生
  Alpine。
- 尚未支持包含全部可选库的静态构建。
