# 平台与构建兼容性

[English](../platform-support.md) · **中文**

Xtate 是 64 位小端 C99 项目，可选依赖可以关闭；基础扫描需要 libpcap 和受支持的编译器。

## 可重复矩阵

`tests/platform/matrix.sh` 用 Docker 跑 Debian 10 和 Alpine/musl 构建。
默认使用上游镜像/归档；大陆网络需显式 opt-in，不能作为默认：

```bash
XTATE_CN_MIRROR=1 bash tests/platform/matrix.sh
```

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

不需要把整台机器换成 Alpine。支持的 musl 路径是 Alpine 根文件系统（容器或真实主机）。

### 原生 Alpine

```bash
apk add bash build-base cmake ninja pkgconf linux-headers \
  libpcap-dev openssl-dev
git clone https://github.com/babycoff/xtate.git
cd xtate
./build.sh --generator ninja
./bin/xtate --selftest
```

`linux-headers` 提供 raw socket 初始化所需的 netlink/接口头文件；
`openssl-dev` 可选，不需要 TLS 探针时可省略并传 `-DWITH_OPENSSL=OFF`。

产物是 **musl 动态链接**：

```text
bin/xtate
bin/xtate-gcc-release
```

### 在 Linux/Windows/macOS 上用 Docker 构建 musl

在仓库根目录执行（Docker Desktop 或 Linux 容器）：

```bash
docker run --rm -v "$PWD:/src" -w /src alpine:3.20 sh -c '
  apk add --no-cache bash build-base cmake ninja pkgconf \
    linux-headers libpcap-dev openssl-dev &&
  ./build.sh --generator ninja &&
  ./bin/xtate --selftest
'
```

这会在宿主仓库的 `bin/xtate` 生成 musl 二进制，构建目录为
`build-gcc-release-ninja/`，可用 `./clean.sh` 清理。

基础静态构建：

```bash
docker run --rm -v "$PWD:/src" -w /src alpine:3.20 sh -c '
  apk add --no-cache bash build-base cmake ninja pkgconf \
    linux-headers libpcap-dev &&
  ./build.sh --generator ninja --static --minimal &&
  ./bin/xtate_static --selftest &&
  file ./bin/xtate_static
'
```

输出：

```text
bin/xtate_static
bin/xtate-gcc-release-static
```

`--minimal` 关闭 OpenSSL/PCRE2/LibXml2/libbson/libmongoc；Alpine 默认包不提供这些
可选库的静态版本。

静态二进制仍需要 raw socket 权限和 libpcap 兼容抓包能力；静态链接不授予网络权限。

### 大陆 Docker/镜像源（仅显式 opt-in）

默认镜像是上游 `alpine:3.20`。只有上游不可访问时，大陆用户才显式替换：

```bash
docker run --rm -v "$PWD:/src" -w /src \
  docker.m.daocloud.io/library/alpine:3.20 sh -c '
  echo "https://mirrors.aliyun.com/alpine/v3.20/main" > /etc/apk/repositories
  echo "https://mirrors.aliyun.com/alpine/v3.20/community" >> /etc/apk/repositories
  apk add --no-cache bash build-base cmake ninja pkgconf \
    linux-headers libpcap-dev openssl-dev &&
  ./build.sh --generator ninja
'
```

不要把 DaoCloud/阿里云设为其他用户或 CI 的默认。

## 旧 CMake / 编译器说明

- CMake 3.13 只用于 `CONFIGURE_DEPENDS` 和 `target_link_options` 这类特性；
  未使用 `cmake_path`/file-set 等新特性。
- 没有 `CMAKE_C_BYTE_ORDER` 时使用 `TestBigEndian` 回退。
- 可选依赖缺失时以 `NOT_FOUND_*` 宏自动关闭；没有 PCRE2、LibXml2、
  libbson/libmongoc 仍可基础构建。
- CMake 会检测 `sendmmsg` 和 `pthread_setname_np`；缺失时回退为逐包 `sendmsg`
  和空线程名。测试矩阵会用 `-DXTATE_NO_SENDMMSG -DXTATE_NO_PTHREAD_SETNAME`
  强制两条回退路径参与编译。
- 旧发行版仓库可能已 EOL。国外用户应使用上游归档（`archive.debian.org`）；
  国内用户可选择大陆镜像，例如 Debian 10 的
  `mirrors.aliyun.com/debian-archive`。不要把大陆源设为其他用户或 CI 的默认。

## 当前限制

- 不承诺很旧的发行版上完整可选依赖构建。
- 尚未把 glibc 到 musl 的交叉编译接入构建脚本；目前支持的 musl 路径是原生
  Alpine。
- 尚未支持包含全部可选库的静态构建。
