# Platform and build compatibility

**English** · [中文](zh-CN/platform-support.md)

Xtate is a 64-bit little-endian C99 project. Optional libraries can be disabled;
the basic scanner needs libpcap and a supported compiler.

## Repeatable matrix

`tests/platform/matrix.sh` runs the Debian 10 and Alpine/musl builds in Docker.
By default it uses upstream images/archives. For a mainland network, opt in
explicitly (never the default):

```bash
XTATE_CN_MIRROR=1 bash tests/platform/matrix.sh
```

## Verified baseline

| Environment | Compiler | CMake | Generator | Result |
|:---|:---|:---|:---|:---|
| Ubuntu 24.04 | GCC 13.3 | 3.28 | Make/Ninja | 0 warnings |
| Debian 10 | GCC 8.3 | 3.13.4 | Make/Ninja | basic build + selftest |
| Alpine 3.20 (musl) | GCC 13.2 | 3.29 | Ninja | basic build + selftest |

The CMake minimum is **3.13**; `TestBigEndian` is used when
`CMAKE_C_BYTE_ORDER` is unavailable.

## Basic build on an older Debian/CentOS-like host

Install only the builder essentials and libpcap:

```bash
# Debian/Ubuntu
sudo apt install build-essential cmake pkg-config libpcap-dev

# RHEL/CentOS-family
sudo dnf install gcc make cmake pkgconf-pkg-config libpcap-devel
```

No optional dependency is required:

```bash
./build.sh --generator make
./build.sh --generator ninja    # if ninja is installed
```

`build.sh` auto-selects Ninja when available, otherwise Unix Makefiles. The
build directory includes compiler, configuration and generator, for example
`build-gcc-release-ninja`.

## Alpine/musl

You do **not** need to replace your whole machine with Alpine. The supported
native path is an Alpine rootfs (container or real host).

### Native Alpine

```bash
apk add bash build-base cmake ninja pkgconf linux-headers \
  libpcap-dev openssl-dev
git clone https://github.com/babycoff/xtate.git
cd xtate
./build.sh --generator ninja
./bin/xtate --selftest
```

`linux-headers` is required for the netlink/interface headers used by the raw
socket setup. `openssl-dev` is optional; omit it and pass
`-DWITH_OPENSSL=OFF` if you do not need TLS probes.

The result is **musl dynamic**:

```text
bin/xtate
bin/xtate-gcc-release
```

### Build musl from Linux, Windows or macOS with Docker

From the repository root (Docker Desktop/Linux containers):

```bash
docker run --rm -v "$PWD:/src" -w /src alpine:3.20 sh -c '
  apk add --no-cache bash build-base cmake ninja pkgconf \
    linux-headers libpcap-dev openssl-dev &&
  ./build.sh --generator ninja &&
  ./bin/xtate --selftest
'
```

This creates `bin/xtate` as a musl binary on the host checkout. Build trees are
`build-gcc-release-ninja/`; remove them with `./clean.sh` if you do not need
them.

For a static basic build:

```bash
docker run --rm -v "$PWD:/src" -w /src alpine:3.20 sh -c '
  apk add --no-cache bash build-base cmake ninja pkgconf \
    linux-headers libpcap-dev &&
  ./build.sh --generator ninja --static --minimal &&
  ./bin/xtate_static --selftest &&
  file ./bin/xtate_static
'
```

Output:

```text
bin/xtate_static
bin/xtate-gcc-release-static
```

`--minimal` disables OpenSSL/PCRE2/LibXml2/libbson/libmongoc. Alpine's default
packages do not provide static archives for those optional libraries.

A static binary still needs raw-socket privileges and libpcap-compatible
capture capability at runtime; static linking does not grant network privileges.

### Mainland China Docker/image mirrors (opt-in only)

The default image is the upstream `alpine:3.20`. Only when upstream access is
unavailable, mainland users may replace it explicitly:

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

Do not make DaoCloud/Aliyun the default for other users or CI.

## Old CMake / compiler notes

- CMake 3.13 required only for `CONFIGURE_DEPENDS` and `target_link_options`
  style features; no `cmake_path`/file-set features are used.
- The endian check falls back to `TestBigEndian` when `CMAKE_C_BYTE_ORDER` is
  absent.
- Optional dependencies are auto-disabled with `NOT_FOUND_*` defines; the
  basic build succeeds without PCRE2, LibXml2, libbson or libmongoc.
- CMake checks `sendmmsg` and `pthread_setname_np`; missing interfaces fall back
  to single-packet `sendmsg` and a no-op thread name. The test matrix forces
  both fallbacks with `-DXTATE_NO_SENDMMSG -DXTATE_NO_PTHREAD_SETNAME` to keep
  the paths compiling.
- Old distro packages may be EOL. Users outside mainland China should use the
  upstream archive (`archive.debian.org`); mainland users can opt into a mirror
  such as `mirrors.aliyun.com/debian-archive` for Debian 10. Do not make a
  mainland mirror the default for other users or CI.

## Current limits

- Full optional-dependency builds on very old distros are not promised.
- musl cross-compilation from glibc is not yet wired into the build script;
  native Alpine is the supported musl path for now.
- Static builds with all optional libraries are not yet supported.
