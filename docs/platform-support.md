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

```bash
apk add bash build-base cmake ninja pkgconf linux-headers \
  libpcap-dev openssl-dev
./build.sh --generator ninja
```

`linux-headers` is required for the netlink/interface headers used by the raw
socket setup. `openssl-dev` is optional; omit it (and pass
`-DWITH_OPENSSL=OFF` manually) if you do not need TLS probes.

The resulting binary is **musl dynamic**, not automatically static.

## Static musl experiment

A fully static binary is possible for the basic configuration, but optional
libraries need static archives:

```bash
apk add bash build-base cmake ninja pkgconf linux-headers libpcap-dev
./build.sh --generator ninja --static --minimal
file bin/xtate_static
./bin/xtate_static --selftest
```

`--minimal` disables OpenSSL/PCRE2/LibXml2/libbson/libmongoc; static optional
libraries are not provided by the default Alpine packages. The output is
`bin/xtate_static` and `bin/xtate-<compiler>-<config>-static`.

Without OpenSSL, libpcap's static archive must be present (`libpcap-dev` on
Alpine provides it). A static binary still needs raw-socket privileges and
libpcap-compatible capture capability at runtime; static linking does not grant
network privileges.

## Old CMake / compiler notes

- CMake 3.13 required only for `CONFIGURE_DEPENDS` and `target_link_options`
  style features; no `cmake_path`/file-set features are used.
- The endian check falls back to `TestBigEndian` when `CMAKE_C_BYTE_ORDER` is
  absent.
- Optional dependencies are auto-disabled with `NOT_FOUND_*` defines; the
  basic build succeeds without PCRE2, LibXml2, libbson or libmongoc.
- Old distro packages may be EOL. Users outside mainland China should use the
  upstream archive (`archive.debian.org`); mainland users can opt into a mirror
  such as `mirrors.aliyun.com/debian-archive` for Debian 10. Do not make a
  mainland mirror the default for other users or CI.

## Current limits

- Full optional-dependency builds on very old distros are not promised.
- musl cross-compilation from glibc is not yet wired into the build script;
  native Alpine is the supported musl path for now.
- Static builds with all optional libraries are not yet supported.
