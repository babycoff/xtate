# Getting started

**English** · [中文](zh-CN/getting-started.md)

Xtate is a modular all-stack network scanner for large-scale active measurement. It sends raw IPv4/IPv6 packets, keeps as little per-target state as it can get away with, and turns replies into structured results — from a single SYN to a completed TLS handshake.

This page takes you from a source checkout to your first scan on Linux or Windows. It assumes you are comfortable with a shell, `sudo`, and basic TCP/IP; it is not a tutorial on scanning itself.

> Documented against Xtate v2.13.2. If your build behaves differently, `--help` and the module help are authoritative.

## Requirements

| Item | Requirement |
|:---|:---|
| OS | Linux (Ubuntu 22.04/24.04 are the reference environments) or Windows |
| CPU | 64-bit **little-endian** only; CMake stops early otherwise |
| Build system | CMake ≥ 3.20 and a C99 compiler (GCC, Clang, MSVC, MinGW-w64) |
| Packet I/O | libpcap (Linux) or Npcap (Windows, runtime) |
| Privileges | root, or `CAP_NET_RAW`+`CAP_NET_ADMIN`; Administrator on Windows |

## Build on Linux

```bash
sudo apt install build-essential cmake libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev

git clone https://github.com/babycoff/xtate.git
cd xtate
./build.sh                 # release build -> ./bin/xtate
./build.sh debug clang     # debug build with Clang -> ./bin/xtate_debug
```

`build.sh` wipes `build/`, configures CMake and copies the resulting binary into `bin/`. On Fedora/Arch install the equivalents (`libpcap`, `openssl`, `pcre2`, `libxml2`, `libbson`, `mongo-c-driver`).

### Optional dependencies

Missing libraries do not break the build: the modules that need them simply disappear at compile time.

| Dependency | Unlocks | Disable with |
|:---|:---|:---|
| OpenSSL ≥ 1.1.1 | `tls-state`, `jarm`, TLS-aware probes | `-DWITH_OPENSSL=OFF` |
| PCRE2 (8-bit) | regex matching in `hello`, `http`, `recog`, `nmap` | `-DWITH_PCRE2=OFF` |
| LibXml2 | Recog XML fingerprint files | `-DWITH_LIBXML2=OFF` |
| libbson / libmongoc | `bson` and `mongodb` output | `-DWITH_BSON=OFF`, `-DWITH_MONGOC=OFF` |

Lua 5.3/5.4 and PF_RING are loaded at runtime, not link time: `lua-tcp`/`lua-udp` need a Lua shared library, and PF_RING is optional Linux acceleration.

## Build on Windows

Install **Npcap** (packet I/O), CMake, and MSVC or MinGW-w64. Optional libraries can come from vcpkg:

```powershell
vcpkg install openssl pcre2 libxml2 mongo-c-driver

cmake -B build -G "Visual Studio 17 2022" `
  -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
```

For MinGW/Clang with Unix Makefiles:

```powershell
cmake -B build -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc
cmake --build build
```

Npcap must be installed for packet I/O; `wpcap.dll` is loaded at runtime. Run `xtate.exe` from an elevated shell.

## Permissions

Raw sockets need root on Linux or Administrator on Windows. Instead of `sudo` for every run you can grant the binary the needed Linux capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate
```

Re-apply this after every rebuild: the capability belongs to the executable file, not to the source tree. On Windows, elevation does the same job.

## Your first scan

A classic stateless SYN scan needs no firewall tricks:

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

What to expect:

- Results go to **stdout** as replies arrive, one line per host/port: `[+] host: 192.168.1.10 port: 80 "open" because "syn-ack"`.
- Only `success`-level results are shown by default. For `tcp-syn`, closed ports are `failed` level (`"closed" because "rst"`); `zbanner` reports open/closed at `info` level unless you promote them. Add `-show failed` and/or `-show info` to see more.
- A live status bar (rate, progress, queue levels) is drawn on **stderr**, so `... > results.txt` keeps the file clean. `--no-status` hides it.
- The interface is auto-detected as the first one with a default gateway; use `--list-if` to list adapters and `-if eth0` to choose one.
- Always give `-p` for TCP/UDP scans. Without any port Xtate warns and substitutes a fake `o:0` endpoint, which is not a TCP/UDP port, so the scan sends nothing at all.
- Stop with a single `Ctrl-C`: transmission stops, late replies are still collected for `--wait` seconds (default 10). Pressing `Ctrl-C` again aborts.

## Banner scans: stop the kernel from answering

`zbanner` and `tcp-state` complete a real TCP handshake. The Linux kernel does not know about those connections and will answer incoming SYN-ACK/data with a RST, killing them before the banner arrives. Suppress that for the duration of the scan:

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http \
  -scan-arg "-banner" -rate 1000 -show info
./firewall/rm_rules.sh
```

- `add_rules.sh` appends `OUTPUT` DROP rules for TCP RST (IPv4 and IPv6) plus ICMP port-unreachable (ICMP 3/3, ICMPv6 1/4). `rm_rules.sh` removes them; `check_rules.sh` prints the current rules.
- These rules are **host-wide**: while they are active, every outgoing RST from this machine is dropped, including those of unrelated SSH/browser sessions. Add them before a scan and remove them immediately afterwards — never leave them installed.
- Module-specific options are passed as a quoted string through `-scan-arg` and `-probe-arg`; for example `-scan-arg "-banner -ttl"` passes `-banner` and `-ttl` to the scan module.
- On Windows there is no bundled equivalent of these scripts. SYN scans work normally, but handshake-based banner scans depend on the Windows stack not resetting the connection.

## Where to go next

| Goal | Read |
|:---|:---|
| Build target lists and port ranges | [Targets and ports](./targets-and-ports.md) |
| Pick a scan/probe pairing | [Scanning modes](./scanning-modes.md) |
| Save or transform results | [Output](./output.md) |
| Fix "no results" problems | [Troubleshooting](./troubleshooting.md) |
| Learn what Xtate does not do | [Known limitations](./known-limitations.md) |
| See the feature list and papers | [README](../README.md) |

The CLI can also explain itself: `--usage`, `--help`, `--intro`, `--list-scan`, `--list-probe`, `--list-out`, `--list-gen`, and `--help-scan <module>` / `--help-probe <module>` for per-module parameters.
