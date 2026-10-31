# Getting started

**English** · [中文](zh-CN/getting-started.md)

Xtate is a modular all-stack network scanner for large-scale active measurement. It sends raw IPv4/IPv6 packets, keeps as little per-target state as it can get away with, and turns replies into structured results — from a single SYN to a completed TLS handshake.

This page takes you from a source checkout to your first scan on Linux or Windows. It assumes you are comfortable with a shell, `sudo`, and basic TCP/IP; it is not a tutorial on scanning itself.

> Documented against Xtate v2.20.0. If your build behaves differently, `--help` and the module help are authoritative.

## Requirements

| Item | Requirement |
|:---|:---|
| OS | Linux (Ubuntu 22.04/24.04 are the reference environments) or Windows 10/11 |
| CPU | 64-bit **little-endian** only; CMake stops early otherwise |
| Build system | CMake ≥ 3.20 and a C99 compiler (GCC, Clang, MSVC, MinGW-w64) |
| Packet I/O | libpcap (Linux) or Npcap (Windows, runtime) |
| Privileges | root, or `CAP_NET_RAW`+`CAP_NET_ADMIN`; Administrator on Windows |

## Build matrix

These combinations are exercised before releases. "Full" means all optional
dependencies are present, so the complete module set is compiled in.

| Platform | Compiler | Status | Optional dependencies |
|:---|:---|:---|:---|
| Ubuntu 24.04 | GCC 13.3 | build + `--selftest` pass, 11/60/7/5 modules | OpenSSL, PCRE2, LibXml2, BSON, mongoc |
| Ubuntu 24.04 | Clang 18.1 | build + `--selftest` pass, 11/60/7/5 modules | OpenSSL, PCRE2, LibXml2, BSON, mongoc |
| Windows 10/11 | MSVC 19.5x (Visual Studio 2022/2026) | build + `--selftest` pass, 11/54/5/5 modules | OpenSSL via Scoop; PCRE2/BSON/mongoc not installed |
| Windows 10/11 | Clang 23 (clang-cl) | build + `--selftest` pass, 11/54/5/5 modules | OpenSSL via Scoop; PCRE2/BSON/mongoc not installed |
| Windows 10/11 | MinGW-w64 GCC 16 | build + `--selftest` pass, 11/52/5/5 modules | no OpenSSL (Scoop build is MSVC-only) |

The module counts are a quick way to verify your dependencies: 60 probes and 7
output modules means everything was found; fewer means at least one optional
library was not discovered.

## Build on Linux

Install the full dependency set on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev

git clone https://github.com/babycoff/xtate.git
cd xtate
```

### Quick build with build.sh

```bash
./build.sh                 # Release, GCC   -> ./bin/xtate
./build.sh clang           # Release, Clang -> ./bin/xtate
./build.sh debug           # Debug, GCC     -> ./bin/xtate_debug
./build.sh debug clang     # Debug, Clang   -> ./bin/xtate_debug
```

`build.sh` wipes `build/`, configures CMake and copies the resulting binary into
`bin/`. The two-argument form takes `debug` and/or a compiler name.

### Manual CMake build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 8
./build/xtate --version
./build/xtate --selftest
```

For Clang:

```bash
cmake -S . -B build-clang -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang
cmake --build build-clang -j 8
```

On Fedora/Arch install the equivalents (`libpcap`, `openssl`, `pcre2`,
`libxml2`, `libbson`, `mongo-c-driver`).

### Optional dependencies on Linux

Missing libraries do not break the build: the modules that need them simply
disappear at compile time.

| Dependency | Unlocks | Disable with |
|:---|:---|:---|
| OpenSSL ≥ 1.1.1 | `tls-state`, `jarm`, TLS-aware probes | `-DWITH_OPENSSL=OFF` |
| PCRE2 (8-bit) | regex matching in `hello`, `http`, `recog`, `nmap` | `-DWITH_PCRE2=OFF` |
| LibXml2 | Recog XML fingerprint files | `-DWITH_LIBXML2=OFF` |
| libbson / libmongoc | `bson` and `mongodb` output | `-DWITH_BSON=OFF`, `-DWITH_MONGOC=OFF` |

On Debian/Ubuntu, `libpcre2-dev` ships pkg-config metadata but no CMake package
config. The build automatically falls back to `pkg-config` for PCRE2, so install
the `pkg-config` package together with `libpcre2-dev` to keep the PCRE2-backed
probes. Without it, `--version` prints `PCRE2 (null)` and six probes disappear.

Lua 5.3/5.4 and PF_RING are loaded at runtime, not link time: `lua-tcp`/`lua-udp`
need a Lua shared library, and PF_RING is optional Linux acceleration.

## Build on Windows

### Prerequisites

1. **Visual Studio 2022 or 2026** with the *Desktop development with C++*
   workload, or **MinGW-w64** (`scoop install mingw`).
2. **CMake ≥ 3.20** (`scoop install cmake`).
3. **Npcap** in WinPcap-compatible mode for packet I/O. `wpcap.dll` is loaded at
   runtime; it is not needed to compile, but no scan will run without it.
4. A 64-bit little-endian host. Run the commands below from a normal PowerShell
   or `cmd.exe`; use an elevated shell for actual scans.

Visual Studio is the most complete option. `clang-cl` shares the MSVC ABI and
works well too. MinGW is supported but has two important constraints:

- Scoop's OpenSSL package is built for MSVC, so it cannot be linked by MinGW.
- The `MinGW Makefiles` generator can fail when the source path contains
  non-ASCII characters (for example a Chinese directory). Use an ASCII staging
  path or the build script described below.

### Optional dependencies on Windows

The quickest route for OpenSSL and Lua is Scoop:

```powershell
scoop install openssl-lts
scoop install lua54
```

- `openssl-lts` installs OpenSSL 3.x with MSVC import libraries. It works with
  MSVC and `clang-cl`; it does **not** work with MinGW.
- `lua54` is chosen because the runtime loader looks for `lua53.dll`,
  `lua54.dll` or `lua.dll`. Scoop's default `lua` package is Lua 5.5, which
  provides `lua55.dll` and is not loaded by this tree.
- If CMake does not pick up Scoop's OpenSSL automatically, pass the root
  explicitly:
  `-DOPENSSL_ROOT_DIR="$env:USERPROFILE\scoop\apps\openssl-lts\current"`.

Scoop does not currently package the PCRE2 development files, libbson or
libmongoc. For the complete probe/output set, use vcpkg (installed via Scoop or
standalone):

```powershell
scoop install vcpkg
vcpkg install pcre2 libxml2 mongo-c-driver --triplet x64-windows

cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$env:USERPROFILE\scoop\apps\vcpkg\current\scripts\buildsystems\vcpkg.cmake"
```

Without PCRE2, Windows builds have 54 probes instead of 60. Without
libbson/mongoc, they have 5 output modules instead of 7. Those are expected
results, not build failures.

### MSVC

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
  -DOPENSSL_ROOT_DIR="$env:USERPROFILE\scoop\apps\openssl-lts\current"
cmake --build build-msvc --config Release -j 8

.\build-msvc\Release\xtate.exe --version
.\build-msvc\Release\xtate.exe --selftest
```

Use `-G "Visual Studio 18 2026"` with Visual Studio 2026. `--selftest` is now
part of the release gate: it exits non-zero if any regression test fails.

### ClangCL

`clang-cl` needs the MSVC linker and Windows SDK. Start a Visual Studio
developer shell first:

```powershell
cmd /c "call ""C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat"" && cmake -S . -B build-clang -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=""%USERPROFILE%\scoop\apps\openssl-lts\current"" && cmake --build build-clang -j 8"
```

Adjust the Visual Studio path and generator to your installation. The
repository's build script below does this automatically if you prefer not to
manage `vcvars64.bat` and Ninja by hand.

### MinGW

```powershell
cmake -S . -B build-mingw -G "MinGW Makefiles" `
  -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Release
cmake --build build-mingw -j 8

.\build-mingw\xtate.exe --version
.\build-mingw\xtate.exe --selftest
```

If the source path contains non-ASCII characters, use the build script's ASCII
staging mode instead of building in place:

```powershell
pwsh -File .\scripts\build-windows.ps1 -Toolchain mingw
```

The script explains the copy, asks for confirmation, and removes the staged
source/build tree afterwards.

### Automated Windows build script

`scripts/build-windows.ps1` builds MSVC, MinGW and ClangCL, runs `--version` and
`--selftest` for each, and keeps the executables in a known directory.

```powershell
# Ask before copying the source to the staging directory
pwsh -File .\scripts\build-windows.ps1

# Non-interactive: pre-approve staging, build all three toolchains
pwsh -File .\scripts\build-windows.ps1 -Toolchain all -Yes

# Just one toolchain, debug configuration
pwsh -File .\scripts\build-windows.ps1 -Toolchain msvc -Config Debug -Yes
```

What it does:

1. Shows the source path, staging path and artifact path.
2. Asks for your approval before copying the source. The default staging root is
   `%LOCALAPPDATA%\xtate-build`, with the source at
   `%LOCALAPPDATA%\xtate-build\src`.
3. Copies the tree there, excluding `.git`, `build`, `bin` and `results`.
4. Builds each requested toolchain under `%LOCALAPPDATA%\xtate-build\build-*`.
5. Runs `--version` and `--selftest` and fails the script if either fails.
6. Copies the binaries to `%LOCALAPPDATA%\xtate-build\artifacts`.
7. Removes the staged source and build directories. Artifacts are kept.

Useful switches:

| Switch | Effect |
|:---|:---|
| `-Toolchain msvc|mingw|clangcl|all` | Which compiler(s) to build |
| `-Config Release|Debug` | Build configuration |
| `-Yes` | Pre-approve staging (no prompt) |
| `-KeepStage` | Keep the staged source/build tree for debugging |
| `-StageRoot <path>` | Use a different staging root |

The script does not silently copy anything: without `-Yes` it waits for your
confirmation, and it never deletes the artifacts directory.

### Run and verify

```powershell
.\build-msvc\Release\xtate.exe --version
.\build-msvc\Release\xtate.exe --selftest
```

`--version` shows the compiler, OpenSSL/PCRE2/BSON versions and whether each
optional library was found. `--selftest` runs the built-in regression suite and
returns non-zero on failure. For real scans, run `xtate.exe` from an elevated
shell with Npcap installed.

## Build troubleshooting

| Symptom | Cause and fix |
|:---|:---|
| `CMake Error: Not a file: .../CMakeFiles/VerifyGlobs.cmake` | The source path contains non-ASCII characters and MinGW Makefiles mis-encodes it. Use an ASCII staging path or `scripts/build-windows.ps1`. |
| `Could NOT find OpenSSL ... missing OPENSSL_CRYPTO_LIBRARY` with MinGW | The Scoop OpenSSL package is MSVC-only. Build with MSVC/clang-cl, or provide a MinGW-built OpenSSL. |
| `PCRE2 (null)` in `--version` | PCRE2 headers/library were not found. On Debian/Ubuntu install `libpcre2-dev` and `pkg-config`; on Windows use vcpkg (Scoop has no PCRE2 dev package). |
| `OpenSSL (null)`, 52 probes | OpenSSL was skipped. On Windows use MSVC/clang-cl with Scoop OpenSSL; on Linux install `libssl-dev`. |
| `bson`/`mongodb` output modules missing | libbson/libmongoc were not found; install them or accept the reduced output set. |
| `--selftest` fails with `timing error` | Fixed in 2.20.0 on Windows; with older builds the 1% timing bound is too strict for the Windows scheduler. Update to the current tree. |
| `--selftest` exits non-zero | Treat it as a real failure now; the summary prints `Regression test: failed` and the process exit code is non-zero. |
| `wpcap.dll` / `Npcap` error at run time | Install Npcap in WinPcap-compatible mode; it is a runtime dependency, not a build dependency. |
| `lua53.dll` / `lua54.dll` not found | Install `lua54` via Scoop and add `%USERPROFILE%\scoop\apps\lua54\current` to `PATH`, or copy `lua54.dll` next to `xtate.exe`. |

For runtime problems after a successful build, see
[Troubleshooting](./troubleshooting.md).

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
