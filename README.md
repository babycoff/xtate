<div align="center">
  <img src="screenshots/poster.jpg" alt="Xtate — a modular all-stack network scanner" width="820">
  <br>

  <h3>Xtate — a modular all-stack network scanner for Internet-scale surveys</h3>

  <p>
    <b>Stateless TCP banners.</b> <b>Hybrid-state TCP/TLS.</b> <b>49 registered modules.</b><br>
    <sub>C99 · Linux glibc/musl &amp; Windows · GCC/Clang/MSVC/MinGW · Make/Ninja · IPv4 &amp; IPv6</sub>
  </p>

  <p>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/version-2.29.0-blueviolet?style=flat-square" alt="version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="license"></a>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/C-99-00599C?style=flat-square&amp;logo=c" alt="C99"></a>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-informational?style=flat-square" alt="platform"></a>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/CMake-3.13%2B-064F8C?style=flat-square&amp;logo=cmake" alt="CMake"></a>
    <a href="https://github.com/knownsec/404StarLink"><img src="https://img.shields.io/badge/404Starlink-member-orange?style=flat-square" alt="404Starlink"></a>
    <a href="https://arxiv.org/abs/2405.07409"><img src="https://img.shields.io/badge/arXiv-2405.07409-B31B1B?style=flat-square&amp;logo=arxiv" alt="arXiv"></a>
  </p>
</div>

> **God is Stateless.** — the Xtate proverb

Xtate is a network scanner for large-scale active measurement. It splits the scanning stack into four pluggable module types — **Scan** (L3/L4 packets), **Probe** (L5+ payloads and parsers), **Generate** (targets) and **Output** (results) — and ships two original engines:

- **ZBanner** obtains real TCP responses without keeping per-target connection state.
- **HLTCP** is a hybrid-state user-space TCP stack that completes TLS handshakes and fetches HTTPS responses when statelessness is not enough.

It is not a crawler, and it does not pretend to be one. It is a packet engine with just enough protocol state to get answers that most fast scanners cannot.

<p align="center">
  <a href="#why-xtate">Why</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#modules">Modules</a> ·
  <a href="#build">Build</a> ·
  <a href="#explore-the-cli">CLI</a> ·
  <a href="docs/README.md">Docs</a> ·
  <a href="#papers-and-citation">Papers</a> ·
  <a href="#license-and-responsible-use">License</a>
</p>

<p align="center">
  <b>English</b> · <a href="README.zh-CN.md">中文</a>
</p>

## Why Xtate

Most fast scanners stop at "port open"; most service scanners give up at Internet scale. Xtate lives in the overlap.

- ⚡ **ZBanner** — real TCP responses without a per-target connection table. The peer's TCP stack holds the state; a SipHash cookie proves the reply is yours.
- 🧬 **HLTCP** — a hybrid-state user-space TCP stack, created only where needed. It completes TLS handshakes and speaks HTTP inside them.
- 🧩 **Modules** — 11 scan / 26 probe / 7 output / 5 generate modules. Four interfaces, one pipeline, no runtime plugin magic.
- 🌐 **Chinese help** — `--lang zh` or `XTATE_LANG=zh` localizes human-facing help, with UTF-8-aware wrapping and safe English fallback for untranslated strings.
- 🎯 **Sparse target patterns** — component ranges such as `132.80-88.90.15` or `2001:db8:1-5::1`; up to four ranges form a Cartesian product (1,048,576-address cap per token) while large continuous spaces still use CIDR/ranges.

## Toolchains, platforms and interactive mode

The scanner is C99 and has no hard dependency beyond libpcap/Npcap. Both build
families and the interactive shell are first-class, not afterthoughts.

### Toolchains and environments

| Area | Supported |
|:---|:---|
| Build system | **CMake 3.13+**, Unix Makefiles or **Ninja** |
| Linux glibc | **GCC / Clang**, Release/Debug; Debian 10-class CMake 3.13 baseline |
| Linux musl | **Alpine/musl**, dynamic build and basic `--static --minimal` build |
| Windows | **MSVC / ClangCL / MinGW UCRT64 / MinGW MINGW64**, Release/Debug, Npcap + optional vcpkg DLLs |
| Binary layout | project-local `bin/`, aliases plus exact per-toolchain names |

Windows CI exercises all four toolchain variants. See [Platform support](docs/platform-support.md),
[Windows quick start](docs/windows-quickstart.md) and [Build artifacts](docs/build-artifacts.md).

### Interactive mode

`xtate -interactive` is a self-contained shell: no ncurses, no readline package,
no extra runtime dependency.

- Grouped `help` / `help <command>` and Chinese help (`--lang zh`);
- `<TAB>` completion for commands, parameter names, module names, common values
  and file paths;
- module-argument completion after selecting a scan/probe/output/generate module;
- command history, `set`, `show diff`, `show all`, `list-param <filter>`;
- real TTY mode and deterministic non-TTY script mode, including clean terminal
  restoration;
- one binary on Linux and Windows; no Python/Go launcher required.

See [Interactive mode](docs/interactive-mode.md).

## Quick start

```bash
# Linux: build from source (dependencies are covered under Build)
git clone https://github.com/babycoff/xtate.git
cd xtate
./build.sh                 # interactive: compiler + Release/Debug
./bin/xtate -interactive   # optional: tab-completion shell

# A classic SYN scan — no firewall tricks needed
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

For a real banner-grabbing handshake, stop the Linux kernel from resetting connections it does not know about:

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http -show info
./firewall/rm_rules.sh
```

> [!TIP]
> Start at `-rate 1000`, not `-rate 1000000`. A lab subnet is not the Internet, and your switch will thank you.

> [!WARNING]
> Xtate sends raw packets. Scan only networks you own or have explicit permission to test. Unauthorized scanning may be illegal where you live.

On Windows, install [Npcap](https://npcap.com/), build with CMake, and run `xtate.exe` from an elevated shell. New to Windows? Start with the [Windows quick start](docs/windows-quickstart.md).

<details>
<summary><b>More commands to try</b></summary>

```bash
# Stateless TLS hello: grab ServerHello hints without a full handshake
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan zbanner -probe tls-hello -show info

# UDP with a generic echo probe
sudo ./bin/xtate -ip 10.0.0.0/24 -p u:80 -scan udp -probe echo -show info

# LAN ARP sweep
sudo ./bin/xtate -ip 192.168.1.0/24 -scan arp-req -lan

# IPv6 neighbor discovery on a local link
sudo ./bin/xtate -ip fe80::1/120 -scan ndp-ns -src-ip fe80::2 -fake-router-mac

# SCTP INIT scan
sudo ./bin/xtate -ip 10.0.0.0/24 -p s:38412 -scan sctp-init -show info
```

</details>

## Architecture

<p align="center">
  <img src="screenshots/architecture.png" alt="Xtate runtime overview: a U-shaped packet path from targets and TX through Internet, RX plus dispatch, handlers and output; ZBanner and HLTCP hang off the handler; the host TCP stack is bypassed" width="100%">
</p>

The overview folds the packet path into a U: targets and TX on the ingress side, a merged `RX + Dispatch` stage, then handlers and output. Under it, ZBanner stays stateless while HLTCP keeps state only for a user-space TCP/TLS conversation. The host kernel TCP stack is deliberately not on this path.

- **Tx:** N threads; target generation, rate control, packet construction, raw send.
- **Rx:** one thread; preprocess, validate, dedup, optional pcap capture, then dispatch.
- **Handle:** M threads; scan/probe state machines, result formatting, follow-up packets.
- **Stateful scans:** one TCP connection table per handle thread, so the hot path needs no locks.

Handle threads inject follow-up packets (ACK, RST, next probe) through a lock-free ring back to Tx, which is how a "stateless" Rx path still drives a real TCP conversation.

**Under the hood, briefly:**

- Packet templates are pre-baked at startup and patched per target; checksums are recomputed.
- The target space is flattened to `ip × port` and permuted with BlackRock; source IP and port can be randomized too (63-bit scan space).
- Results are an `OutItem` with three typed key-value chains (scan, probe, output), streamed to whichever OutputModule you chose.
- `--pcap`, `--resume`, `--shard` and a live status bar are built in.

## Two ways to scan

| | **ZBanner** (stateless) | **HLTCP** (hybrid-state) |
|:---|:---|:---|
| Per-target state | none | TCB after SYN-ACK |
| From our side | SYN + ACK with probe payload | full TCP state machine |
| You get | open/closed + first banner(s) | TLS handshake, certificates, ciphers, HTTP over TLS |
| Memory | dedup table only | small TCB; TLS sessions are OpenSSL-sized |
| Sweet spot | Internet-wide banner census | targeted evidence on interesting hosts |
| Entry point | `-scan zbanner -probe <tcp>` | `-scan tcp-state -probe <state>` |

The flagship trick, in one sequence:

<p align="center">
  <img src="screenshots/zbanner-sequence.png" alt="ZBanner sequence: stateless SYN with a SipHash cookie, SYN-ACK acknowledging cookie plus one, ACK with probe payload, ACK with banner, internal parse to OutItem, then RST; no TCB and no timeout table" width="100%">
</p>

No TCB. No timeout table. No retransmission bookkeeping. Just arithmetic that the peer's TCP stack helps you verify.

### HLTCP: when statelessness ends

<p align="center">
  <img src="screenshots/hltcp-sequence.png" alt="HLTCP sequence: a stateless SYN is sent first; only a SYN-ACK creates the TCB; then ACK, an optional TLS handshake, internal evidence collection, and RST" width="100%">
</p>

The first SYN is stateless. A TCB exists only after the SYN-ACK, and the optional TLS handshake runs inside that user-space state. Raw frames bypass the host TCP stack; the final RST retires the flow.

## Modules

Counts below assume a full build with all optional dependencies enabled; modules whose libraries are missing simply disappear.

### Scan modules (11)

| Module | Probe | What it does |
|:---|:---:|:---|
| `tcp-syn` | — | Classic SYN scan with a SipHash cookie as ISN; optional `--send-rst`. |
| `udp` | UDP | Sends UDP payloads and validates responses. |
| `zbanner` | TCP | Stateless TCP handshake; payload on the third ACK; grabs the banner. |
| `tcp-state` | STATE | HLTCP stateful TCP; pairs with TLS/HTTP state probes. |
| `icmp-echo` | — | ICMP echo host discovery; can record TTL and IPID. |
| `icmp-time` | — | ICMP timestamp scan. |
| `sctp-init` | — | SCTP INIT scan. |
| `arp-req` | — | Layer-2 ARP scan in LAN mode. |
| `ndp-ns` | — | IPv6 NDP neighbor solicitation. |
| `yarrp-echo` | — | Stateless topology probing with ICMP echo. |
| `yarrp-udp` | — | Stateless topology probing with UDP + ICMP errors. |

### Probe modules (26)

- **General:** `http` (+ state), `hello` (+ UDP/state), `tls-hello`, `tls-state`, `dns`, `snmp`, `echo`, `ssh`, `jarm`, `h2c`, `h2`.
- **Fingerprinting:** `recog` (+ UDP/state, Recog XML), `nmap` (+ UDP, nmap-service-probes).
- **Scriptable:** `lua-tcp`, `lua-udp` — drop in a Lua script and you have a probe.
- **Plumbing:** `get-state`, `close-state`, `null`.
- **Developer examples:** `slot-test`, `slot-test-udp` — the two `ProbeSlot_Always` examples used by the lab; safe to read as templates.

### Output and generate modules

- **Output:** `text`, `csv`, `ndjson`, `bson`, `mongodb`, `list`, `null`.
- **Generate:** `blackrock` (default, stateless permutation), `ip-list`, `addr-list`, `ip-stream`, `addr-stream`.

Writing your own is intentionally boring: each module is a struct plus one line in a NULL-terminated registry, and the same metadata drives `--help-*`, parameter parsing, fuzzy search and interactive completion. Look for `REGISTER YOUR ... MODULE HERE` in [`src/scan-modules/scan-modules.c`](src/scan-modules/scan-modules.c) and friends.

## Documentation

The README is the landing page. The manual lives in [`docs/`](docs/README.md):

- [Getting started](docs/getting-started.md) — build, permissions, first scan, firewall
- [Targets and ports](docs/targets-and-ports.md) — IPv4/IPv6 input, files, ASN, excludes, sharding
- [Scanning modes](docs/scanning-modes.md) — stateless vs stateful, scan/probe pairings, recipes
- [Output](docs/output.md) — result levels, formats, MongoDB
- [Modules](docs/modules.md) — the four module types and what ships with Xtate
- [Module development](docs/module-development.md) — C interfaces, registration and slot-plan examples
- [Architecture](docs/architecture.md) · [ZBanner](docs/zbanner.md) · [HLTCP](docs/hltcp.md)
- [Chinese help and i18n](docs/help-i18n.md) — `--lang`, catalog fallback and UTF-8 layout
- [Interactive mode](docs/interactive-mode.md) — TTY/script mode, completion, history and Chinese help
- [Platform support](docs/platform-support.md) — CMake 3.13, old distros, Ninja and musl builds
- [Build artifacts](docs/build-artifacts.md) — aliases, exact toolchain names, Debug/DLL layout
- [Testing policy](docs/testing.md) — required Tier 0/1/2 checks after a change
- [Troubleshooting](docs/troubleshooting.md) · [Known limitations](docs/known-limitations.md)

中文文档：[`docs/zh-CN/`](docs/zh-CN/README.md)

## Build

See [Testing policy](docs/testing.md) for the required build/test matrix after a change.

### Linux

```bash
sudo apt install build-essential cmake pkg-config libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev
./build.sh                                  # interactive: compiler + config
./build.sh --compiler gcc --config release  # explicit
./build.sh --compiler clang --config debug  # explicit debug
./build.sh --generator ninja                # Ninja instead of Makefiles
./build.sh --static --minimal               # basic static musl build
```

Outputs: `bin/xtate` (release alias), `bin/xtate_debug` (debug alias), and
`bin/xtate-<compiler>-<config>` per-toolchain files. `--generator ninja|make`
selects the CMake generator; see [Platform support](docs/platform-support.md). See
[Build artifacts](docs/build-artifacts.md) for the alias rules. Build trees are
`build-<compiler>-<config>-<generator>`; `./clean.sh` removes them and `bin/xtate*` while
preserving `bin/.gitignore`.

Ubuntu 22.04/24.04 are the reference environments. On Fedora/Arch, install the equivalent development packages (`libpcap`, `openssl`, `pcre2`, `libxml2`, `libbson`, `mongo-c-driver`).

PCRE2 discovery uses CMake's package config when available and falls back to `pkg-config` on Debian/Ubuntu, so `pkg-config` is required alongside `libpcre2-dev` there.

Recommended compilers: GCC, Clang, MSVC and MinGW-w64. Xtate requires a 64-bit little-endian host; CMake stops early otherwise.

<details>
<summary><b>Windows build</b></summary>

Install **Npcap** (runtime), CMake, and Visual Studio 2022/2026 or MinGW-w64. For a
step-by-step beginner walkthrough, see [Windows quick start](docs/windows-quickstart.md);
the full platform/toolchain matrix and troubleshooting live in
[Getting started](docs/getting-started.md#build-on-windows).

Optional dependencies via Scoop (MSVC/clang-cl):

```powershell
scoop install openssl-lts lua54
```

Scoop does not package PCRE2, libbson or libmongoc; use vcpkg for the complete
probe/output set, or accept the reduced module count.

MSVC:

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
  -DOPENSSL_ROOT_DIR="$env:USERPROFILE\scoop\apps\openssl-lts\current"
cmake --build build-msvc --config Release -j 8
```

MinGW:

```powershell
cmake -S . -B build-mingw -G "MinGW Makefiles" `
  -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Release
cmake --build build-mingw -j 8
```

Run `scripts\build-windows.ps1` with no parameters to choose **one compiler**
and **one configuration** interactively. It asks before copying the source to
an ASCII staging directory and cleans the staging tree afterwards. The primary
binary is placed in `bin\xtate.exe` (or `bin\xtate_debug.exe` for Debug);
per-toolchain copies are `bin\xtate-<toolchain>-<config>.exe` (the Linux
`build.sh` convention is `bin/xtate`).

All three toolchains support Release and Debug: pass `-Config Debug` with
`-Toolchain msvc|clangcl|mingw`. Use `-Toolchain all` only when you explicitly
want the full matrix.

Npcap must be installed for packet I/O; `wpcap.dll` is loaded at runtime.

To remove project build trees and binaries (the Windows counterpart of
`clean.sh`):

```powershell
pwsh -File .\scripts\clean-windows.ps1
pwsh -File .\scripts\clean-windows.ps1 -IncludeStage  # also remove %LOCALAPPDATA%\xtate-build
```
</details>

<details>
<summary><b>Optional dependencies and what they unlock</b></summary>

| Dependency | Unlocks | Switch |
|:---|:---|:---|
| OpenSSL ≥ 1.1.1 | `tls-state`, `jarm`, TLS-aware probes | `-DWITH_OPENSSL=OFF` |
| PCRE2 (8-bit) | regex matching in `hello`, `http`, `recog`, `nmap` | `-DWITH_PCRE2=OFF` |
| LibXml2 | Recog XML fingerprint files | `-DWITH_LIBXML2=OFF` |
| libbson / libmongoc | BSON and MongoDB output | `-DWITH_BSON=OFF`, `-DWITH_MONGOC=OFF` |
| libpcap / Npcap | packet I/O (runtime) | loaded dynamically |
| PF_RING | zero-copy packet I/O on Linux (runtime) | optional |
| Lua 5.3/5.4 | `lua-tcp`, `lua-udp` (runtime) | optional |

Missing optional libraries simply remove the corresponding modules at compile time — the core scanner still builds. On Windows, CMake may warn about a found-but-incomplete PCRE2 from Conda, or about LibXml2/libbson/libmongoc not being installed; those are optional. Install a matching vcpkg triplet (for example `vcpkg install pcre2 libxml2 mongo-c-driver --triplet x64-windows`; see [Windows optional dependencies](docs/windows-dependencies.md) for MinGW/MSYS2 and full setup) if you need those modules.
</details>

> [!NOTE]
> Raw sockets need root on Linux or Administrator on Windows. On Linux, `sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate` is an alternative to `sudo` for each run, if you know what you are doing.

## Explore the CLI

```bash
xtate --usage                 # short usage and examples
xtate --help                  # every global parameter
xtate --intro                 # the architecture tour
xtate --list-scan             # 11 scan modules
xtate --list-probe            # 26 probe modules
xtate --list-out              # 7 output modules
xtate --list-gen              # 5 generate modules
xtate --help-scan zbanner     # module-specific parameters
xtate --lang zh --help        # Chinese human help (English fallback for untranslated strings)
xtate --interact              # interactive shell (TTY: completion/history; pipe: scripts)
```

## Papers and citation

Xtate's two engines come from our research:

- **ZBanner: Fast Stateless Scanning Capable of Obtaining Responses over TCP** — [arXiv:2405.07409](https://arxiv.org/abs/2405.07409) · [IPCCC 2024](https://doi.org/10.1109/IPCCC59868.2024.10850469)
- **Efficient Application-Layer Scanning with Hybrid-State Lightweight TCP Stack for TLS-based Service Monitoring** — [ICCT 2024](https://doi.org/10.1109/ICCT62411.2024.10946306)
- **Master's thesis:** *Research on Technologies of Network Protocol and Device Identification Based on Application-Layer Scanning* (NUDT, 2024)

<details>
<summary><b>BibTeX</b></summary>

```bibtex
@misc{chen2024zbanner,
  title         = {ZBanner: Fast Stateless Scanning Capable of Obtaining Responses over TCP},
  author        = {Chen, Chiyu and Lu, Yuliang and Yang, Guozheng and Xie, Yi and Guo, Shasha},
  year          = {2024},
  eprint        = {2405.07409},
  archivePrefix = {arXiv},
  primaryClass  = {cs.NI}
}

@inproceedings{chen2024hltcp,
  title     = {Efficient Application-Layer Scanning with Hybrid-State Lightweight TCP Stack for TLS-based Service Monitoring},
  author    = {Chen, Chiyu and Lu, Yuliang and Yang, Guozheng and Xie, Yi and Guo, Shasha},
  booktitle = {2024 IEEE 24th International Conference on Communication Technology (ICCT)},
  pages     = {2067--2073},
  year      = {2024},
  doi       = {10.1109/ICCT62411.2024.10946306}
}
```
</details>

If Xtate helps your research, a citation is appreciated more than a star.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the build
and test matrix, C/module guidelines and pull-request checklist. Report security
issues privately as described in [SECURITY.md](SECURITY.md); do not open a public
issue for a vulnerability.

## License and responsible use

AGPL-3.0. See [LICENSE](LICENSE). If you run a modified Xtate as a network service, the AGPL's network-use clause applies.

> [!WARNING]
> Xtate is a dual-use tool for measurement and security research. Use it only on networks you own or have written permission to test. You are responsible for complying with local law, ISP policy and the target network's rules.

Xtate started from [Masscan](https://github.com/robertdavidgraham/masscan)'s codebase; thanks to Robert Graham and every upstream project noted in the source. Xtate is a member of [404Starlink](https://github.com/knownsec/404StarLink).

Created by **Alvin Chen** (陈驰昱) · [shineccy@aliyun.com](mailto:shineccy@aliyun.com). The original code was written during his master's studies at the National University of Defense Technology and the Anhui Province Key Laboratory of Cyberspace Security Situation Awareness and Evaluation.

<div align="center">
  <sub>God is Stateless. Physical layer? We stop at the wire.</sub>
</div>
