# Testing and compatibility policy

**English** · [中文](zh-CN/testing.md)

Xtate now has several compilers, generators and libc variants. A change is not
"done" just because one local build passes. Use the tiers below to choose the
minimum verification, and report exactly what you ran.

## Tier 0 — every code change, on the platform you have

You only need one working platform. Do **not** block a contribution because
you do not have the other OS.

On Linux:

```bash
./build.sh --compiler gcc --config release --generator ninja
./bin/xtate --selftest
```

On Windows (PowerShell):

```powershell
pwsh -File .\scripts\build-windows.ps1 -Toolchain msvc -Config Release -Yes
.\bin\xtate.exe --selftest
```

Then run the relevant focused suites on that platform:

```bash
XTATE_BIN=./bin/xtate bash tests/i18n/test.sh
XTATE_BIN=./bin/xtate bash tests/interactive/test.sh
```

- Help/i18n change: `tests/i18n/test.sh` must pass.
- Interactive-mode change: `tests/interactive/test.sh` must pass.
- Linux TTY/terminal change: additionally `tests/interactive/tty.sh`.
- Header change: run `tests/include/check_headers.sh`.
- Packet parsing/memory ownership change: run the sanitizer selftest
  (see CONTRIBUTING).
- Large-result/output change: run the relevant `tests/large-batch/` case and
  report the scale and disk usage.

If the other platform is unavailable, write `not available` in the pull
request. The maintainers/CI will cover it; do not claim it passed.

## Tier 1 — affected dimension (when available)

Add these only for the dimensions you touched and can actually run. Missing
environments are reported, not silently skipped or marked as passed.

| Change touches | Also run |
|:---|:---|
| CMake / compiler flags / headers | Linux Clang + one Debug build |
| build.sh / generators | GCC and Clang; Make and Ninja |
| Windows build scripts | MSVC, ClangCL, MinGW UCRT64 and legacy MINGW64 |
| i18n/catalog | `tests/i18n/test.sh` on a Windows binary too |
| interactive/TTY | `tests/interactive/test.sh` and `tty.sh` on Linux; interactive smoke on Windows |
| old distro / CMake | Debian 10-style CMake 3.13 + GCC 8 build |
| old libc fallbacks | build with `-DXTATE_NO_SENDMMSG -DXTATE_NO_PTHREAD_SETNAME` |
| musl/libc | Alpine musl build |
| static linking | Alpine `--static --minimal`, then `file` and `--selftest` |
| full Linux matrix | `bash tests/platform/matrix.sh` (add `XTATE_CN_MIRROR=1` only in mainland China) |

Useful commands:

```bash
# Compiler/generator combinations
./build.sh --compiler clang --config debug --generator ninja
./build.sh --compiler gcc --config release --generator make

# Windows matrix
pwsh -File .\scripts\build-windows.ps1 -Toolchain all -Config Release -Yes

# Alpine musl (run inside the Alpine builder)
./build.sh --generator ninja
./build.sh --generator ninja --static --minimal
```

## Tier 2 — release (maintainer/CI)

Release owners run the full matrix that the project claims. External
contributors are not expected to own this tier:

| Platform | Compiler | Config | Generator | Required |
|:---|:---|:---|:---|:---|
| Ubuntu 24.04 | GCC 13 | Release/Debug | Make/Ninja | yes |
| Ubuntu 24.04 | Clang 18 | Release/Debug | Make/Ninja | yes |
| Debian 10 (baseline) | GCC 8.3, CMake 3.13.4 | Release | Make/Ninja | basic build + selftest |
| Alpine 3.20 (musl) | GCC 13.2 | Release | Ninja | basic build + selftest |
| Alpine 3.20 (musl) | GCC 13.2 | Release | Ninja | `--static --minimal`, `file` + selftest |
| Windows 10/11 | MSVC / ClangCL / MinGW UCRT64 / MINGW64 | Release | Visual Studio / MSYS2 | build + selftest |

Required release evidence:

```text
Linux:   compile warnings = 0
Windows: compile warnings = 0
selftest: pass on every artifact that is shipped
i18n coverage: pass
interactive + PTY: pass
```

## Rules

> [!IMPORTANT]
> Lab scanner containers must install `iptables` and run `/src/firewall/add_rules.sh` before `zbanner`, `tcp-state`, `tls-state`, H2/H3 or any state probe. Target containers do not need the rules. Missing rules produce `open` with no banner/TLS output — this was the root cause of the TLS composition lab failure.


- **Warnings are defects.** New warnings in Tier 0/1 need a fix or an explicit,
  documented suppression; do not silently raise the warning count.
- **Optional dependencies must stay optional.** A missing PCRE2/LibXml2/bson/
  mongoc must not fail the basic build.
- **No silent fallback.** If a check is unavailable (no Windows machine, no
  Docker, no `script`), say so in the PR; do not mark it as passed.
- **Use exact binary names** for evidence; aliases (`xtate`, `xtate.exe`) are
  convenience copies, not reproducibility targets.
- **Record commands, versions and results** in the pull request template.

## CI

`.github/workflows/ci.yml` runs the Linux half of Tier 0 on GitHub Actions:

- GCC and Clang;
- Release and Debug;
- header self-containment;
- target syntax, i18n and interactive suites;
- PTY terminal test on GCC/Release.

Windows builds run in `.github/workflows/windows.yml` with MSVC, ClangCL and
MSYS2 MinGW UCRT64/MINGW64. The hosted runners do not install Npcap, so CI
builds and runs `--selftest` but does not perform a live packet scan.

## Benchmarks

`tests/bench/` is a manual Linux benchmark suite for target ingestion and the
offline Tx path. It is deliberately not part of the CI gate because wall time
and RSS are noisy on shared runners. See `tests/bench/README.md`.

## Current test suites

| Suite | Command | Scope |
|:---|:---|:---|
| header self-containment | `tests/include/check_headers.sh` | every header compiles on its own |
| selftest | `xtate --selftest` | built-in regression |
| i18n | `tests/i18n/test.sh` | Chinese help coverage |
| target syntax | `tests/target/test.sh` | address/CIDR/explicit/component ranges |
| interactive | `tests/interactive/test.sh` | non-TTY commands/help/state |
| TUI control client | `python tests/tui/test_tui.py` | one-command private control plane, non-TTY snapshot, Windows Named Pipe / Unix socket |
| GUI control client | `python tests/gui/test_gui.py` | one-command private control plane, embedded page + token, Host/token rejection, authorization gate, dry-run job, manifest |
| JARM aggregation | `tests/jarm/test.sh` | output-side parts, stats, retry list |
| module templates | `tests/module-examples/test.sh` | compile all four module interface examples |
| parameter parser | `tests/config/test.sh` | unknown/missing/help/CLI parser basics |
| slot-plan lab | `tests/lab/run.sh` | real TCP/UDP `ProbeSlot_Always`, JARM `AfterFirstReply`, SSH banner/KEX, h2c/h2 framing, TLS certificate details |
| ZBanner pcap matrix | `tests/zbanner/run.sh` | offline `file:` replay: SYNACK/RST, banner, retransmit, all-banner limit/floor, wrong ACK, IPv6, zero-window, Lua payload mismatch |
| HTTP pcap matrix | `tests/http-pcap/run.sh` | offline keyword/regex/header/body/no-match checks |
| tcp-syn pcap matrix | `tests/tcp-syn-pcap/run.sh` | offline SYN-ACK/RST basics |
| HTTP-state pcap matrix | `tests/http-state-pcap/run.sh` | recorded plaintext stateful HTTP replay + header/no-match |
| H2C synthetic pcap matrix | `tests/h2c-pcap/run.sh` | cleartext HTTP/2 SETTINGS/HEADERS/DATA frames |
| UDP pcap matrix | `tests/udp-pcap/run.sh` | echo cookie response + invalid response |
| TLS+H2 local CI | `tests/lab/ci-h2.sh` | local TLS HTTP/2 target; status/header/body |
| TLS+H2 depth | `tests/lab/ci-h2-depth.sh` | status 404, empty DATA, extra header, matcher |
| H2C depth | `tests/lab/ci-h2c-depth.sh` | settings/ping, all-frames |
| Protocol probe lab | `tests/lab/ci-probes.sh` | Redis/Memcached/NTP/MQTT/SOCKS5/Telnet fake servers |
| Batch B protocol lab | `tests/lab/ci-batch-b.sh` | MySQL/PostgreSQL/MongoDB/SMTP/IMAP/POP3/FTP/ManageSieve tcp+state |
| Batch C protocol lab | `tests/lab/ci-batch-c.sh` | IPP/AMQP/PPTP tcp+state |
| TLS/STARTTLS composition | `tests/lab/ci-tls-composition.sh` | SMTP state in implicit TLS / STARTTLS |
| QUIC/HTTP3 local CI | `tests/lab/ci-quic.sh` | local aioquic HTTP/3 target; body/match |
| QUIC/HTTP3 depth | `tests/lab/ci-quic-depth.sh` | body/header/no-match, status 404, empty body, extra header |
| HTTP3 frame fixture | `tests/http3-frame/` | decrypted HEADERS/DATA QPACK selftest |
| PTY | `tests/interactive/tty.sh` | terminal restore + completion |
| large batch | `tests/large-batch/` | replay/RSS/output failure |
