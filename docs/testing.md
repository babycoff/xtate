# Testing and compatibility policy

**English** · [中文](zh-CN/testing.md)

Xtate now has several compilers, generators and libc variants. A change is not
"done" just because one local build passes. Use the tiers below to choose the
minimum verification, and report exactly what you ran.

## Tier 0 — every code change

Run these for any change that touches C code, CMake, or user-facing behavior:

```bash
# Linux, GCC, current CMake
./build.sh --compiler gcc --config release --generator ninja
./bin/xtate --selftest

# Windows, MSVC (Git Bash or PowerShell)
pwsh -File .\scripts\build-windows.ps1 -Toolchain msvc -Config Release -Yes
.\bin\xtate.exe --selftest
```

Then run the relevant focused suites:

```bash
XTATE_BIN=./bin/xtate bash tests/i18n/test.sh
XTATE_BIN=./bin/xtate bash tests/interactive/test.sh
```

- Help/i18n change: `tests/i18n/test.sh` must pass.
- Interactive-mode change: `tests/interactive/test.sh` must pass.
- Linux TTY/terminal change: additionally `tests/interactive/tty.sh`.
- Packet parsing/memory ownership change: run the sanitizer selftest
  (see CONTRIBUTING).
- Large-result/output change: run the relevant `tests/large-batch/` case and
  report the scale and disk usage.

## Tier 1 — build, portability and toolchain changes

In addition to Tier 0, verify the affected dimension:

| Change touches | Also run |
|:---|:---|
| CMake / compiler flags / headers | Linux Clang + one Debug build |
| build.sh / generators | GCC and Clang; Make and Ninja |
| Windows build scripts | MSVC, ClangCL and MinGW |
| i18n/catalog | `tests/i18n/test.sh` on a Windows binary too |
| interactive/TTY | `tests/interactive/test.sh` and `tty.sh` on Linux; interactive smoke on Windows |
| old distro / CMake | Debian 10-style CMake 3.13 + GCC 8 build |
| musl/libc | Alpine musl build |
| static linking | Alpine `--static --minimal`, then `file` and `--selftest` |

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

## Tier 2 — release

Before tagging a release, verify the full matrix that the project claims:

| Platform | Compiler | Config | Generator | Required |
|:---|:---|:---|:---|:---|
| Ubuntu 24.04 | GCC 13 | Release/Debug | Make/Ninja | yes |
| Ubuntu 24.04 | Clang 18 | Release/Debug | Make/Ninja | yes |
| Debian 10 (baseline) | GCC 8.3, CMake 3.13.4 | Release | Make/Ninja | basic build + selftest |
| Alpine 3.20 (musl) | GCC 13.2 | Release | Ninja | basic build + selftest |
| Alpine 3.20 (musl) | GCC 13.2 | Release | Ninja | `--static --minimal`, `file` + selftest |
| Windows 10/11 | MSVC/ClangCL/MinGW | Release/Debug | Visual Studio / MinGW | build + selftest |

Required release evidence:

```text
Linux:   compile warnings = 0
Windows: compile warnings = 0
selftest: pass on every artifact that is shipped
i18n coverage: pass
interactive + PTY: pass
```

## Rules

- **Warnings are defects.** New warnings in Tier 0/1 need a fix or an explicit,
  documented suppression; do not silently raise the warning count.
- **Optional dependencies must stay optional.** A missing PCRE2/LibXml2/bson/
  mongoc must not fail the basic build.
- **No silent fallback.** If a check is unavailable (no Windows machine, no
  Docker, no `script`), say so in the PR; do not mark it as passed.
- **Use exact binary names** for evidence; aliases (`xtate`, `xtate.exe`) are
  convenience copies, not reproducibility targets.
- **Record commands, versions and results** in the pull request template.

## Current test suites

| Suite | Command | Scope |
|:---|:---|:---|
| selftest | `xtate --selftest` | built-in regression |
| i18n | `tests/i18n/test.sh` | Chinese help coverage |
| interactive | `tests/interactive/test.sh` | non-TTY commands/help/state |
| PTY | `tests/interactive/tty.sh` | terminal restore + completion |
| large batch | `tests/large-batch/` | replay/RSS/output failure |
