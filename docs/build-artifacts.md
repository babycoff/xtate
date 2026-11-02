# Build artifacts and binary names

**English** · [中文](zh-CN/build-artifacts.md)

Both build scripts keep outputs in the project-local `bin/` directory. An
**alias** file (`xtate` / `xtate.exe`) is a copy of one selected build, not a
wrapper script. The per-toolchain files are stable and should be used by CI or
when reproducing a build.

## Linux

`./build.sh` with `--compiler gcc|clang --config release|debug` creates:

| File | Meaning |
|:---|:---|
| `bin/xtate` | Alias of the most recently built **Release** binary |
| `bin/xtate_debug` | Alias of the most recently built **Debug** binary |
| `bin/xtate-gcc-release` | Exact GCC Release build |
| `bin/xtate-gcc-debug` | Exact GCC Debug build |
| `bin/xtate-clang-release` | Exact Clang Release build |
| `bin/xtate-clang-debug` | Exact Clang Debug build |

Build trees are isolated as `build-<compiler>-<config>/`.

## Windows

`scripts\build-windows.ps1 -Toolchain msvc|clangcl|mingw -Config Release|Debug`
creates:

| File | Meaning |
|:---|:---|
| `bin\xtate.exe` | Alias of the primary **Release** build (MSVC if present) |
| `bin\xtate_debug.exe` | Alias of the primary **Debug** build |
| `bin\xtate-msvc-release.exe` | Exact MSVC Release build |
| `bin\xtate-msvc-debug.exe` | Exact MSVC Debug build |
| `bin\xtate-clangcl-release.exe` | Exact ClangCL Release build |
| `bin\xtate-clangcl-debug.exe` | Exact ClangCL Debug build |
| `bin\xtate-mingw-release.exe` | Exact MinGW Release build |
| `bin\xtate-mingw-debug.exe` | Exact MinGW Debug build |

Runtime DLLs produced by vcpkg app-local deployment are copied next to these
binaries (`pcre2-8.dll`, `libxml2.dll`, `bson2.dll`, `mongoc2.dll`, ...).

## Alias rules

- The alias is copied/overwritten by the build you run.
- On Windows, if several toolchains are built in one run, MSVC is preferred for
  `xtate.exe`; otherwise the first built toolchain is used.
- On Linux, a Release build overwrites `bin/xtate`; a Debug build overwrites
  `bin/xtate_debug`. Building several compilers means the last one wins for the
  alias.
- The per-toolchain filename always identifies the exact compiler/config.

For CI, reproducible distribution or comparing toolchains, use the exact
per-toolchain name, not the alias.

## Feature differences

- MSVC / ClangCL builds can use vcpkg's `x64-windows` packages.
- MinGW cannot link those MSVC-ABI packages; optional modules may be absent.
- Debug builds link debug runtime libraries and debug DLLs; do not mix Debug and
  Release DLLs.
- `clean.sh` / `clean-windows.ps1` remove build trees and `bin/xtate*`; they do
  not uninstall vcpkg packages.
