# 构建产物与二进制命名

[English](../build-artifacts.md) · **中文**

两个构建脚本都把产物放在项目内的 `bin/` 目录。**别名**文件（`xtate` /
`xtate.exe`）是某一次构建产物的复制，不是包装脚本。按工具链命名的文件是稳定的，
CI 或复现构建应使用它们。

## Linux

`./build.sh --compiler gcc|clang --config release|debug` 生成：

| 文件 | 含义 |
|:---|:---|
| `bin/xtate` | 最近一次 **Release** 构建的别名 |
| `bin/xtate_debug` | 最近一次 **Debug** 构建的别名 |
| `bin/xtate-gcc-release` | 精确的 GCC Release 产物 |
| `bin/xtate-gcc-debug` | 精确的 GCC Debug 产物 |
| `bin/xtate-clang-release` | 精确的 Clang Release 产物 |
| `bin/xtate-clang-debug` | 精确的 Clang Debug 产物 |

构建目录按 `build-<compiler>-<config>/` 隔离。

## Windows

`scripts\build-windows.ps1 -Toolchain msvc|clangcl|mingw -Config Release|Debug`
生成：

| 文件 | 含义 |
|:---|:---|
| `bin\xtate.exe` | 主 **Release** 版本的别名（有 MSVC 时优先 MSVC） |
| `bin\xtate_debug.exe` | 主 **Debug** 版本的别名 |
| `bin\xtate-msvc-release.exe` | 精确的 MSVC Release 产物 |
| `bin\xtate-msvc-debug.exe` | 精确的 MSVC Debug 产物 |
| `bin\xtate-clangcl-release.exe` | 精确的 ClangCL Release 产物 |
| `bin\xtate-clangcl-debug.exe` | 精确的 ClangCL Debug 产物 |
| `bin\xtate-mingw-release.exe` | 精确的 MinGW Release 产物 |
| `bin\xtate-mingw-debug.exe` | 精确的 MinGW Debug 产物 |

vcpkg app-local 运行库 DLL 会复制到这些二进制旁边
（`pcre2-8.dll`、`libxml2.dll`、`bson2.dll`、`mongoc2.dll` 等）。

## 别名规则

- 别名会被你最近一次运行的构建覆盖。
- Windows 一次构建多个工具链时，`xtate.exe` 优先使用 MSVC；否则使用第一个构建的
  工具链。
- Linux 的 Release 构建覆盖 `bin/xtate`，Debug 构建覆盖 `bin/xtate_debug`；
  连续构建多个编译器时，最后一次构建会覆盖别名。
- 按工具链命名的文件始终对应精确的编译器/配置。

CI、可复现分发或对比工具链时，请使用按工具链命名的文件，不要依赖别名。

## 功能差异

- MSVC / ClangCL 可以使用 vcpkg 的 `x64-windows` 包。
- MinGW 不能链接这些 MSVC ABI 包，可能缺少可选模块。
- Debug 版本链接 debug 运行库和 debug DLL；不要混用 Debug/Release DLL。
- `clean.sh` / `clean-windows.ps1` 删除构建目录和 `bin/xtate*`，但不会卸载
  vcpkg 包。
