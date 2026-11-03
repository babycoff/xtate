# 测试与兼容性规范

[English](../testing.md) · **中文**

Xtate 现在有多个编译器、生成器和 libc 变体。一个改动不能只靠“某一次本机构建通过”
就算完成。按下面的分级选择最低验证，并在 PR 中写清楚实际跑了什么。

## Tier 0：每次代码改动，在你有环境的那一侧

**只需要一个平台**。不要因为缺少另一个系统就阻止提交。

Linux：

```bash
./build.sh --compiler gcc --config release --generator ninja
./bin/xtate --selftest
```

Windows（PowerShell）：

```powershell
pwsh -File .\scripts\build-windows.ps1 -Toolchain msvc -Config Release -Yes
.\bin\xtate.exe --selftest
```

再在该平台运行对应测试：

```bash
XTATE_BIN=./bin/xtate bash tests/i18n/test.sh
XTATE_BIN=./bin/xtate bash tests/interactive/test.sh
```

- 改帮助/i18n：必须跑 `tests/i18n/test.sh`；
- 改交互式模式：必须跑 `tests/interactive/test.sh`；
- 改 Linux TTY/终端：额外跑 `tests/interactive/tty.sh`；
- 头文件改动：运行 `tests/include/check_headers.sh`。
- 改报文解析/内存所有权：跑 sanitizer selftest（见 CONTRIBUTING）；
- 改大批量/输出：运行对应 `tests/large-batch/` 用例，并报告规模和磁盘占用。

## Tier 1：受影响的维度（有环境时）

只对你实际改动、并且确实能运行的环境追加检查。缺少环境要报告，不能静默跳过
或标记通过。

| 改动范围 | 追加验证 |
|:---|:---|
| CMake / 编译选项 / 头文件 | Linux Clang + 一个 Debug 构建 |
| build.sh / 生成器 | GCC 和 Clang；Make 和 Ninja |
| Windows 构建脚本 | MSVC、ClangCL、MinGW |
| i18n/catalog | Windows 二进制也跑 `tests/i18n/test.sh` |
| 交互/TTY | Linux `tests/interactive/test.sh` + `tty.sh`；Windows 交互冒烟 |
| 旧发行版/CMake | Debian 10 风格 CMake 3.13 + GCC 8 构建 |
| 旧 libc 回退 | 用 `-DXTATE_NO_SENDMMSG -DXTATE_NO_PTHREAD_SETNAME` 构建 |
| musl/libc | Alpine musl 构建 |
| 静态链接 | Alpine `--static --minimal`，`file` + selftest |
| Linux 完整矩阵 | `bash tests/platform/matrix.sh`（仅大陆网络加 `XTATE_CN_MIRROR=1`） |

常用命令：

```bash
# 编译器和生成器组合
./build.sh --compiler clang --config debug --generator ninja
./build.sh --compiler gcc --config release --generator make

# Windows 矩阵
pwsh -File .\scripts\build-windows.ps1 -Toolchain all -Config Release -Yes

# Alpine musl（在 Alpine builder 内）
./build.sh --generator ninja
./build.sh --generator ninja --static --minimal
```

## Tier 2：发布前（维护者/CI）

发布负责人验证完整矩阵。外部贡献者不承担这一层：

| 平台 | 编译器 | 配置 | 生成器 | 要求 |
|:---|:---|:---|:---|:---|
| Ubuntu 24.04 | GCC 13 | Release/Debug | Make/Ninja | 必须 |
| Ubuntu 24.04 | Clang 18 | Release/Debug | Make/Ninja | 必须 |
| Debian 10（基线） | GCC 8.3, CMake 3.13.4 | Release | Make/Ninja | 基础构建 + selftest |
| Alpine 3.20（musl） | GCC 13.2 | Release | Ninja | 基础构建 + selftest |
| Alpine 3.20（musl） | GCC 13.2 | Release | Ninja | `--static --minimal`，`file` + selftest |
| Windows 10/11 | MSVC/ClangCL/MinGW | Release/Debug | Visual Studio / MinGW | 构建 + selftest |

发布必须报告：

```text
Linux:   编译 warning = 0
Windows: 编译 warning = 0
selftest: 每个发布产物通过
i18n coverage: 通过
interactive + PTY: 通过
```

## 规则

- **Warning 是缺陷。** Tier 0/1 出现新 warning 必须修复或明确记录抑制；
  不能悄悄提高 warning 数。
- **可选依赖必须保持可选。** 缺少 PCRE2/LibXml2/bson/mongoc 不能导致基础构建失败。
- **只有单平台是正常的。** 完成当前平台 Tier 0 即可；另一侧由维护者/CI 负责。
- **不能假装跑过。** 没有 Windows 机器、Docker 或 `script` 时，在 PR 中写明；
  不能标记为通过。
- **证据使用精确产物名。** 别名 `xtate`/`xtate.exe` 只是方便复制，
  不作为可复现目标。
- **记录命令、版本和结果。** 填 PR 模板里的验证区。

## CI

`.github/workflows/ci.yml` 在 GitHub Actions 上跑 Linux 侧 Tier 0：

- GCC 和 Clang；
- Release 和 Debug；
- 头文件自包含；
- 目标语法、i18n 和交互测试；
- GCC/Release 的 PTY 终端测试。

Windows 构建仍需维护者/手动验证，直到配置带 Npcap/Visual Studio 的托管 runner。

## Benchmark

`tests/bench/` 是手动运行的 Linux 基准套件，覆盖目标解析和离线 Tx 路径。由于
共享 runner 上的耗时/RSS 噪声较大，默认不放进 CI。详见
`tests/bench/README.md`。

## 现有测试套件

| 套件 | 命令 | 范围 |
|:---|:---|:---|
| 头文件自包含 | `tests/include/check_headers.sh` | 每个头文件可单独编译 |
| selftest | `xtate --selftest` | 内置回归 |
| i18n | `tests/i18n/test.sh` | 中文帮助覆盖率 |
| interactive | `tests/interactive/test.sh` | 非 TTY 命令/帮助/状态 |
| PTY | `tests/interactive/tty.sh` | 终端恢复 + 补全 |
| large batch | `tests/large-batch/` | replay/RSS/输出失败 |
