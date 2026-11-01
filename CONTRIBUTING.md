# Contributing to Xtate

[中文](#中文)

Xtate is a C99 network scanner for authorized, large-scale active measurement.
Contributions are welcome — bug fixes, portability work, module improvements,
tests, documentation, and careful performance work.

## Ground rules

- **Only scan systems you own or have written permission to test.** Do not use
  issues, pull requests or CI to probe third-party networks.
- **Do not open a public issue for a security vulnerability.** Follow
  [SECURITY.md](SECURITY.md) instead.
- Keep changes focused. One logical change per pull request is much easier to
  review, test and revert than a mixed refactor.
- User-facing behavior changes need tests and documentation. The docs are
  maintained in English and Chinese; update both trees when the change is
  user-visible.
- By contributing you agree that your contribution is licensed under the
  repository's **AGPL-3.0** license.

## Before you start

- Search existing issues and pull requests.
- For a design change, open a short issue first so the approach can be agreed
  before a large implementation.
- Read [docs/getting-started.md](docs/getting-started.md),
  [docs/architecture.md](docs/architecture.md) and the relevant module page.
- Reproduce on a **local lab** (loopback, VM, Docker network or a pcap replay),
  not on the public Internet.

## Build and test

Linux (reference environment):

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/xtate --selftest
```

Windows (all supported toolchains):

```powershell
pwsh -File .\scripts\build-windows.ps1 -Toolchain all -Yes
```

Useful checks before opening a pull request:

```bash
# sanitizer selftest, if your change touches packet parsing or memory ownership
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="-O1 -fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build-asan -j
ASAN_OPTIONS=detect_leaks=0 ./build-asan/xtate --selftest

# deterministic large-batch replay (local Docker image required)
XTATE_BIN=$PWD/build/xtate bash tests/large-batch/replay.sh

# output failure / RSS checks (optional MongoDB image)
XTATE_BIN=$PWD/build/xtate bash tests/large-batch/failure.sh
```

If a full suite needs substantial time or a MongoDB image, say so in the pull
request: at minimum, report the exact commands you ran and the results.

## C and module guidelines

- Target **C99**, no compiler-specific extensions outside existing `#ifdef`
  portability blocks.
- Follow [.clang-format](.clang-format). Run `./format.sh` or clang-format on
  the files you changed; do not reformat unrelated code.
- Keep the four module interfaces intact: **Scan**, **Probe**, **Generate**,
  **Output**. New modules are registered at build time and must declare their
  parameters via the existing `ConfParam` mechanism.
- Do not add a mandatory dependency. Optional libraries (OpenSSL, PCRE2,
  LibXml2, libbson/libmongoc) must be guarded with the existing feature macros.
- Error paths matter: return failure, log a diagnosable message, and do not
  silently drop results. Packet buffers must not be freed by the wrong layer.
- Prefer bounded queues and bounded retry policies over unbounded result
  accumulation.
- Keep hot-path changes justified with a reproducible benchmark; `tcp-syn` and
  `zbanner` throughput is a core property.
- Add comments for non-obvious wire-format or state-machine logic, not for
  self-evident assignments.

## Tests and documentation

- Add a regression test when fixing a bug. The existing suites live under
  `tests/`; the large-batch suite documents its own scale and disk costs.
- Update `docs/` and `docs/zh-CN/` for user-visible flags, output formats,
  module behavior, limitations or security implications.
- Do not edit `reports/` artifacts as if they were source; they are local
  investigation output.
- Version bumps and release notes are maintainer work; do not bump the version
  in a normal pull request unless asked.

## Commit and pull request style

- Write a short imperative subject, for example:
  - `fix: bound MongoDB output retries`
  - `docs: clarify Windows loopback RST behavior`
  - `test: add 1M replay RSS check`
- Explain **why** in the body, not just what changed.
- Reference the issue with `Fixes #123` when applicable.
- Include the exact verification commands and results in the pull request.
- Keep generated binaries, packet captures, keys and third-party scan data out
  of commits unless a small, sanitized fixture is genuinely required.

Use the pull request template and complete its checklist.

## Reporting bugs and proposing features

Use the issue templates:

- **Bug report** — reproducible behavior, environment, commands and logs.
- **Feature request** — the problem, proposed behavior and alternatives.

For security issues use [SECURITY.md](SECURITY.md), never a public issue.

## 中文

Xtate 是 C99 编写的、面向**授权范围内**大规模主动测量的网络扫描器。欢迎提交
bug 修复、跨平台适配、模块改进、测试、文档和经过验证的性能优化。

### 基本规则

- **只扫描你拥有或获得书面授权的系统。** 不要利用 issue、PR 或 CI 探测第三方网络。
- **安全漏洞不要开公开 issue**，请按 [SECURITY.md](SECURITY.md) 私密报告。
- 一个 PR 只做一件逻辑上的事；混合重构会让 review、回滚和测试都变困难。
- 面向用户的行为变化需要测试和文档；文档有中英两套，用户可见变化请同步更新。
- 提交即表示你同意贡献按仓库的 **AGPL-3.0** 许可证授权。

### 开始之前

- 先搜索已有 issue 和 PR。
- 较大的设计改动先开一个简短 issue 对齐方向。
- 阅读 `docs/getting-started.md`、`docs/architecture.md` 和相关模块文档。
- 在**本地实验环境**（loopback、虚拟机、Docker 网络或 pcap 回放）复现，不要扫描公网。

### 构建与测试

Linux：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/xtate --selftest
```

Windows：

```powershell
pwsh -File .\scripts\build-windows.ps1 -Toolchain all -Yes
```

提交前按改动范围运行：

```bash
# 涉及包解析/内存所有权时建议跑 sanitizer
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="-O1 -fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build-asan -j
ASAN_OPTIONS=detect_leaks=0 ./build-asan/xtate --selftest

# 确定性大批量回放（需要本地 Docker 镜像）
XTATE_BIN=$PWD/build/xtate bash tests/large-batch/replay.sh

# 输出失败 / RSS 检查（MongoDB 镜像可选）
XTATE_BIN=$PWD/build/xtate bash tests/large-batch/failure.sh
```

需要较长时间或 MongoDB 镜像的测试，在 PR 里说明；至少给出实际执行的命令和结果。

### C 与模块规范

- 目标语言是 **C99**；除现有可移植性 `#ifdef` 外，不引入编译器扩展。
- 遵循 `.clang-format`，用 `./format.sh` 或 clang-format 处理改动文件，不要重排无关代码。
- 保持四类模块接口：**Scan**、**Probe**、**Generate**、**Output**。新模块在构建时注册，参数走现有 `ConfParam`。
- 不增加强制依赖。OpenSSL、PCRE2、LibXml2、libbson/libmongoc 必须沿用现有特性宏保护。
- 错误路径要返回失败、记录可诊断日志，不能静默丢结果；packet buffer 不能由错误层释放。
- 优先使用有界队列和有界重试，不要无界积累结果。
- 热路径优化要有可复现基准；`tcp-syn` 和 `zbanner` 吞吐是核心指标。
- 注释解释不直观的 wire format 或状态机，不要注释显然的赋值。

### 测试与文档

- 修 bug 时尽量加回归测试；现有套件在 `tests/`，大批量套件在自身 README 中说明了规模和磁盘成本。
- 用户可见的 flag、输出格式、模块行为、限制或安全影响，需同步更新 `docs/` 和 `docs/zh-CN/`。
- 不要把 `reports/` 下的本地调查产物当作源码提交。
- 版本号和 release notes 由维护者处理；普通 PR 不要主动改版本号。

### 提交与 PR 风格

- 标题用简短祈使句，例如：
  - `fix: bound MongoDB output retries`
  - `docs: clarify Windows loopback RST behavior`
  - `test: add 1M replay RSS check`
- 正文解释**为什么**改，而不只是改了什么。
- 相关 issue 用 `Fixes #123`。
- PR 中写清楚实际验证命令和结果。
- 不要把生成二进制、抓包、密钥或第三方扫描数据提交进来，除非是确实需要的小型脱敏 fixture。

请使用 PR 模板并完成其中的检查项。

### 报告问题与提需求

- **Bug report**：可复现行为、环境、命令和日志。
- **Feature request**：问题、期望行为和替代方案。

安全漏洞请走 [SECURITY.md](SECURITY.md)，不要开公开 issue。
