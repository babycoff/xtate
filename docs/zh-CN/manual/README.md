# Xtate 3.0 手册

[English](../../manual/README.md) · **中文**

这是 Xtate 3.0 扫描控制台及其背后命令行、控制面与 job 工作流的任务导向手册。手册按本代码树编写：`web/gui.html` 中的浏览器控制台、`src/util-scan/gui.c` 中的回环 GUI 服务器，以及它使用的扫描引擎、控制面和 job manager。

本手册描述 **3.0.0-rc.5 候选发布版**。它记录本代码树中已存在、并由测试覆盖的内容；行为仍有限制时，手册会直说，而不是承诺未来的功能。

## 本手册适合谁

- **想用控制台的操作者。** 从[01 · 安装与快速上手](./01-install-and-quickstart.md)开始，然后读[02 · GUI 控制台](./02-gui-console.md)。
- **偏好命令行的用户。** 从[03 · CLI 与 job](./03-cli-and-jobs.md)开始。
- **自动化与 AI 客户端。** 先读 [03](./03-cli-and-jobs.md) 中控制面和 job 的内容，再读深入参考 [MCP server](../mcp-server.md)与 [Agent Skill](../agent-skill.md)。
- **从 2.44.x 迁移的人。** 扫描引擎与结果格式未变；新增的是扫描优先的控制台、服务端预检，以及用一条命令启动 GUI/MCP。见 [3.0.0-rc.5 发布说明](../release-notes/3.0.0-rc.5.md)。

## 章节

| 章节 | 内容 |
|:---|:---|
| [01 · 安装与快速上手](./01-install-and-quickstart.md) | 构建或验证二进制、权限、第一次扫描、第一次 GUI 会话 |
| [02 · GUI 控制台](./02-gui-console.md) | 控制台的每个页面与字段、预检、授权、安全模型、限制 |
| [03 · CLI 与 job](./03-cli-and-jobs.md) | 扫描选项与示例、输出、控制面、托管 job、结果文件 |
| [04 · 目标与扫描](./04-targets-and-scanning.md) | IPv4/IPv6、CIDR/区间/文件/排除、端口、扫描引擎与尝试次数 |
| [05 · 模块与参数](./05-modules-and-parameters.md) | 扫描/探测/输出/生成模块、配对规则、常用参数 |
| [06 · 结果与文件](./06-results-and-files.md) | NDJSON 记录、manifest、分片、索引、压缩与配额 |
| [07 · 协议与 HTTP/3](./07-protocols-and-http3.md) | HTTP/1.1、HTTP/2、HTTP/3/QUIC、DNS/TLS、能力上报、RAW 链接 |
| [08 · 架构与安全](./08-architecture-and-security.md) | 流水线、线程、控制面、GUI/MCP 边界、部署 |
| [09 · 故障排查](./09-troubleshooting.md) | 空结果、防火墙、权限、TUN/fake-IP、Windows 专项 |

## 阅读路径

1. **第一次扫描，最快路径：** [01](./01-install-and-quickstart.md) → 第一次 CLI 扫描 → [03](./03-cli-and-jobs.md) 了解输出。
2. **控制台优先：** [01](./01-install-and-quickstart.md) → `xtate --gui` → 逐页读 [02](./02-gui-console.md)。
3. **banner 与有状态工作：** [04](./04-targets-and-scanning.md) → [05](./05-modules-and-parameters.md) → [防火墙规则](../firewall.md)。
4. **长时间或自动化扫描：** [03](./03-cli-and-jobs.md) → 控制面 → [06](./06-results-and-files.md) → [MCP server](../mcp-server.md)。
5. **HTTP/3 与 QUIC：** [07](./07-protocols-and-http3.md) → `xtate --list-capabilities` → [quic-state](../quic-state.md)。
6. **出问题了：** [09](./09-troubleshooting.md) → [已知限制](../known-limitations.md)。

## 约定

- 命令在仓库根目录运行。Linux 用 `./bin/xtate`，Windows 用 `.\bin\xtate.exe`。已安装的二进制可以直接叫 `xtate`。
- 原始套接字扫描在 Linux 上需要 root，Windows 上需要管理员权限。示例在需要处写出 `sudo`。
- `-ip` 是 `--target-ip` 的短形式，`-p` 是 `--port` 的短形式，`-if` 选择网卡。选项区分大小写。
- 本手册中的结果等级为 `success`、`failed` 和 `info`，与输出契约一致。
- GUI、TUI 与 MCP 都是同一个本地控制面的客户端，因此在一个客户端里启动的 job 可以在另一个客户端中列出和取消。TUI 在 3.0 中已弃用；GUI 是受支持的交互界面。

## 准确性与范围

本手册对照构建出的二进制与测试套件检查。它不能替代 `--help`：手册与 `--help` 冲突时，以二进制为准。控制台行为由 `python tests/gui/test_gui.py` 覆盖，MCP 行为由 `python tests/mcp/test_mcp.py` 覆盖。

本手册不覆盖内嵌浏览器页的构建、打包，或历史 TUI 工作流；见[构建产物](../build-artifacts.md)与 [TUI](../tui.md)。

## 相关文档

- [文档索引](../README.md)
- [仓库 README](../../../README.zh-CN.md)
- [GUI 控制台](../gui.md)与 [MCP server](../mcp-server.md)
- [控制面](../control-plane.md)与 [job 模型](../job-model.md)
- [JSON 契约](../json-contracts.md)与[错误码](../error-codes.md)
- [故障排查](../troubleshooting.md)与[已知限制](../known-limitations.md)
