# 从 2.44.x 升级到 3.0

[English](../migration-3.0.md) · **中文**

Xtate 3.0 是面向使用体验的候选发布线：扫描优先的 GUI、单命令 MCP 服务、双语文档、
显式协议能力报告和统一的结果目录。报文引擎和四类模块没有改变，但若干接口和默认
行为发生变化。升级前请先阅读本页，尤其是封装了 Xtate 的自动化脚本。

> 3.0.0 目前是 RC。请先试用，再替换稳定环境。最近一个稳定版本是 2.44.2。

## 快速升级清单

1. 替换二进制和 DLL；保留旧二进制，直到新版本通过 `--selftest` 和一次真实扫描。
2. 如果使用 MCP 自动化，把 `start_scan` 改成扁平请求，并运行契约测试。
3. 如果解析结果路径，不要假设文件出现在当前工作目录；使用 `xtate-state`、
   `XTATE_STATE_DIR` 或显式 `result_path`。
4. 如果使用 `--tui`，请迁移到 `--gui`；TUI 在 3.0 中已弃用。
5. 重新确认 HTTP/3、QUIC 预期：仅 Linux，且构建时必须找到 ngtcp2/GnuTLS。
6. 阅读 [3.0 发布说明](./release-notes/3.0.0-rc.7.md) 和
   [已知限制](./known-limitations.md)。

## 破坏性/行为变化

### MCP `start_scan` 改为扁平字段

3.0 中 JSON-RPC 的 `params.arguments` 对象本身就是扫描请求，不要再包一层
`arguments`。

```json
{"name":"start_scan","arguments":{
  "scan":"tcp-syn",
  "targets":["203.0.113.0/24"],
  "ports":[80,443],
  "rate":1000,
  "timeout_sec":300,
  "authorized":true
}}
```

旧的嵌套形式会返回 `unknown field: arguments`。顶层未知字段也会被拒绝，而不是
静默忽略。参见 [MCP 服务](./mcp-server.md)。

### `preflight`、`check` 与能力发现

- `preflight` 的 `targets`、`ports` 现在既接受 JSON 数组，也兼容旧的逗号分隔字符串；
  它仍然不发送数据包。
- `check` 现在真正执行路由/链路类型检查。它报告链路能力；Linux 防火墙规则是独立
  资源，不由 `check` 返回。
- 使用 `capabilities` 工具或 `--list-capabilities` 查询 HTTP/3、QUIC、zstd、
  raw socket 和模块可用性，不要根据构建名猜。
- MCP 单行参数上限仍是 8 KiB；大目标集请用 `include_file`。超限会明确返回
  `request too large`。

### 结果不再写到当前目录

2.44.x 可能在工作目录生成 `xtate-job-<epoch>.ndjson`。3.0 默认使用统一状态目录：

| 平台 | 默认状态根目录 |
|---|---|
| Windows | `<xtate.exe 所在目录>\xtate-state` |
| Linux | `${XDG_STATE_HOME:-$HOME/.local/state}/xtate` |
| 覆盖 | `XTATE_STATE_DIR=/path` |

结果位于 `runs/<YYYYMMDD-HHMMSS>-<seq>/scan.ndjson`，同目录有
`scan.ndjson.log`；请求和心跳文件是临时的。GUI 显示运行时间，不再只显示 job id。
需要自定义布局时，通过 CLI 输出参数或 MCP/API 的 `result_path` 指定。

### TUI 已弃用

`xtate --tui` 在 3.0 中仍保留一个过渡窗口，但不再投入新功能，也不属于 3.0 的
正式界面。请使用 `xtate --gui` 或 MCP。需要旧控制平面契约的客户端仍可启动
控制平面并用 `--control-connect` 连接。

### GUI 不再自动打开浏览器

`xtate --gui` 会启动私有控制平面，打印 URL 和会话 token 后等待。它不会启动
Explorer、Edge 或 `xdg-open`。`--gui-no-open` 仍是兼容性 no-op。请手动打开打印的
本机地址。Docker 中需设置 `XTATE_GUI_ALLOW_REMOTE=1` 并映射端口，参见
[Docker 构建](./docker-build.md)。

### 模块名称与参数编辑

GUI 使用 Xtate 自己的分类：**扫描模块**、**探针模块**、**输出模块**、**生成模块**。
模块可展开查看完整说明和参数表。GUI 只暴露 23 个可与扫描字段安全组合的全局参数
（`global_args`）；输出、结果、job 等字段由控制平面固定。其他全局参数请走 CLI 或
MCP。

### HTTP/3 与 QUIC 由能力决定

带 ngtcp2/GnuTLS 的 Linux 完整构建报告 `http3:true`、`quic_transport:true`，并包含
`http3-state`/`quic-state`。Windows 构建两者均为 false 并给出原因。这是 3.0 的明确
限制，不是缺少 DLL 的告警。

### zstd 是可选依赖

未启用 zstd 时结果不压缩，`capabilities.zstd` 为 `false`。Ubuntu 24.04 Docker 镜像
默认启用。参见 [Docker 构建](./docker-build.md) 和
[Windows 依赖](./windows-dependencies.md)。

## 兼容性对照

| 接口 | 2.44.x | 3.0 |
|---|---|---|
| CLI 扫描参数 | 不变 | 不变 |
| MCP `start_scan` | 嵌套 `arguments` | 扁平请求 |
| MCP `check` | 与 explain 相同 | 真正执行 `--check` |
| MCP 未知字段 | 常被忽略 | 拒绝 |
| MCP `preflight` targets | 字符串 | 数组或字符串 |
| 结果位置 | 常在 cwd | 状态目录 / `runs/<ts>` |
| GUI | job 列表 | 扫描优先控制台 |
| TUI | 支持 | 弃用 |
| GUI 浏览器 | 自动打开 | 不自动打开 |
| HTTP/3、QUIC | 取决于构建 | 显式能力；官方构建仅 Linux |

## 升级后的验证

```bash
xtate --version
xtate --selftest
xtate --list-capabilities
xtate --explain-target=192.0.2.10 --check
```

MCP：

```bash
python3 tests/mcp/test_mcp_contract.py
python3 tests/skill/test_skill_contract.py
```

然后执行一次已授权扫描，确认：

- job 到达 `completed`；
- result manifest 完整；
- MCP `job.records` 或 GUI `/api/results` 能返回记录；
- 结果文件位于预期的状态目录。

## 回滚

在试用扫描通过前保留旧二进制和 `bin/` 下的 DLL。状态目录是新增的；删除它会删除
本地运行历史。要回到 2.44.x，恢复旧二进制，并从自动化中去掉仅为 3.0 添加的
`XTATE_STATE_DIR`。

## 相关文档

- [3.0 手册](./manual/README.md)
- [MCP 服务](./mcp-server.md)
- [GUI 控制台](./gui.md)
- [控制平面](./control-plane.md)
- [Docker 构建](./docker-build.md)
- [已知限制](./known-limitations.md)
