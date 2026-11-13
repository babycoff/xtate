# Xtate 文档

[English](../README.md) · **中文**

本目录是 **Xtate v3.0.0-rc.7** 的用户手册——一款面向互联网级测量的模块化全栈网络扫描器。

项目 [README](../../README.zh-CN.md) 是落地页。如果你想上手使用 Xtate，而不是只扫一眼功能列表，就从这里开始。

**发布说明：** [3.0.0-rc.7](./release-notes/3.0.0-rc.7.md)——发布工程（CI 集成、带校验和的 Windows/Linux 资产、Docker 溯源）、版本一致性检查、帮助换行与文档修复、GUI 会话 token 加固，以及 2.44.x → 3.0 迁移指南。这是供实际试用的发布候选版本，不是最终 3.0.0。

## 从哪里开始

| 你的情况 | 建议阅读 |
|---|---|
| 刚接触 Xtate | [3.0 手册](./manual/README.md) → [快速上手](./getting-started.md) |
| 从 2.44.x 升级 | [迁移指南](./migration-3.0.md) |
| 正在规划一次扫描 | [目标与端口](./targets-and-ports.md) → [扫描模式](./scanning-modes.md) |
| 要把结果接入流水线 | [输出](./output.md) → [聚合](./aggregation.md) |
| 在挑选模块 | [模块](./modules.md) |
| 编写模块 | [模块开发](./module-development.md) |
| 计划中的工作 | [路线图](./roadmap.md) → [P3/P4 可行性](./feasibility.md) |
| HTTP 探针质量 | [HTTP 探针审计](./http-probes-audit.md) |
| 参数解析测试 | [参数解析器计划](./parser-test-plan.md) |
| 协议扩展 | [协议覆盖计划](./protocol-coverage.md) |
| DNS over HTTPS | [DNS over HTTPS](./dns-over-https.md) |
| DNS over TLS | [DNS over TLS](./dns-over-tls.md) |
| 输入/输出审查 | [输入/输出审查](./input-output-audit.md) |
| Job 模型 | [Job 模型](./job-model.md) |
| 自动化扫描 / AI 客户端 | [Agent Skill](./agent-skill.md) → [MCP server](./mcp-server.md) → [控制面](./control-plane.md) |
| 大目标文件或流式输入 | [输入模块](./input-modules.md) |
| 错误码 | [错误码](./error-codes.md) |
| JSON 契约 | [JSON 契约](./json-contracts.md) |
| AI 集成设计 | [AI 集成设计](./ai-integration.md) |
| Linux 防火墙 | [Linux 防火墙前置条件](./firewall.md) |
| 想了解内部原理 | [架构](./architecture.md) → [ZBanner](./zbanner.md) / [HLTCP](./hltcp.md) / [TLS 组合](./tls-composition.md) |
| 卡住了 | [故障排查](./troubleshooting.md) → [已知限制](./known-limitations.md) |
| 中文帮助 / 本地化 | [帮助 i18n](./help-i18n.md) |
| Windows 第一次尝试 | [Windows 快速上手](./windows-quickstart.md) |
| Windows 可选依赖 | [Windows 依赖](./windows-dependencies.md) |
| 构建产物命名 | [构建产物](./build-artifacts.md) |
| 交互式模式 | [交互式模式](./interactive-mode.md) |
| 平台与构建兼容性 | [平台支持](./platform-support.md) |
| 测试与兼容性规范 | [测试规范](./testing.md) |
| 插件协议（Go sidecar） | [插件协议](./plugin-protocol.md) |

## 目录

### 使用 Xtate

- [快速上手](./getting-started.md)——构建、权限、首次扫描、防火墙
- [目标与端口](./targets-and-ports.md)——IPv4/IPv6 输入、文件、ASN、排除、分片
- [扫描模式](./scanning-modes.md)——无状态与有状态、扫描/探测配对、常用配方
- [输出](./output.md)——结果级别、text/CSV/NDJSON/BSON/MongoDB、转义
- [聚合](./aggregation.md)——结束后 NDJSON 聚合、schema 与规模
- [模块](./modules.md)——四种模块类型以及 Xtate 自带的模块
- [模块开发](./module-development.md)——C 接口、注册和 ProbeSlotPlan 示例
- [路线图](./roadmap.md)——已完成工作与 P2/P3 计划
- [HTTP 探针审计](./http-probes-audit.md)——现状问题与重写计划
- [参数解析器计划](./parser-test-plan.md)——覆盖范围与测试框架
- [协议覆盖计划](./protocol-coverage.md)——zgrab2 参考协议矩阵与批次
- [P3/P4 可行性](./feasibility.md)——目标选择、自适应速率、模板与流量随机化
- [中文帮助与 i18n](./help-i18n.md)——`--lang`、catalog 回退与 UTF-8 帮助排版
- [Windows 快速上手](./windows-quickstart.md)——新手安装、Npcap、构建、首次扫描与排查
- [Windows 可选依赖](./windows-dependencies.md)——PCRE2/LibXml2/bson/mongoc 与 MinGW 注意事项
- [构建产物](./build-artifacts.md)——别名与按工具链命名、Debug 名称与 DLL
- [Ubuntu 24.04 Docker 构建](./docker-build.md)——全功能镜像、中国大陆镜像源与宿主机 GUI 访问
- [交互式模式](./interactive-mode.md)——命令、TTY/脚本模式、历史与补全
- [平台支持](./platform-support.md)——旧 CMake/发行版基线、Ninja 与 musl 构建
- [测试规范](./testing.md)——Tier 0/1/2 检查、矩阵与证据规则
- [插件协议](./plugin-protocol.md)——Go sidecar 边界、结果 envelope 与非目标

### 自动化与集成

- [3.0 手册](./manual/README.md)——按任务组织的安装、GUI、CLI、模块、结果、协议与故障排查
- [迁移到 3.0](./migration-3.0.md)——2.44.x 到 3.0 的破坏性变化、结果路径、MCP 形状与回滚
- [MCP server](./mcp-server.md)——stdio 工具、resource、prompt、路由规划与限制
- [GUI 控制台](./gui.md)——扫描优先的环回控制台，含预检、实时视图、网卡与模块
- [TUI 任务面板](./tui.md)——旧版全屏控制平面客户端；3.0 中已弃用
- [控制面](./control-plane.md)——MCP/TUI/GUI 共用的本地 JSON-lines API
- [Job 模型](./job-model.md)——托管 job、超时、心跳、取消与结果
- [输入模块](./input-modules.md)——静态目标与 generate 流、错误策略
- [Agent Skill](./agent-skill.md)——供外部 agent 通过 MCP 使用的可安装操作手册
- [JSON 契约](./json-contracts.md)——scan-request、模块元数据与错误 schema
- [AI 集成设计](./ai-integration.md)——边界、安全要求与剩余工作

### 工作原理

- [架构](./architecture.md)——线程、队列、扫描流水线
- [ZBanner](./zbanner.md)——无状态 TCP 响应与 banner 抓取
- [HLTCP](./hltcp.md)——混合状态 TCP 协议栈、TLS 与嵌套探测
- [QUIC state](./quic-state.md)——可选的 ngtcp2/GnuTLS QUIC 握手扫描器与子探测
- [HTTP 响应匹配](./matching.md)——HTTP/1、h2、http3 的 keyword/regex 与 header/body/all 范围
- [ZBanner 审计](./zbanner-audit.md)——状态机问题、边界与重构计划

### 出问题时

- [故障排查](./troubleshooting.md)——没有回应、内核 RST、pcap/Npcap、输出异常
- [已知限制](./known-limitations.md)——Xtate 刻意不做的事（现阶段）

## 关于准确性

Xtate 的命令行帮助是 flag 的权威来源：

```bash
xtate --help
xtate --help-scan <module>
xtate --help-probe <module>
```

本文档基于 v3.0.0-rc.7 的代码树编写。如果你在更新的 commit 上发现内容有出入，请以二进制为准，也欢迎提 issue。

## 生成参考

模块与参数的权威参考直接来自二进制：

```bash
xtate --list-modules-json
xtate --help-scan <name>
xtate --help-probe <name>
xtate --help-output <name>
xtate --help-generate <name>
```

可浏览的文档站点计划作为单独一步推进；目前本目录下的内容全部是纯 Markdown。
