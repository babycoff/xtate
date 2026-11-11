# Xtate 文档

[English](../README.md) · **中文**

本目录是 **Xtate v2.41.2** 的用户手册——一款面向互联网级测量的模块化全栈网络扫描器。

项目 [README](../../README.zh-CN.md) 是落地页。如果你想上手使用 Xtate，而不是只扫一眼功能列表，就从这里开始。

**发布说明：** [2.41.2](./release-notes/2.41.2.md)——JSON 契约、scan-request 运行时与错误处理。

## 从哪里开始

| 你的情况 | 建议阅读 |
|---|---|
| 刚接触 Xtate | [快速上手](./getting-started.md) |
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
| 错误码 | [错误码](./error-codes.md) |
| JSON 契约 | [JSON 契约](./json-contracts.md) |
| AI 集成设计 | [AI 集成设计](./ai-integration.md) |
| Linux 防火墙 | [Linux 防火墙前置条件](./firewall.md) |
| 想了解内部原理 | [架构](./architecture.md) → [ZBanner](./zbanner.md) / [HLTCP](./hltcp.md) |
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

本文档基于 v2.39.1 的代码树编写。如果你在更新的 commit 上发现内容有出入，请以二进制为准，也欢迎提 issue。

## 计划中

以下内容尚未编写：

- 常见测量场景的配方（HTTP banner、TLS 证书、IPv6、LAN 发现）
- 自动生成的 CLI 与各模块参考

可浏览的文档站点计划作为单独一步推进；目前本目录下的内容全部是纯 Markdown。
