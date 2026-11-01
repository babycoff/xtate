# Xtate 文档

[English](../README.md) · **中文**

本目录是 **Xtate v2.20.3** 的用户手册——一款面向互联网级测量的模块化全栈网络扫描器。

项目 [README](../../README.zh-CN.md) 是落地页。如果你想上手使用 Xtate，而不是只扫一眼功能列表，就从这里开始。

## 从哪里开始

| 你的情况 | 建议阅读 |
|---|---|
| 刚接触 Xtate | [快速上手](./getting-started.md) |
| 正在规划一次扫描 | [目标与端口](./targets-and-ports.md) → [扫描模式](./scanning-modes.md) |
| 要把结果接入流水线 | [输出](./output.md) → [聚合](./aggregation.md) |
| 在挑选模块 | [模块](./modules.md) |
| 想了解内部原理 | [架构](./architecture.md) → [ZBanner](./zbanner.md) / [HLTCP](./hltcp.md) |
| 卡住了 | [故障排查](./troubleshooting.md) → [已知限制](./known-limitations.md) |

## 目录

### 使用 Xtate

- [快速上手](./getting-started.md)——构建、权限、首次扫描、防火墙
- [目标与端口](./targets-and-ports.md)——IPv4/IPv6 输入、文件、ASN、排除、分片
- [扫描模式](./scanning-modes.md)——无状态与有状态、扫描/探测配对、常用配方
- [输出](./output.md)——结果级别、text/CSV/NDJSON/BSON/MongoDB、转义
- [聚合](./aggregation.md)——结束后 NDJSON 聚合、schema 与规模
- [模块](./modules.md)——四种模块类型以及 Xtate 自带的模块

### 工作原理

- [架构](./architecture.md)——线程、队列、扫描流水线
- [ZBanner](./zbanner.md)——无状态 TCP 响应与 banner 抓取
- [HLTCP](./hltcp.md)——混合状态 TCP 协议栈、TLS 与嵌套探测

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

本文档基于 v2.20.3 的代码树编写。如果你在更新的 commit 上发现内容有出入，请以二进制为准，也欢迎提 issue。

## 计划中

以下内容尚未编写：

- 常见测量场景的配方（HTTP banner、TLS 证书、IPv6、LAN 发现）
- 模块编写指南（用 C 编写扫描/探测/输出/生成模块）
- 自动生成的 CLI 与各模块参考

可浏览的文档站点计划作为单独一步推进；目前本目录下的内容全部是纯 Markdown。
