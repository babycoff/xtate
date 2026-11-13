# Xtate 3.0 路线图

**中文** · [English](../roadmap-3.0.md)

本文件是 Xtate 3.0 的工作计划，基线为已发布的 2.44.2。它不是日期承诺，
而是范围、优先级和验收条件。

## 产品定义

Xtate 3.0 是产品级发布，包含四条主线：

1. **扫描控制台 GUI**：面向使用者，选择目标、查看路由和网卡、设置参数、
   授权、启动、实时观察结果、停止或导出。它不是“任务列表加一个表单”。
2. **AI 原生操作**：外部 Agent 通过 MCP 和 Agent Skill 使用 Xtate；Xtate
   不内嵌大模型、API Key 或聊天服务。
3. **协议深度**：HTTP/1.1、HTTP/2 在 Windows 和 Linux 都支持；HTTP/3 与 QUIC
   传输在 Linux 且 ngtcp2/GnuTLS 可用时支持。Windows 保留能力探测并明确显示
   “不支持”，而不是假装存在。两种情况都要有文档、本地互操作测试，并在构建
   支持时出现在 GUI/MCP 模块目录中。
4. **真正的中英文手册**：结构化使用手册、自动生成的模块参考、内置帮助和
   CLI 帮助共用同一份元数据。

### TUI

TUI 不属于 3.0。现有 `--tui` 是 2.44.x 的功能，在 3.0 文档中标记 deprecated，
不再投入开发。代码可以保留到 GUI 覆盖相应操作为止，然后删除。GUI 是唯一正式
支持的交互界面。

### 3.0 不做的事

- 不内嵌 LLM、云账号、遥测或托管扫描服务。
- 不允许 GUI/MCP 执行任意 shell。
- 不允许无显式授权的扫描。
- 第一版 GUI 不强行暴露所有实验模块。
- 不做虚假协议声明：QUIC 传输响应不等于 HTTP/3 成功。

## 当前差距（2.44.2 基线）

| 领域 | 现状 | 3.0 目标 |
|---|---|---|
| GUI | 单页面任务列表，只代理少量 `job.*` | 扫描优先的工作台：网卡、模块、实时记录、结果、帮助 |
| GUI 数据 | 只有任务列表/状态/manifest/取消/启动 | 结构化网卡、模块元数据、预检、有界结果读取 |
| AI | MCP 只支持静态 targets 或 include_file；控制面要单独启动 | 一条命令 MCP、完整工具面、结果流、generate、Skill v2 |
| HTTP/1.1 | 已有 `http`/`http-state` | 审计请求/响应、chunked、TLS 组合并测试 |
| HTTP/2 | 已有 `h2`（TLS/ALPN）和 `h2c` | 审计 HPACK/帧/SETTINGS/GOAWAY，本地互操作 |
| HTTP/3 | `http3-state` 存在，但可选且依赖 ngtcp2/GnuTLS | Linux 发布构建覆盖 QPACK/static table 和互操作；Windows 明确显示不支持 |
| QUIC | `quic` 能力探测；`quic-state` 可选 | Linux 发布构建覆盖版本/Retry/握手；Windows 保留能力探测 |
| 文档 | 页面分散、模块数量易漂移、无统一手册 | 手册 + 自动参考 + 双语一致性门禁 |

当前 Windows 模块表显示 11 个 scan、59 个 probe；未找到 ngtcp2 时
`quic-state`、`http3-state` 不出现。Windows 目前没有可靠的 ngtcp2 构建路径，
因此 3.0 接受 HTTP/3 与 QUIC 传输为 **Linux-only**，Windows 明确报告不支持。
依赖状态必须在模块目录、GUI、MCP 和手册中可见，发布矩阵实际测试 Linux 传输
路径。

## 工作流 A — GUI 扫描控制台

### 信息架构

- **新建扫描**（默认页）：目标、扫描方式、Probe、端口、速率、超时、网卡、
  结果路径、模块高级参数、预检、授权、开始。
- **运行中**：进度、已发送/目标数、速率、耗时/预计剩余、实时记录、过滤、停止。
- **结果**：本次扫描记录、搜索/过滤、详情抽屉、导出。
- **网卡**：IPv4/IPv6、MAC、网关、链路类型、默认路由、状态、“用此网卡扫描”。
- **模块与帮助**：scan/probe/generate/output 目录、参数、示例、双语帮助、
  “带入新建扫描”。
- **会话**：当前控制面会话内的扫描；明确私有模式下退出即停止。
- **设置**：端点/token 状态、MCP 命令与配置复制、语言、主题、诊断。

主界面不使用 job 概念；job id 只出现在高级详情。

### 后端需要补的接口

- `iface.list`：结构化网卡，包含链路类型和默认路由。
- `iface.explain`：目标的路由/源地址/网关/链路类型预检。
- `module.list` / `module.describe`：表单和帮助所需的模块元数据。
- `scan.preflight`：一次校验目标、路由和扫描配置。
- `job.records`：按 offset/limit 有界读取结果记录，浏览器不能读任意文件。
- 状态或派生字段：packets/sec、ETA。

安全规则不变：只监听 `127.0.0.1`、Host 校验、每次运行 token、方法白名单、
显式 `authorized=true`、不执行 shell、请求体有界。

### 视觉方向

目标是专业仪器面板，不是运维后台：

- 石墨深色底 + 克制的薄荷/青色强调；可选浅色主题
- 左侧导航、顶部上下文栏、主工作区
- 8px 间距网格、清晰字号层级、IP/端口/协议用等宽字体
- 数据表密集但安静；骨架加载；行内可操作错误
- 键盘可达、焦点可见、支持减少动效
- 不依赖外部 CDN，不需要运行时资源目录

先做原型，再实现。第一版覆盖主流程 + 网卡 + 模块 + 结果，其余动作后续补。

### 验收

- 新用户不读 CLI 文档，60 秒内完成“选网卡 → 填目标 → 预检 → 授权 → 开始”。
- 发包前能看到路由、网卡、链路类型和参数错误。
- 扫描中能看到实时记录；停止有确认，终态明确。
- 主界面不需要理解 job id。
- Windows/Linux 核心流程通过浏览器测试和截图验证。

## 工作流 B — AI 与 MCP

- `xtate --mcp` 像 `--gui` 一样自动拉起私有控制面。
- MCP 工具补齐网卡、模块目录、预检、有界结果读取、状态、取消。
- 支持 generate/stream 输入，而不只是静态 targets/include_file。
- Agent Skill v2 覆盖与 GUI 等价的流程、安全规则和错误处理。
- 评测场景：Agent 必须在不读源码的情况下完成预检、授权、启动、监控、读结果。
- GUI 设置页可复制 MCP 命令和 Skill 安装路径。

## 工作流 C — 协议支持

定义支持矩阵并逐格测试：

| 协议 | Windows | Linux | 3.0 要求 |
|---|---|---|---|
| HTTP/1.1 | 支持 | 支持 | 方法/Header/Body、chunked 响应、匹配范围、TLS 组合 |
| HTTP/2 | 支持 | 支持 | `h2` over TLS 与 `h2c`、HPACK、SETTINGS、DATA、GOAWAY/RST |
| HTTP/3 | 3.0 不支持 | ngtcp2/GnuTLS 构建 | `http3-state` on `quic-state`、QPACK 静态表/Huffman、GET/POST、Header/Body |
| QUIC | 仅能力探测 | ngtcp2/GnuTLS 构建 | `quic` 能力探测 + `quic-state` 传输：Version Negotiation、Retry、Initial、Handshake |

在 Linux 上用 ngtcp2/GnuTLS 构建和测试 HTTP/3/QUIC 传输。Windows 必须明确显示
不支持，不能静默失败或声称传输存在。构建缺少依赖时，模块目录和 GUI 必须明确
说明。用 nghttp2、nghttp3、aioquic 或 quic-go 做本地互操作，再加少量真实端点
抽样。

## 工作流 D — 手册与帮助

建立 `docs/manual/`：

1. 安装与快速开始
2. GUI 使用手册（每页、每字段）
3. 目标、端口与网卡
4. 扫描模式
5. Probe 参考（HTTP/1、HTTP/2、HTTP/3、QUIC 独立章节）
6. 输出与结果
7. MCP、Agent Skill、自动化
8. 故障排查（fake-IP、TUN、防火墙、权限）
9. 安全与授权
10. 完整参数参考

模块参考从注册表生成；GUI 帮助、`--help`、手册共用元数据；中英文章节一致，
0 断链。

## 阶段

| 阶段 | 产出 | 退出条件 |
|---|---|---|
| P0 设计与基线 | 3.0 范围、GUI brief、静态原型、差距/API 清单 | 视觉方向确认 |
| P1 AI/MCP | 一条命令 MCP、工具、结果读取、Skill v2、评测基线 | Agent 不读源码完成安全扫描 |
| P2 GUI 后端 | 网卡/模块/预检/记录接口、安全测试 | API 契约稳定 |
| P3 GUI 控制台 | 新建扫描、运行中、结果、网卡、模块/帮助 | Windows/Linux 核心流程通过 |
| P4 协议 | HTTP/1/2 审计、Linux HTTP/3/QUIC 构建与互操作、Windows 能力报告 | 协议矩阵全绿 |
| P5 手册/帮助 | 双语手册、内置帮助、示例校验 | 0 断链、双语一致 |
| P6 加固/发布 | CI、ASan/fuzz、性能、安全、RC | 发布门禁全过 |

P1 与 P2 可并行；P5 尽早开始，与 P4/P6 一起收尾。

## 发布门禁

满足以下条件才发布 3.0.0：

- 无 P0/P1 缺陷，安全审计无 High；
- Windows + Linux 全量测试通过；
- GUI 核心流程有浏览器/e2e 覆盖；
- HTTP/1.1、HTTP/2 在 Windows 和 Linux 互操作测试通过；
- HTTP/3、QUIC 传输在 Linux 互操作测试通过，Windows 明确报告不支持；
- ASan/UBSan、fuzz、配置模糊测试无新增问题；
- 手册 0 断链，中英文章节一致；
- 所有模块在 CLI/GUI/MCP 中可见且有说明；
- 版本、tag、release notes、校验和、源码包齐全；
- 有 2.44.x → 3.0.0 迁移说明。

## 立即下一步

1. 在 3.0 文档中标记 TUI deprecated；等 GUI 覆盖相应操作后删除。
2. 评审静态 GUI 原型，确定视觉方向。
3. 记录 API 差距和协议构建差距为实施任务。
4. 实现扫描优先的 GUI 外壳和后端切片。
5. 先用截图做一次可用性评审，再扩展范围。
