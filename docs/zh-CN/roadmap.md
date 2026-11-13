# 路线图

**中文** · [English](../roadmap.md)

本页记录 Xtate 2.33.0 之后的计划。它不是日期承诺，而是优先级和验收条件；
已完成项也会保留，避免后续修改悄悄回退。

## 2.33.0 已完成

- 可选 `quic-state`：原始 UDP + ngtcp2/GnuTLS 的 QUIC 握手，输出证书/ALPN，并
  支持 state 子探测；HTTP/3 仍是后续应用探测。
- 可选 `http3-state`：`quic-state` 之上的 HTTP/3 请求，支持方法/header/body、
  Huffman QPACK 字符串、完整 static table 和结构化响应 header；dynamic QPACK
  仍刻意关闭并显式标记。

- QUIC 能力探测（`quic`）：合法 QUIC v1 Initial，识别 Version
  Negotiation/Retry/Initial/Handshake；本地 aioquic lab。
- 模块数量：59 个探测。
- 本机目标上的 Salesforce JARM 1.0 对比；修复 `jarm` TLS 1.3 扩展解析偏移。
- `jarm --first-probe N` 轮换；`jarm_slot` 保留标准编号，聚合与顺序无关。
- `tls-state` 的 SMTP/IMAP/POP3/FTP STARTTLS；升级后输出证书并可运行子探测。
- 结构化 X.509 细节 `--dump-cert-details`。
- 参数解析器回归套件、严格值解析、200 例 fuzz 和错误传播。
- 中英文帮助与文档扩展。

- 通用 `ProbeSlotPlan`：`ProbeSlot_Always`、`ProbeSlot_AfterFirstReply`。
- 移除旧的 `MultiMode`/`multi_num` 语义。
- TCP/UDP 独立 slot 执行。
- 内置 `slot-test`、`slot-test-udp` 运行期示例。
- JARM 逐 slot 输出与输出侧聚合。
- 离线 JARM/TCP/UDP lab。
- 四类模块开发文档。
- 可编译检查的 probe/state/output/generate 模板。

## 当前优先级调整

当前优先级：

1. **QUIC/HTTP3 下一步**——能力探测和可选的 `quic-state` 握手传输已完成；
   下一层是 HTTP/3/QPACK 与 DoQ 应用探测；见
   [QUIC state](./quic-state.md)。
2. **Xtate 原生 YAML 模板**——先做只读 matcher/schema，不复制 Nuclei。
3. **协议覆盖扩展**——按[协议覆盖计划](./protocol-coverage.md)的 zgrab2
   矩阵，先做 Batch A。
4. **流量随机化研究**——opt-in、固定 seed、只在 lab；与默认扫描器分离。

下面的旧计划仍然有效，但除非有具体测量需求，优先级较低。

## P1 — 模块示例（已完成）

- [`examples/modules/`](../../examples/modules/) 每种模块类型一个编译检查模板。
- `tests/module-examples/test.sh` 已接入 Linux CI。
- 运行期 slot 示例仍是 `slot-test` / `slot-test-udp`。

## 参数解析覆盖（2.31.0/2.33.0 已完成）

- `tests/config/test.sh` 覆盖 flag、参数形式、未知/缺失、长名称、裸 `--`、
  位置 token 和嵌套 `-probe-arg`。
- 严格 bool/int/size/time 解析，checked API 和 setter 错误传播。
- `tests/config/fuzz.py` 在 CI 跑 200 个确定性用例。
- 交互式 malformed recovery 有覆盖。

HTTP/1 探针按当前方向冻结在结构化响应解析阶段。

## P2 — JARM 正确性

JARM fuzzy hash 已改为 Salesforce JARM 1.0 语义：

- cipher → JARM 有序表索引（两个十六进制字符）；
- TLS 版本 → 一个版本 nibble（`a`–`f`）；
- ALPN + extensions → SHA-256 前 32 个十六进制字符。

测试已加入精确 62 字符参考向量。剩余工作：

1. 已完成：本机目标上与 Salesforce 官方 JARM 对比，并修复扩展解析偏移。
2. 增加扫描器级 lab 断言：完整、alert/非 TLS、缺失 slot。
3. 继续明确 `targets_with_parts` 语义：0 part 目标无法从 JARM 行反推；不要给
   扫描器加 group 状态。
4. `jarm_sha256` 必须继续注明是原始 parts 的辅助哈希，不是标准 JARM 值。
5. 如果 retry 不够用，使用外部目标清单，不要假装 0 part 目标已经扫描过。

验收：

- 精确参考向量通过；
- 官方 JARM 与 Xtate 在本地目标上一致；
- complete/incomplete/retry fixture 通过；
- 文档说明 `targets_with_parts` 的限制。

## P2 — 协议探针

状态：JARM 哈希/参考向量的工作、SSH banner/KEX、cleartext `h2c` 与 `h2` 状态探针（通过 HLTCP 的 TLS/ALPN h2）均已实现。`h2` 只有最小的静态/字面量 HPACK 请求以及 frame/HEADERS/DATA 解析；Huffman/动态 HPACK、完整流管理、STARTTLS、HTTP/3/QUIC 与 TLS 变体指纹仍待做。TLS 证书/subject 细节已存在于 `tls-state`；HTTP 状态行为已存在于 `http-state`。

在不引入扫描器侧每目标状态的前提下增加协议专用细节探针。每个探针在合适处复用单 slot 或 `ProbeSlot_Always`。

计划顺序：

1. TLS 证书/细节探针已在 `tls-state` 中通过 `--dump-cert-details` 实现（subject、issuer、SAN、有效期、密钥类型/位数、签名算法、ALPN、版本/密码套件）。
2. SSH banner 探针已实现（`ssh`），包括合并的 KEX/host-key 算法列表。完整 KEX 包交换仍是后续工作。
3. HTTP/1 工作在结构化响应解析器一轮之后冻结；不再计划进一步的 HTTP 重写。
4. SMTP、IMAP、POP3 与 FTP 的 STARTTLS 适配器已在 `tls-state --starttls` 中实现，包括升级后的证书细节。
5. HTTP/2 保持最小（`h2`）：静态/字面量 HPACK，无 Huffman/动态表，无完整流管理。HTTP/3/QUIC 仍是独立研究。
6. TLS 变体指纹研究：ClientHello 变体、扩展顺序、GREASE、ALPN 顺序。
7. QUIC 探针与 HTTP/3 探索：独立的 UDP/QUIC 传输路径、ALPN `h3`、QUIC Initial/Handshake 包与可选 QUIC 库评估。未完成 QUIC 握手时，不要把 UDP 数据报称为 HTTP/3 探针。

约束：

- 每个 slot 一条 flow；扫描器不保存 target group；
- 载荷与输出字段有上限；
- 需要真实服务的路径进 `tests/lab/`，保持确定性；
- 可选依赖仍然保持可选。

P3/P4 可行性见[P3/P4 可行性](./feasibility.md)。

## HTTP 探针审计/重写（冻结）

第一轮结构化响应解析已实现。按当前方向 HTTP/1 工作到此为止；共享请求构造器
抽取和跨段 chunked 状态暂缓。详见 [HTTP 探针审计](./http-probes-audit.md)。

## P3 — 扫描控制

- 基于端口/banner/TLS 证据的有限目标相关探针选择。
- 未知网络的自适应包速率，明确 min/max 和可复现反馈。
- 跨层指纹：IP/TCP/TLS/应用层组合。
- stateless → stateful 两阶段 handoff。

## P3 — 模板与流量

- Xtate 原生 YAML 模板，借鉴 Nuclei 但不兼容。
- 扫描流量指纹随机化与研究开关。

## 暂缓

- UDP `ProbeSlot_AfterFirstReply`：当前 UDP 响应归属不够精确；UDP 使用
  `ProbeSlot_Always`。
- HLTCP slot：见[模块开发](./module-development.md#hltcp-与-slot-plan计划中)
  的计划。先做连接内 `AfterFirstReply`，再做并行独立连接。

## 建议后续顺序

1. YAML 模板 schema 与只读 matcher（10A）。
2. 扩展 HTTP/3：dynamic QPACK 与 DoQ；保持传输扫描器与应用探测分离。
3. 协议覆盖 Batch A：Redis、Memcached、MQTT、Telnet、SOCKS5、NTP。
4. 流量随机化研究：opt-in、固定 seed、只在 lab（10B）。
5. JARM 失败模式与外部 retry manifest。
6. SSH 深度 KEX/host-key、完整 HTTP/2 HPACK/流管理。
7. HLTCP slot：连接内 AfterFirstReply，再考虑并行 flow。
8. TLS 变体指纹。
9. P3 外部两阶段目标选择、opt-in 自适应速率。
10. stateless -> stateful handoff。

## ZBanner 审计与简化

ZBanner 是最大、最复杂的无状态链路。审计和验收条件见
[ZBanner 审计](./zbanner-audit.md)。优先级：当前协议工作之后、ZBanner 新功能之前。

- [x] 给 `AfterFirstReply` 加 one-shot 保护；
- [x] 合并 all-banner limit/floor/RST/truncated 策略；
- [x] 在输出/文档中澄清 `banner idx` 与 `banner seqno`；
- [x] 收窄通用 `AfterFirstReply` 响应语义为 banner/数据；
- [x] 补 payload 长度不一致回归覆盖；
- [x] 在不引入 per-target 状态的前提下抽离响应分类器；
- [x] 补 all-banner 的 pcap/lab 边界覆盖。

## Windows quic-state TODO

- [ ] 为 Windows MSVC 增加 ngtcp2 OpenSSL backend。
- [ ] CMake 识别 `vcpkg install ngtcp2[openssl]:x64-windows`，不再假设 pkg-config。
- [ ] 将 `quic-state` 的证书/TLS 元数据和 `http3-state` 移植到 OpenSSL。
- [ ] 在声称支持前补齐 MSVC 构建和本地 HTTP/3 lab。
- [ ] OpenSSL 路径验证前保持 Linux 的 GnuTLS backend。

## 发布策略

功能变化使用中版本（`2.29.x` → `2.33.0`），修复使用补丁版本。标签推送、
GitHub Release 和构建/测试证据齐全才算发布完成。

## 输入/输出模块审查

在下一批协议之前，计划对所有输入（目标生成/pcap）和输出模块做一次专项审查：

- 文件/流/BSON/NDJSON/pcap 输入的边界和溢出；
- text/NDJSON/CSV/BSON/Mongo 输出的错误处理和部分写入；
- 输出转义和 JSON 合法性；
- 路径/权限和清理行为；
- 畸形输入和失败路径的单元测试；
- 现有 pcap 和目标文件矩阵回归。

这是代码审查工作流，不是新功能；应单独产出审计报告和修复。

## AI 集成（MCP / Agent / Skill）

目标：让 AI 能安全地操作 Xtate，而不是把无结构 shell 交给模型。
CLI 仍是事实来源；控制面拥有 job，MCP 是类型化客户端。

2.42.0 已交付：

1. scan-request、模块元数据、结果和错误码的 JSON schema。
2. 托管扫描 job：超时、stall 检测、心跳和取消。
3. 本地控制面：Linux Unix socket 或 Windows Named Pipe，使用
   `XTATE_CONTROL_TOKEN`。
4. MCP stdio server：只读工具和受控 `start_scan`：
   `list_modules`、`describe_probe`、`explain_target`、`check`、
   `validate_config`、`start_scan`、`job_list`、`job_status`、
   `job_result_manifest`、`job_cancel`。
5. 路由感知规划，并拒绝跨多个路由的目标集。
6. 安全边界：不执行 shell、只接受已注册模块名、目标/速率上限、显式
   `authorized:true`、审计日志、控制面仅本地。

2.42.1 已交付：

- `skills/xtate/` 的 Agent Skill，含中英文文档和与运行时对齐的 `dry_run` 契约；
- 全树审计修复：内存安全、Windows UTF-8 路径、控制面分帧/校验和结果存储 JSON
  转义。

2.43.0 已交付：

- 全屏 TUI 控制平面客户端（`xtate --tui`），支持任务列表、启动、取消和 manifest
  详情，并附中英文文档。

2.44.0 已交付：

- 仅监听环回的浏览器 GUI（`xtate --gui`），作为又一个控制平面客户端：任务面板、
  启动向导、取消、状态与结果 manifest，并带每次运行的会话 token、Host 校验和
  job 方法白名单。

2.44.1 已交付：

- 本机 TUI/GUI 一条命令启动，私有控制面只在该界面生命周期内存在；
  `--control-connect` 仍可连接已有控制面。

2.44.2 已交付：

- 修正 `PCAP_DLT_RAW`（`DLT_RAW` 12），TUN/VPN 网卡（包括 fake-IP 隧道）
  不再被误判为未知链路类型。
- `--explain-target` 显示网卡链路类型并标记不支持的类型；扫描启动时以可操作
  的提示拒绝不支持的链路类型，多默认网卡错误也会提示
  `--explain-target`/`--list-if`。
- 扫描启动横幅和元信息文件显示实际 `Rate:`（默认值或 `--rate`）。

仍待完成：

- agent 评测套件与打包；
- MCP generate/流式输入（目前只有静态 `targets` 和 `include_file`）；
- 扫描期间的单 job 磁盘配额强制（目前只在完成后报告）。

阶段：

```text
2.42.0  JSON 契约 + job + 控制面 + MCP server（已完成）
2.42.1  Agent Skill + 全树审计加固（已完成）
2.43.0  TUI 控制平面任务面板（已完成，已发布）
2.44.0  控制平面浏览器 GUI（已完成，已发布）
2.44.1  TUI/GUI 一条命令启动私有控制面（已完成，已发布）
2.44.2  RAW/TUN 链路预检 + 启动速率显示（已完成）
下一步  评测套件与打包
以后    MCP generate/流式输入
```

见 [AI 集成设计](./ai-integration.md) 和 [MCP server](./mcp-server.md)。

## 互联网规模 job 数据面

MCP/TUI/GUI 使用的结果路径状态：

- [x] 64 位结果大小与游标（`uint64_t`、`fseeko`/`_fseeki64`）；
- [x] 控制响应有界；客户端读 manifest 和分片，而不是向控制面请求整个结果；
- [x] 结果分片 NDJSON、可选 zstd、可选索引；
- [x] 完成 job 的 TTL 和最大保留数；
- [x] 心跳与 stall 检测；
- [x] 控制面/数据面分离，供 MCP/TUI/GUI 使用；
- [ ] 扫描期间强制单 job 磁盘配额（目前完成后检查并告警）。

见 [控制面](./control-plane.md)。
