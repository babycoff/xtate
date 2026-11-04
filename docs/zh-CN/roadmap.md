# 路线图

**中文** · [English](../roadmap.md)

本页记录 Xtate 2.29.0 之后的计划。它不是日期承诺，而是优先级和验收条件；
已完成项也会保留，避免后续修改悄悄回退。

## 2.29.0 已完成

- 通用 `ProbeSlotPlan`：`ProbeSlot_Always`、`ProbeSlot_AfterFirstReply`。
- 移除旧的 `MultiMode`/`multi_num` 语义。
- TCP/UDP 独立 slot 执行。
- 内置 `slot-test`、`slot-test-udp` 运行期示例。
- JARM 逐 slot 输出与输出侧聚合。
- 离线 JARM/TCP/UDP lab。
- 四类模块开发文档。
- 可编译检查的 probe/state/output/generate 模板。

## P1 — 模块示例（已完成）

- [`examples/modules/`](../../examples/modules/) 每种模块类型一个编译检查模板。
- `tests/module-examples/test.sh` 已接入 Linux CI。
- 运行期 slot 示例仍是 `slot-test` / `slot-test-udp`。

## 参数解析覆盖（计划中）

CLI/参数解析器还没有专门的回归测试套件。在依赖更多嵌套/subprobe 参数之前应补齐：

- `ConfParam` 的 flag/argument/未知选项/重复选项；
- 引号、空格、反斜杠和嵌套 `-subprobe-arg`；
- 整数/范围/十六进制/size 边界和非法值；
- `-scan-arg`、`-probe-arg`、`-output-arg`、`-gen-arg` 嵌套；
- 交互式 `set` 和恢复配置文件；
- 非法输入的非零退出码和 stderr。

验收：`tests/config/` 在 Linux CI 运行，覆盖解析器和四类注册表各一个代表模块，
且不依赖网络。

## P2 — JARM 正确性

JARM fuzzy hash 已改为 Salesforce JARM 1.0 语义：

- cipher → JARM 有序表索引（两个十六进制字符）；
- TLS 版本 → 一个版本 nibble（`a`–`f`）；
- ALPN + extensions → SHA-256 前 32 个十六进制字符。

测试已加入精确 62 字符参考向量。剩余工作：

1. 在同一个本地 TLS 目标上，把 Xtate 输出与官方 JARM 实现对比，而不只测哈希。
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

状态：JARM 哈希/参考向量、SSH banner/KEX、cleartext `h2c` 和
`h2` state 探针（HLTCP + TLS ALPN h2）已实现。`h2` 支持最小静态/literal
HPACK 请求以及帧/HEADERS/DATA 解析；Huffman/动态 HPACK、完整流管理、
STARTTLS、HTTP/3/QUIC 和 TLS 变体指纹仍未实现。TLS 证书/subject 细节已由
`tls-state` 提供，HTTP state 行为已由 `http-state` 提供。

增加协议细节探针，同时保持扫描器无 per-target 状态。能单 slot 就单 slot，
需要并行变体时使用 `ProbeSlot_Always`。

计划顺序：

1. TLS 证书与细节：subject、issuer、SAN、有效期、key type、签名算法、
   ALPN、协商版本/cipher。
2. SSH banner 探针已实现（`ssh`），包括合并报文中的 KEX/host-key 算法列表；
   完整 KEX 包交换仍是后续工作。
3. HTTP state 探针增强：状态行、header、重定向目标、body 上限。
4. STARTTLS：SMTP、IMAP、POP3、FTP；升级后组合 TLS 细节。
5. cleartext h2c 能力/framing 探针已实现（`h2c`）；TLS 上的 HTTP/2、完整 HTTP/2 客户端和
   HTTP/3/QUIC 仍是后续工作。
6. TLS 变体指纹研究：ClientHello 变体、扩展顺序、GREASE、ALPN 顺序。
7. QUIC 探针与 HTTP/3 探索：独立的 UDP/QUIC 传输路径、ALPN `h3`、QUIC
   Initial/Handshake 报文，以及可选 QUIC 库评估。没有 QUIC 握手就不能把
   UDP 数据报叫作 HTTP/3 探针。

约束：

- 每个 slot 一条 flow；扫描器不保存 target group；
- 载荷与输出字段有上限；
- 需要真实服务的路径进 `tests/lab/`，保持确定性；
- 可选依赖仍然保持可选。

P3/P4 可行性见[P3/P4 可行性](./feasibility.md)。

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

## 发布策略

功能变化使用中版本（`2.29.x` → `2.30.0`），修复使用补丁版本。标签推送、
GitHub Release 和构建/测试证据齐全才算发布完成。
