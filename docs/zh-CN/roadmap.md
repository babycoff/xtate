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
- 模块数量：27 个探测。
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

已实现：JARM 官方对比/first-probe、SSH banner/KEXINIT、cleartext `h2c`、
TLS/ALPN h2 `h2`、TLS 证书细节、SMTP/IMAP/POP3/FTP STARTTLS。

仍待做：

1. SSH 实际 KEX 包交换、host-key 指纹和协商结果。
2. 完整 HTTP/2：HPACK Huffman/动态表、SETTINGS ACK、流/窗口和更强的 ALPN 校验。
3. TLS 变体指纹：ClientHello 变体、扩展顺序、GREASE、ALPN 顺序。
4. QUIC/HTTP3 独立传输研究，不把 UDP 数据报当 HTTP/3。
5. JARM 失败模式：alert/非 TLS/缺失 slot 的 scanner-level lab。

HTTP/1 探针按当前方向冻结，不再继续重写。

约束：

- 每个 slot 一条 flow；扫描器不保存 target group；
- 载荷与输出字段有上限；
- 需要真实服务的路径进 `tests/lab/`，保持确定性；
- 可选依赖仍然保持可选。

P3/P4 可行性见[P3/P4 可行性](./feasibility.md)。

## HTTP 探针审计/重写（冻结）

第一轮结构化响应解析已实现。按当前方向 HTTP/1 工作到此为止；共享请求构造器
抽取和跨段 chunked 状态暂缓。详见 [HTTP 探针审计](./http-probes-audit.md)。
`h2c`/`h2` 保持独立。

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

## Windows quic-state TODO

- [ ] 为 Windows MSVC 增加 ngtcp2 OpenSSL backend。
- [ ] CMake 识别 `vcpkg install ngtcp2[openssl]:x64-windows`，不再假设 pkg-config。
- [ ] 将 `quic-state` 的证书/TLS 元数据和 `http3-state` 移植到 OpenSSL。
- [ ] 在声称支持前补齐 MSVC 构建和本地 HTTP/3 lab。
- [ ] OpenSSL 路径验证前保持 Linux 的 GnuTLS backend。

## 发布策略

功能变化使用中版本（`2.29.x` → `2.33.0`），修复使用补丁版本。标签推送、
GitHub Release 和构建/测试证据齐全才算发布完成。
