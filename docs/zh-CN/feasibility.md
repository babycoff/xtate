# P3 / P4 可行性评估

**中文** · [English](../feasibility.md)

这是工程可行性评估，不是实现承诺。前提是 2.42.0 架构：无状态
ZBanner/UDP、HLTCP 有状态 TCP、输出侧聚合。

## QUIC 探针与 HTTP/3 探索

**结论：QUIC 能力探测已实现；真正的 HTTP/3 扫描是独立传输工程，必须先做库选型。**

QUIC 不是“UDP 上的 HTTP/2”。它把 TLS 1.3、丢包恢复、packet number space、
connection ID 和至少 1200 字节的 Initial 报文组合在一起。只发一个带
`ALPN=h3` 的 UDP 数据报既不是 QUIC 探针，也不是 HTTP/3 探针。

### 方案 A——QUIC 能力探测（建议先做）

无状态 `quic`/`quic-hello` UDP 探针可以：

- 构造合法的 QUIC v1 Initial 包，使用随机 DCID/SCID 和 TLS 1.3 ClientHello
  （ALPN `h3`）；
- 派生 Initial 密钥，使用 AES-128-GCM 做 header protection；
- 用唯一 DCID 匹配响应并分类：
  - Version Negotiation；
  - Retry（带 token）；
  - Initial/Handshake 响应；
  - connection close / stateless reset；
  - 无响应；
- 输出 QUIC 版本、CID 和响应类型。

它**不能**：

- 证明 HTTP/3 可用；
- 完成 TLS 握手或发送 HTTP/3 请求；
- 观察 QPACK/control stream。

成本：中等。它适合现有无状态 ZBanner/UDP 模型：每个目标使用唯一 DCID，
不保存连接状态。但仍需要正确实现 QUIC 包构造、版本/Retry/token 边界，
并用本地 `aioquic`、`quiche` 或 `ngtcp2` 服务端测试。

### 方案 B——库支持的 QUIC 握手和 HTTP/3

真正的 HTTP/3 探针需要：

- UDP socket/事件循环和逐连接状态；
- QUIC 握手、TLS 1.3 和 transport parameters；
- ACK/丢包检测/定时器、Retry/token、connection close；
- HTTP/3 control stream、QPACK、请求/响应和 GOAWAY。

它不能塞进当前无状态 `udp` 扫描或 `tcp-state` HLTCP，需要新的
`quic-state` 类扫描器（或独立 helper 进程）、新 probe 类型和并发/资源模型。
可以用可选 `ngtcp2`/`nghttp3`、`quiche` 或 `msquic` 提供传输，但扫描器仍要
自己负责流调度、重试、输出和上限。

成本：高。会改变默认构建/CI/依赖策略，必须保持可选，不能静默降级。

### 方案 C——外部 sidecar

独立 QUIC/HTTP3 helper 按目标或批次调用，可以保持核心扫描器小，但增加
进程/IPC 开销，rate/连接统计更难。它适合研究原型，不是第一版生产集成。

### 方案 D——明确非目标

如果测量需求只是“这个 UDP 端口是不是 QUIC”，做到方案 A 即可，并明确不声称
HTTP/3。这比伪造 HTTP/3 结果安全。

### 建议与决策门槛

1. 先在热路径外做 QUIC/HTTP3 研究原型，至少和一个本地 `aioquic`/`quiche`
   服务端对比。
2. 如果 lab 证明响应归属、Retry/版本行为确定，再实现**方案 A** 的
   `quic-hello`（或 `quic`）。
3. 只有出现真实的 HTTP/3 响应需求并完成库选型，才进入方案 B；不要因为
   QUIC 热门就增加默认依赖。
4. 输出语义必须区分：
   - `quic`：观察到 QUIC transport；
   - `http3`：完成 HTTP/3 握手/请求。

方案 A 验收：

- 本地 QUIC 服务端收到合法 Initial；
- Version Negotiation 和 Retry 可分类；
- 唯一 DCID 防止跨目标错误归属；
- 不保存 per-target 表和无界重试状态；
- lab 不依赖公网。

项目的 OpenSSL 支持范围包含 1.1.1，而 QUIC API 并非所有版本都有；实现不能
静默要求会破坏正常构建的新 OpenSSL。

## 协议覆盖扩展

见 [协议覆盖计划](./protocol-coverage.md)：以 zgrab2 为参考的协议矩阵和分层
实现计划。大多数协议不需要新的传输层机制，和 QUIC 是独立工作流。

## P3 — 扫描控制

### 有限的目标相关探针选择

**结论：可行，中等复杂度，中等风险。**

目标：根据端口、banner、TLS 证据选择下一步探针，而不是对所有目标盲发所有
探针。

可行原因：

- 扫描器已经输出 classification、banner、TLS 字段；
- 选择逻辑可以放在报文热路径之外；
- 不需要 ZBanner 保存逐目标状态。

核心设计问题是决策放在哪里：

1. **外部控制器**：第一轮输出 NDJSON，控制器按探针生成第二轮目标文件。
   风险最低；不改扫描器 API；速度较慢。
2. **输出侧调度**：输出模块生成后续目标文件。仍然无扫描器状态；需要本地
   编排步骤。
3. **扫描器内选择**：需要逐目标决策状态和第二探针队列，与无状态设计冲突，
   不应作为第一版。

第一版验收：

- 输入/输出确定；
- 不保存无界 per-target 表；
- 有文档化的两轮 recipe；
- 测试证明只有证据匹配的目标会被选中。

### 自适应发包速率

**结论：可行，中高复杂度，高测量风险。**

目标：从低于固定 `--rate` 开始，观察丢包/超时/ICMP 错误后自动调整。

需要：

- 有界反馈窗口和控制环；
- 明确 min/max 速率和安全默认值；
- 区分本地拥塞、链路丢包和目标不响应；
- 确定性/手动回退（`--rate` 必须仍是权威）；
- lab 和真实网络验证。

风险：

- 反馈环可能震荡或放大丢包；
- 无状态扫描器无法归因每一个丢包；
- 结果会依赖速率，更难复现。

建议：作为现有 throttle 外围的可选控制器实现，不要放进 probe 回调。

### 跨层服务指纹

**结论：可行，数据模型复杂度高。**

组合 IP/TCP 选项、TLS 参数和应用层证据。扫描器只输出字段；归一化和分组放在
输出层。无状态实现不能维护逐目标指纹表。

### stateless → stateful 两阶段 handoff

**结论：可行，复杂度高。**

自然形式：ZBanner/端口证据选出少量候选，然后 HLTCP 对有状态 TLS/应用探针。
需要交接格式和调度器，并控制 TCB 成本。它与暂缓的 HLTCP slot 工作重叠。

## P4 — 模板与流量

### Xtate 原生 YAML 模板

**结论：可行，中高复杂度，接口面很大。**

要求：

- 小型 Xtate 原生 schema，不做 Nuclei 兼容；
- 模板编译到现有 probe/slot plan，而不是解释任意代码；
- 有界超时、载荷和输出字段；
- 明确失败语义；
- schema 版本和校验。

避免：嵌入通用语言、任意文件/网络访问、静默 Nuclei 回退。第一版只做只读
matcher/response schema 和少量编译动作。

### 扫描流量指纹随机化

**结论：可行，中等复杂度，研究与策略风险。**

选项：TCP option 顺序、IP ID 行为、源端口选择、TTL、HTTP header 顺序、
TLS 扩展顺序、GREASE。部分已在 stack/probe 设计中。

风险：

- 可能改变目标行为，影响测量有效性；
- 随机化降低可复现性；
- 可被滥用规避监测；
- 需要研究开关、确定性 seed 和清晰文档。

建议：只作为显式研究功能，不默认开启，且只在本地 lab 测试。

## 建议顺序

当前方向优先 QUIC/HTTP3 与模板/流量，其余保留在 backlog：

1. QUIC 能力探测和 HTTP/3 库选型。
2. 只读的 Xtate 原生 YAML 模板。
3. 协议覆盖 Batch A（见[协议覆盖计划](./protocol-coverage.md)）。
4. 流量随机化研究（opt-in、固定 seed、只在 lab）。
5. JARM 失败模式与外部 retry manifest。
6. SSH 深度 KEX/host-key、完整 HTTP/2、HLTCP slot。
7. 外部目标相关选择、自适应速率、两阶段 handoff。

## 第一版非目标

- 扫描器内 per-target 选择状态；
- 无约束模板执行；
- 默认流量混淆；
- Nuclei 兼容；
- 功能或依赖不可用时的静默回退。
