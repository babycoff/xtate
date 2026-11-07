# ZBanner 审计与简化

[English](../zbanner-audit.md) · **中文**

`zbanner` 是无状态 TCP banner 链路，也是最大的扫描模块文件
（`src/scan-modules/zbanner-scan.c`，约 1200 行）。这是一份审计计划，不表示
当前所有行为都有故障。目标是在不破坏无状态模型的前提下，把状态机显式化、
可测试化。

## 发现

### 1. `AfterFirstReply` 可能重复 fan-out

`ProbeSlot_AfterFirstReply` 在 slot 0 返回 banner 时发送 slot 1..N。触发逻辑
位于 banner 分支，没有 one-shot 保护，也没有 per-target group 状态。多段响应
或多次去重后 banner 可能让 fan-out 执行多次，产生重复 SYN。JARM 通常只返回
一个 ServerHello，所以不一定暴露；对慢速/多段目标这是逻辑问题。

修复方向：

- 只在首个被接受的 banner（`valid_pkt->repeats == 0`）触发；
- 或增加有界的 per-target one-shot 标记；
- 或等 connection-local plan 实现后移入其中。

### 2. all-banner limit/floor 边界曾经是隐式的

旧代码用 `repeats >= limit - 1` 触发 RST/truncated，用 `repeats >= limit`
控制 no-output。文档定义的是“触发 limit 的那一段标记 `truncated: 1`”，所以
旧行为是有意设计，不是差一 bug。真正的风险是规则分散在分支里，未来容易改得
不一致。

本轮把规则集中到 `zbanner-policy.c` 并测试：

- 记录 `limit` 个段（ordinal 0..limit-1）；
- 在触发 limit 的段上发送 RST；
- 该段标记 `truncated`（文档语义）；
- 后续段不记录、不 ACK；
- floor 抑制低于 1-based floor 的段。

### 3. `banner idx` 不是段序号

`banner idx` 是 banner 去重键的零基重复计数：该 flow/type 的 entry 创建后，
收到的第一个 banner 包为 0；之后每个匹配包递增，包括重传和新数据段。它不是
TCP 段序号；去重 entry 被淘汰后可能从 0 重新开始，关闭去重时恒为 0。文档已
按此精确说明。`banner seqno` 才是精确 TCP 序列号，离线排序/去重应使用它。
`banner idx` 仅为兼容和近似 all-banner 计数保留，不作为主段序号。

### 4. `AfterFirstReply` 只覆盖 banner 分支

实现只在带数据 banner 分支 fan-out；纯 ACK 或 RST 首响应不会触发后续 slot。
这对 JARM 是正确的，通用 slot 计划文档现已明确收窄 ZBanner 语义为首个
banner/数据段；不计划增加 accepted-response 判断。

### 5. `all-banner-limit/floor` 依赖近似去重

两个选项都使用 `valid_pkt->repeats`。去重表是 best-effort，高负载会淘汰条目，
因此 limit/floor 是近似的。文档已说明，但代码和测试应把它当作准确性限制，
而不是精确段计数器；排序优先使用 `banner seqno`，并补边界测试。

### 6. `with-ack` 与零 payload

代码已经只在 `payload_len > 0` 时发送额外握手 ACK；零 payload 探针只发一个
ACK。保留该行为并补测试，避免将来引入多余报文。

### 7. 声明长度与实际长度不一致

现在验证阶段会调用 `make_payload_cb` 得到实际长度，并用实际长度做 banner/ACK
ACK 号校验；声明/实际不一致不再静默导致响应验证失败。SYN-ACK 路径仍会告警，
并在结果中输出 `payload_len_declared` / `payload_len_actual`。Probe 契约仍应
要求两者相等，后续应在测试或 probe 初始化时拒绝不一致。

### 8. 参数校验偏薄

`--all-banner-limit`/`--all-banner-floor` 现在限制在 `0..1000000`，且非零
floor 大于非零 limit 会在启动时拒绝。

## 已经做得好的地方

- probe 回调前检查源端口 index；
- payload 大小与 packet buffer 长度检查；
- RST/SYN-ACK/banner/ACK 分支和输出 reason 明确；
- all-banner 对小 TCP 窗口、snaplen、max packet len 的告警；
- init 时检查 slot 数和源端口容量。

## 本轮已实现

- 响应分类抽成 `zb_classify()`；`validate` 和 `handle` 共用同一事件表。
- all-banner 的 limit/floor/RST/ACK/truncated 决策抽成
  `zb_all_banner_decide()`，并有 policy 自检。
- `AfterFirstReply` 只在首个被接受 banner（`repeats == 0`）后 fan-out，避免
  重复/多段 banner 的重复 slot 突发。注意：这依赖去重 `repeats`；使用
  `--no-dedup-banner` 或全局 `-nodedup` 时 repeats 恒为 0，仍可能重复 fan-out。
  若该模式需要严格 one-shot，后续应加有界 one-shot 表。
- 增加 all-banner limit/floor 边界和 floor<=limit 校验。
- 记录并保留 `with-ack` 零 payload 行为。
- banner/ACK 验证使用实际生成 payload 长度；不一致诊断附在 SYN-ACK 结果上。

## 剩余工作

- `AfterFirstReply` 已明确收窄为首个 banner/数据段；纯 ACK/RST 首响应不会
  fan-out。文档已按 ZBanner 语义写清楚。
- `banner idx` 已明确为零基去重重复计数，不是 TCP 段序号；离线排序用
  `banner seqno`。
- payload 声明/实际长度不一致已有诊断且不再静默破坏验证，但 probe 契约错误
  还不是启动期硬错误。
- 去重压力下 limit/floor 仍是近似值。
- `tests/zbanner/` 的 pcap 矩阵覆盖 SYNACK/RST、banner、重传、all-banner
  limit、错误 ACK 和 Lua payload mismatch。

## 建议的重构

1. 抽出响应分类器，返回 `SYNACK`/`RST`/`BANNER`/`ACK`/`IGNORE` 及标准化结果。
2. 把 all-banner 的 limit/floor/truncated/RST 决策收进一个 helper，并补边界测试。
3. 给 `AfterFirstReply` 加 one-shot 保护，测试多段 banner。
4. 保留 `banner seqno` 作为排序字段，把 `banner idx` 降级为近似去重计数。
5. 补回归矩阵：
   - limit 1/2/8；floor 1/2；
   - 重复/重传 banner；
   - ACK-only、RST 首响应；
   - payload 长度不一致；
   - IPv4/IPv6；
   - with-ack 的零/非零 payload。

## 非目标

- 不把 ZBanner 改成 HLTCP，不增加 per-target TCP 状态。
- 不在重构中改变默认输出或防火墙要求；兼容性决策另做。
