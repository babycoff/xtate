# 扫描模式

[English](../scanning-modes.md) · **中文**

在 Xtate 中，一次扫描是一个**组合**：用 `-scan` 选择扫描模块，需要时再用 `-probe` 选择探测模块。扫描模块负责数据包与接收校验；探测模块负责载荷及其解析器。探测模块的*类型*必须与扫描模块声明的要求完全一致，否则扫描会拒绝启动。

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

`-scan` 是必需的；只有当模块声明“不需要探测”时 `-probe` 才是可选的。模块参数分别通过 `-scan-arg` 和 `-probe-arg` 传入，每个都是一整条带引号的字符串（见 `--help-scan <module>`、`--help-probe <module>`）。

> 本文档对应 Xtate v2.43.0。命令行才是最终依据：`--help`、`--help-scan`、`--help-probe`。

## 选择扫描模块

| 扫描模块 | 探测类型 | 常用探测 | 产出 | 内核 RST 规则 |
|:---|:---|:---|:---|:---:|
| `tcp-syn` | none | - | 开放/关闭判定，无载荷 | 否 |
| `zbanner` | `tcp` | `http`、`hello`、`tls-hello` | 真实 TCP 握手 + 首个 banner | **是** |
| `tcp-state` | `state` | `tls-state`、`http-state`、`hello-state` | 完整 TCP 会话、TLS、HTTP | **是** |
| `udp` | `udp` | `echo`、`dns`、`snmp`、`hello-udp` | UDP 响应或 ICMP 端口不可达 | **是** |
| `icmp-echo` | none | - | 存活主机 | 否 |
| `icmp-time` | none | - | 存活主机，仅 IPv4 | 否 |
| `sctp-init` | none | - | SCTP 端口开放/关闭 | 否 |
| `arp-req` | none | - | 局域网 IPv4 主机的 MAC 地址 | 否 |
| `ndp-ns` | none | - | 局域网 IPv6 主机的 MAC 地址 | 否 |
| `yarrp-echo` | none | - | 无状态 ICMP 追踪路由跳点 | 否 |
| `yarrp-udp` | none | - | 无状态 UDP 追踪路由跳点 | 否 |

“内核 RST 规则”是指主机需要 `./firewall/add_rules.sh` 添加的 iptables/ip6tables 规则。这些规则会丢弃向外发送的 TCP RST 和 ICMP 端口不可达报文，使本机内核无法拆掉它不认识的连接。探测类型那一列同时也是约束：`none` 类模块完全不能传 `-probe`，`zbanner` 需要 `tcp` 类型探测，`udp` 需要 `udp` 类型，`tcp-state` 需要 `state` 类型——传错就是启动错误。

## 无状态与有状态

- **无状态**（`tcp-syn`、`udp` 以及 ICMP/SCTP/ARP/NDP/Yarrp 系列模块）：一次请求、一次响应，没有按目标维护的表。规模受网络和速率限制，而不受内存限制。
- **ZBanner**（`zbanner`）在同样意义上也是无状态的，但它能完成 TCP 握手：连接状态保存在对端，序列号里的 SipHash cookie 用来证明响应属于我们。参见 [ZBanner](./zbanner.md)。
- **混合状态**（`tcp-state`）会为每条已建立的连接在用户态分配一个小的 TCB。这换来了 TLS 握手、证书和 HTTPS，代价是吞吐量低若干个数量级。参见 [HLTCP](./hltcp.md)。

经验法则：端口清单用 `tcp-syn`，互联网规模 banner 用 `zbanner`，UDP 服务用 `udp`，主机发现用 ICMP/ARP/NDP，需要真实会话才能拿到证据的少量主机用 `tcp-state`。

## 速率不是目标速率

`-rate` 限制的是**线上总包速率**，包括接收路径上生成的包。它不是目标/秒的保证，也不存在通用的 `目标/秒 = rate / N` 公式。

每目标实际发包数取决于扫描模块、探测模块、目标响应、重传和模块选项：

| 模块 | 每目标典型发包数 | 主要变化 |
|:---|:---|:---|
| `tcp-syn` | 约 1 个初始 SYN | `--send-rst` 会为开放响应多发一个 RST |
| `zbanner` | 默认正常完成时约 3 个：SYN、ACK+载荷、RST | `--no-rst` 少一个；`--with-ack` 多一个；closed/零窗口、`--all-banner`、multi-slot 和丢包都会改变比例 |
| `tcp-state` / HLTCP | 不固定：SYN、ACK+探测、重传、ACK/FIN/RST | 取决于 TCP 状态、探测/子探测、目标行为和重传策略；**不要使用固定倍数** |
| `udp`、`icmp-*`、`sctp-init` | 通常每目标一个请求 | 重试、ICMP 错误和探测行为可能增加包 |

ZBanner 默认情况在 CPU/网络饱和前大约接近 `rate / 3`，这只是 **ZBanner 默认行为**，不能套用到 HLTCP 或其它模块。参见 [ZBanner 速率计算](./zbanner.md#速率计算)。

估算目标吞吐时：

1. 先用小规模运行，实测线上包数和结果数；
2. 计算当前模块/探测/目标群体的实际每目标包数；
3. 只把 `-rate` 提高到 CPU、网卡或目标容量饱和为止；
4. 记住响应包、重传和协议栈生成的包都占用同一个预算。

## 实战示例

### SYN 扫描——无探测模块、无需防火墙

开放端口是 `success`（`"open" because "syn-ack"`）；关闭端口是 `failure`（`"closed" because "rst"`），默认隐藏，需要加 `-show failed` 才能看到。`--send-rst` 会用 RST 回复 SYN-ACK，而不是把半开连接留给目标。在 Windows 上，本机协议栈不会对未知半开连接发 RST，所以 `tcp-syn` 需要 `-scan-arg "--send-rst"`；`zbanner` 本来就会自己发 RST。

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000 -show failed
```

### ZBanner + HTTP——抓取真实 banner

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http \
  -rate 1000 -show info
./firewall/rm_rules.sh
```

`zbanner` 的端口状态以 `info` 级别输出，因此必须加 `-show info` 才能看到 `open` / `closed` / `fake-open` 行；探测模块给出的 banner 结果是 `success`。如果希望端口状态进入默认输出流，可用 `-scan-arg "--port-success --port-failure"` 提升它们的级别。

### ZBanner + TLS ClientHello——不完成握手

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan zbanner -probe tls-hello \
  -rate 1000 -show info
./firewall/rm_rules.sh
```

`tls-hello` 会读取 ServerHello（协议、版本线索、HTTPS 关键字）而不完成握手，因此在仅支持 TLS 1.3 的服务器上，它得到的信息比 `tls-state` 少。

### tcp-state + tls-state + http-state——获取 HTTPS 证据

`tls-state` 是中间层，没有可用的默认子探测模块：必须用 `-subprobe` 指定一个 `state` 类型探测。嵌套值整体作为一个参数传给 `-probe-arg`。

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -version -subject -cert" \
  -rate 100 -wait 30 -show info
./firewall/rm_rules.sh
```

要给子探测模块传它自己的参数，就用 `-subprobe-arg`，引号层级再深一层：
`-probe-arg "-subprobe http-state -subprobe-arg '-url /admin -user-agent xtate' -version"`。
`tcp-state` 会把未知 TCB 的 RST 作为 `closed` 以 `info` 等级输出；加 `-show info` 才能看到这些行。重复 RST 会被接收侧去重表抑制。

### UDP + echo

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p u:7,u:19 -scan udp -probe echo \
  -rate 1000 -show info
```

`echo` 会发送四个由连接 cookie 派生的字节，并接受包含这些字节的响应。收到 UDP 响应记为 `responsed`；收到 ICMP 端口不可达记为 `closed`（只有加 `-scan-arg "--port-failure"` 才是 `failure` 级别）。这里防火墙规则很重要，否则内核会为那些无人监听的端口自行向对端发送不可达消息。

### 用 ICMP 做主机发现

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -scan icmp-echo -rate 1000
sudo ./bin/xtate -ip 192.168.1.0/24 -scan icmp-time -rate 1000   # IPv4 only
```

它们不是端口扫描：不要传 `-p`。它们会输出 `success` 结果，分类为 `"alive"` / `"echo reply"`（或 `"timestamp reply"`）。

### 局域网发现——ARP 与 NDP

ARP 是二层协议，只在本网段有效；`-lan-mode` 把目的 MAC 设为广播地址，`arp-req` 仅支持 IPv4 且不读取端口。

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -scan arp-req -lan-mode -rate 1000
```

`-lan-mode` 只是把路由器/目的 MAC 改成广播地址，**不会**解析每个目标的 MAC。它只适合 ARP/NDP 以及明确需要二层广播的扫描。普通 TCP/UDP 扫描请先不要加：默认的网关/单播路径通常是对的，而广播目的地址在路由、Docker/bridge 或过滤链路上可能直接失败。

IPv6 邻居使用 NDP：在同一链路上使用链路本地源地址，`--fake-router-mac` 可以阻止 Xtate 为非链路本地目标解析网关。

```bash
sudo ./bin/xtate -ip fe80::1/120 -scan ndp-ns -src-ip fe80::2 -fake-router-mac
```

`--bypass-os` 更进一步：Xtate 会自己替（可能是伪造的）源地址应答 ARP/NDP，因此不需要防火墙规则——但此后操作系统协议栈无法再替你发送 RST 或 ICMP 不可达。

### Yarrp——无状态拓扑探测

Yarrp 把 TTL 编码进数据包，并离线重建路径。TTL 范围通过 `o:` 端口命名空间指定（`-p o:1-20`），绝不使用普通端口列表。

```bash
# ICMP echo: hop distance 1..20; UDP: destination port carries TTL from 33434
sudo ./bin/xtate -ip 198.51.100.7 -p o:1-20 -scan yarrp-echo -rate 100
sudo ./bin/xtate -ip 198.51.100.7 -p o:1-20 -scan yarrp-udp \
  -scan-arg "-init-target-port 33434" -rate 100
```

两者都会产生 `path`（TTL 超限）和 `destination` 结果，并带 `distance` 字段；路径在后续处理中按 `(target, distance)` 重建。

## 探测 slot

JARM 是目前唯一内置的多 slot 探针。它声明 `ProbeSlotPlan`：
`count = 10`、`trigger = after first reply`。slot 0 正常发送；只有第一个
slot 的响应被判定为 TLS 记录后，才发送剩余九个 slot。在 ZBanner 执行器中这特指
首个 banner/数据段；纯 ACK 或 RST 首响应不会触发 fan-out。

`ProbeSlot_Always` 是另一种触发方式：ZBanner/TCP 和 UDP 从第一次迭代就发送
全部 slot。UDP 没有握手，所以启动时会拒绝 `ProbeSlot_AfterFirstReply`；
UDP 探针应使用 `Always`。

slot 靠**源端口**区分：slot `i` 使用 `source_port_start + i`，响应目的端口
反推 slot 编号。源端口范围必须覆盖 plan 的 slot 数量。引擎不保存逐目标
group，也不在扫描器里聚合；每个 slot 输出自己的 `jarm_part`，由输出侧
脚本合并。

## 防火墙规则

同样的三类规则覆盖所有基于握手的模式：丢弃向外发送的 TCP RST（v4 和 v6），并丢弃向外发送的 ICMP 端口不可达（ICMP 3/3、ICMPv6 1/4）。

```bash
./firewall/add_rules.sh     # append the rules
# ... run zbanner / tcp-state / udp scans ...
./firewall/rm_rules.sh      # remove them immediately afterwards
```

这些规则影响整台主机：生效期间，本机发出的所有 RST 都会被丢弃，包括无关的 SSH 或浏览器会话。绝不要长期保留。Windows 上没有随附的等价脚本；SYN 和 ICMP 扫描在 Windows 上照常工作，但握手类模式能否成功取决于 Windows 协议栈是否重置这些连接。

## 另见

- [目标与端口](./targets-and-ports.md) - 构造地址与端口空间
- [输出](./output.md) - 结果级别与格式
- [模块](./modules.md) - 完整模块清单
- [ZBanner](./zbanner.md) 与 [HLTCP](./hltcp.md) - 两个引擎的工作原理
