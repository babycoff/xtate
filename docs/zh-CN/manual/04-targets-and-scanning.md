# 04 · 目标与扫描

[English](../../manual/04-targets-and-scanning.md) · **中文**

扫描由目标空间和引擎共同定义。目标空间是一组地址乘以一组端口；引擎决定发送哪些报文、如何归类响应。本章介绍地址与端口语法、目标计数，以及扫描引擎的实用选择。

模块目录见 [05 · 模块与参数](./05-modules-and-parameters.md)；job 执行见 [03 · CLI 与 job](./03-cli-and-jobs.md)。

## 目标空间

目标用 `-ip`（别名 `--target-ip`）提供，端口用 `-p`（别名 `--port`）。两者都支持多种形式。

| 形式 | 示例 | 地址数 |
|:---|:---|:---:|
| 单个地址 | `-ip 203.0.113.10` | 1 |
| CIDR | `-ip 198.18.0.0/24` | 256 |
| 闭区间 | `-ip 203.0.113.10-203.0.113.40` | 31 |
| 分量区间 | `-ip 192.168.0-3.1-20` | 80 |
| 逗号列表 | `-ip 10.0.0.1,10.0.0.4-10.0.0.8` | 6 |
| IPv6 | `-ip 2001:db8::/64` | 2^64 |

```bash
xtate -ip 198.18.0.0/24,203.0.113.10-203.0.113.40 -p 80,443 -scan tcp-syn \
  --list-target
```

`--list-target` 打印解析后的 `address port` 对而不发送报文，是验证目标表达式最快的方式。需要确定性的排序列表时用带方括号的形式 `--list-target[order]`（或 `[norandom]`）。

### 分量区间

分量区间在一个 token 内变化最多四个以点分隔的分量。`192.168.0-3.1-20` 表示 `192.168.[0..3].[1..20]`，是一个稀疏矩形，而不是连续区间。内部按笛卡尔积展开，有两个限制：

- 每个 token 最多 **4** 个可变分量；
- 该乘积内最多 **1,048,576** 个地址。

单个 CIDR 或连字符区间不受乘积上限约束；`0.0.0.0/0` 存为一个区间，而不是四十亿个条目。IPv6 分量区间由同一套展开逻辑支持。

其他限制：目标 token 最长 128 字节，include 文件的一行最长 65,535 字节。更长的内容会以错误拒绝。

### 重复选项会替换

`-ip` 设置地址列表，不追加。`-ip A -ip B` 只扫描 B。要合并目标，请用逗号或 include 文件：

```bash
xtate -ip 10.0.0.0/24,10.0.1.2 -p 22 -scan tcp-syn
```

同样的替换规则适用于 `-p`、`-iL` 和 `--exclude`（见下面的警告）。

## Include 文件与 stdin

```bash
xtate -iL targets.txt -p 80,443 -scan tcp-syn
cat targets.txt | xtate -iL - -p 443 -scan tcp-syn
```

`-iL`（`--include-file`）读取与 `-ip` 相同的语法，每行一个或多个条目。`#` 开始注释，空行被忽略，`-` 读取 stdin。坏行会连同文件名和行号一起报告并中止启动；目标在任何报文发出前完成解析和排序。文件会替换先前的地址列表，因此不要把 `-ip` 和 `-iL` 组合起来指望取并集。

## 排除

```bash
xtate -ip 10.0.0.0/24 -p 22,80 --exclude 10.0.0.0/28 --exclude-port 80
xtate -ip 10.0.0.0/24 -p 22 --exclude-file skip.txt
```

排除在所有目标与端口解析完之后应用，同时作用于地址和端口两个维度。共有三种形式：`--exclude`（语法同 `-ip`）、`--exclude-file` 和 `--exclude-port`。

**每个 `--exclude` 选项都会替换之前的排除列表。** 这与多数人的预期相反：

```bash
# Wrong: only the second exclusion is applied
xtate -ip 10.0.0.0/24 -p 22 --exclude 10.0.0.0/28 --exclude 10.0.0.128/28

# Right: combine them in one option, or use a file
xtate -ip 10.0.0.0/24 -p 22 --exclude 10.0.0.0/28,10.0.0.128/28
xtate -ip 10.0.0.0/24 -p 22 --exclude-file skip.txt
```

Blackrock 在目标超过十亿个 IPv4 地址且没有任何 IPv4 排除时拒绝启动，以防意外全互联网扫描。如果你确实要这么做，加一个无害的排除，例如 `--exclude 255.255.255.255`。

## ASN 目标

加载 ip2asn 表后，可以按自治系统选择目标：

```bash
xtate --ip2asn-v4 ip2asn-v4.tsv --asn-v4 13335 -p 443 -scan tcp-syn
xtate --ip2asn-v6 ip2asn-v6.tsv --asn-v6 15169 -p 443 -scan tcp-syn
```

`--asn-v4`/`--asn-v6` 加入某个 ASN 的前缀；`--exclude-asn-v4/v6` 移除它们。ip2asn 文件是必需的：没有它，ASN 选择会在启动时失败。`--output-as-info` 用 ASN、国家和描述标注结果。

## 端口

| 语法 | 含义 |
|:---|:---|
| `80` | TCP 80 |
| `80,443` | TCP 80 和 443 |
| `8000-8100` | TCP 区间，含端点 |
| `u:161` | UDP 161 |
| `s:38412` | SCTP 38412 |
| `o:1-20` | "other" 空间，用于 TTL/偏移量值 |
| `80,u:161,162` | TCP 80，UDP 161 和 162 |

协议前缀会持续到下一个前缀，因此 `u:161,162` 是两个 UDP 端口。前缀不区分大小写。内部 TCP、UDP、SCTP 和 "other" 各有自己的 0–65535 空间；`u:53` 和 `53` 是不同的端口。

`-p` 会先清空端口列表。`--top-port N` 追加内置 TCP 热门端口列表中的前 N 个端口，`--udp-top-port N` 对 UDP 做同样的事。由于它们只追加，请把 `-p` 放在它们前面：

```bash
xtate -ip 203.0.113.10 -p 8080 --top-port 100 -scan tcp-syn
```

无端口引擎忽略 `-p`：`icmp-echo`、`icmp-time`、`arp-req` 和 `ndp-ns`。`yarrp-*` 引擎使用 "other" 空间，因此必须提供 `-p o:1-20`。使用 blackrock 且完全没有端口时，Xtate 会警告并插入一个假的 `o:0` 目标；大多数引擎会直接忽略它。

## IPv6 说明

- 链路本地目标需要显式的链路本地源地址，例如
  `-src-ip fe80::1%eth0`。
- NDP 扫描使用 `--fake-router-mac`，这样 Xtate 不会要求操作系统为非链路本地目标解析网关；用 `--bypass-os` 让它自己应答邻居发现。
- Blackrock 的目标空间限制为 63 位（地址 × 端口），因此带多个端口的 /64 会超限。请扫描子区间，或使用列表生成器。
- IPv6 的分量区间和 CIDR 行为与 IPv4 相同，但请记住 /64 是 2^64 个地址：启动前先用 `--list-target`。

## 扫描模式一览

| 引擎 | 探测类型 | 状态 | 每目标报文数 | 防火墙规则 |
|:---|:---|:---|:---|:---|
| `tcp-syn` | 无 | 无状态 | 1 SYN（`--send-rst` 时加 RST） | 不需要 |
| `zbanner` | tcp | 无状态握手 | ≈3（SYN、ACK+载荷、RST） | 需要 |
| `tcp-state` | state | 有状态 TCB | 取决于会话 | 需要 |
| `udp` | udp | 无状态 | 1 个数据报 | 需要 |
| `quic-state` | state | 有状态 QUIC | 握手 | 按 UDP 指引 |
| `icmp-echo` | 无 | 无状态 | 1 个 echo | 不需要 |
| `icmp-time` | 无 | 无状态 | 1 个 timestamp | 不需要 |
| `sctp-init` | 无 | 无状态 | 1 个 INIT | 不需要 |
| `arp-req` | 无 | 无状态 | 1 个请求 | 不需要 |
| `ndp-ns` | 无 | 无状态 | 1 个 solicitation | 不需要 |
| `yarrp-echo` | 无 | 无状态 | 每 TTL 1 个 | 不需要 |
| `yarrp-udp` | 无 | 无状态 | 每 TTL 1 个 | 不需要 |

探测类型必须匹配：`zbanner` 需要 `tcp` 探测，`tcp-state` 需要 `state` 探测，`udp` 需要 `udp` 探测。Xtate 在启动时校验，不匹配就以错误退出，而不是静默发出错误的报文：

```bash
# Error: tls-state is a state probe, but tcp-syn has no probe support
xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -probe tls-state
```

## 选择引擎

- **端口可达性，快速简单** —— `tcp-syn`。不需要防火墙规则，每目标一个报文。关闭的端口显示为失败；需要时加 `-show failed`。
- **不需要状态的 banner 或协议证据** —— 用带 `tcp` 探测的 `zbanner`。它在用户态用 SipHash cookie 完成握手，是版本探测最常见的选择。
- **任何需要真实连接的场景** —— 用带 `state` 探测（`tls-state`、`http-state`、`get-state` 等）的 `tcp-state`。它会保留 TCB，因此要为 `--tcb-mem` 和 `--conn-expire` 做预算。
- **UDP 服务** —— 用带 UDP 探测的 `udp`；UDP 应答是 `responsed`，ICMP 不可达是 `closed`/`port unreachable`。
- **主机存活** —— `icmp-echo` 或 `icmp-time`。
- **本地链路发现** —— `arp-req`（IPv4）或 `ndp-ns`（IPv6）。
- **路径追踪** —— `yarrp-echo`/`yarrp-udp`，每个 TTL 一个探测。

## 速率、超时与完成

`-rate` 是出向报文速率，单位包/秒，不是目标/秒。默认值是 100。接受小数：

```bash
xtate -ip 10.0.0.0/24 -p 22 -scan tcp-syn -rate 250.5
```

每秒尝试次数取决于引擎：`tcp-syn` 和 `udp` 每次尝试约发一个报文，因此尝试/秒 ≈ rate；默认 `zbanner` 每目标约发三个报文，因此尝试/秒约为 rate/3；`tcp-state` 随会话变化。生成的后续报文（RST、ACK）也消耗速率。

通过控制面发送的扫描请求把 `rate` 限制在 1–10000。CLI 接受任何正浮点值。

`--wait` 是 Xtate 在最后一个报文发出后继续接收的秒数，默认 10。总墙钟超时属于 job 层（扫描请求中的 `timeout_sec`，1–86400 秒，或 CLI 上的 `--job-timeout`）。

## 分片、恢复与种子

```bash
# Two shards of the same scan; both must use the same seed
xtate -ip 10.0.0.0/16 -p 80 -scan tcp-syn -seed 0x1234 -shard 1/2
xtate -ip 10.0.0.0/16 -p 80 -scan tcp-syn -seed 0x1234 -shard 2/2
```

`-shard k/n` 从偏移 k-1 开始，发送每第 n 个报文。各分片必须共用同一 `-seed`；否则它们打乱后的顺序不同，会互相重叠。没有显式种子就分片时，Xtate 会警告。

`--resume-index N` 从打乱后序列的位置 N 重新开始。被中断的扫描通常会留下 `resume.conf`，可以用 `--conf resume.conf` 重新载入；`--no-resume-file` 禁用该文件。`-seed time` 从时钟取种；不给 `-seed` 时，Xtate 从熵中派生种子。

## 配方

```bash
# Open TCP ports, including closed ones as failures
xtate -ip 203.0.113.10 -p 1-1024 -scan tcp-syn -show failed

# HTTP and TLS evidence
xtate -ip 203.0.113.0/24 -p 80,443 -scan zbanner -probe http -show info
xtate -ip 203.0.113.0/24 -p 443 -scan zbanner -probe tls-hello -show info

# HTTP inside TLS, with certificate details
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -subprobe-arg '--url / --all-banner' --dump-cert-details" \
  -show info

# UDP service discovery
xtate -ip 203.0.113.10 -p u:53,u:123,u:161 -scan udp -probe echo -show all

# Local ARP and NDP
xtate -ip 192.168.1.0/24 -scan arp-req --lan-mode -show info
xtate -ip fe80::/64 -scan ndp-ns -src-ip fe80::1%eth0 --fake-router-mac -show info

# TTL-limited path discovery
xtate -ip 203.0.113.10 -p o:1-20 -scan yarrp-echo -gen blackrock -show info
```

## 防火墙规则

`zbanner`、`tcp-state` 和 `udp` 引擎工作需要操作系统保持安静：必须抑制出向 TCP RST 和 ICMP port-unreachable 报文，否则主机会自己应答扫描。Xtate 随附 `firewall/add_rules.sh` 和 `firewall/rm_rules.sh`；规则是主机全局的，扫描结束就应移除。`tcp-syn` 和 ICMP/ARP/NDP/yarrp 引擎不需要它们。Windows 没有等价脚本 —— 对 `tcp-syn` 用 `--send-rst`，并在 `zbanner`/`udp` 中考虑本地协议栈的影响。

## 限制

| 限制 | 值 |
|:---|:---|
| 每 token 的可变分量 | 4 |
| 每个分量区间 token 的地址数 | 1,048,576 |
| 目标 token 长度 | 128 字节 |
| include 文件行长度 | 65,535 字节 |
| Blackrock 目标空间 | 63 位（地址 × 端口） |
| `-rate` | > 0，浮点 |
| 控制面 `rate` | 1–10000 |
| 控制面 `timeout_sec` | 1–86400 秒 |
| `--wait` 默认值 | 10 秒 |

## 另见

- [05 · 模块与参数](./05-modules-and-parameters.md) —— 引擎和探测选项
- [目标与端口](../targets-and-ports.md) —— 详尽的目标参考
- [扫描模式](../scanning-modes.md) —— 引擎对比与探测 slot
- [防火墙](../firewall.md) —— 规则与平台行为
- [03 · CLI 与 job](./03-cli-and-jobs.md) —— 控制面与 job 执行
