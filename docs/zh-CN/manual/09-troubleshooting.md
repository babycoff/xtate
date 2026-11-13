# 09 · 故障排查

[English](../../manual/09-troubleshooting.md) · **中文**

本章是一套诊断顺序，而不是一堆零散技巧。Xtate 的失败集中在五类原因上，按正确顺序检查，几分钟内就能找到大多数问题：

1. 网卡或源地址选错；
2. 包过滤器吃掉了回复；
3. 内核复位了它不认识的连接；
4. 速率超过链路承受能力；
5. 结果存在，但被显示过滤掉了。

从上往下逐条排查，并且在改动任何东西之前，先用下面的命令收集证据。每个小节都有两条前提保持不变：原始扫描需要 `sudo`/管理员权限；Linux 上做基于握手的扫描需要安装防火墙规则。

## 先收集证据

| 工具 | 作用 |
|:---|:---|
| `-d`、`-dd`、`-ddd` | 更高的日志级别。日志和实时状态栏写 stderr，结果写 stdout。默认级别显示错误、警告和提示。 |
| `--echo` | 打印生效的配置（包括与默认值不同的项），然后退出。写 bug 报告时从这份输出开始。 |
| `--packet-trace` | 把每个 SENT 与 RCVD 报文（地址、端口、TCP flags）打印到 stdout。配合 `--offline` 与 `-rate 1`，可以在不联网的情况下检查报文构建。 |
| `--pcap capture.pcap` | 把 Xtate 收到的报文（只含接收，不含发送）存成 pcap，供 Wireshark 分析。 |
| `./firewall/check_rules.sh` | 查看 Linux 的 OUTPUT DROP 规则是否已安装。 |
| `--explain-target=<target> --check` | 在扫描前显示选中的网卡、源地址、网关、链路类型与路由组。 |
| `xtate --version` | 构建类型、编译器与构建日期；每份报告都应带上。 |

因此在 Linux 上，有用的第一条命令是：

```bash
sudo xtate -ip 198.51.100.10 -p 80 -scan zbanner -probe http \
  -d -dd --pcap /tmp/xtate.pcap --explain-target=198.51.100.10 --check
```

## 快速分诊

| 症状 | 可能原因 | 第一步 |
|:---|:---|:---|
| 完全没有输出，进程立即退出 | 模块/探测配对错误、目标列表为空、网卡不对 | 读 stderr；检查 `--list-scan`/`--list-probe` |
| 部分目标有回应，部分没有 | 速率过高、路径上有速率限制/防火墙/NAT | 把 `-rate` 减半；先测单台主机 |
| 端口显示 `open`，但没有 banner/TLS 结果 | 内核 RST、防火墙规则缺失 | `./firewall/check_rules.sh`，安装规则 |
| 结果写进了文件，但屏幕上没有 | 选了输出模块、等级被过滤 | `--output-screen` 或 `-o -`；`-show info`/`-show failed` |
| 什么都没收到，也没有报错 | BPF 过滤器、`-src-ip`/`-src-port` 不对、网卡选错 | `--no-bpf`；`--explain-target`；`--list-if` |
| 全部显示 open，包括本该下线的主机 | Fake-IP/TUN 网卡，或中间设备替所有目标应答 | `--explain-target`；解析真实地址 |

## 1. Linux 防火墙规则（有状态扫描先查这一项）

如果 `zbanner`、`tcp-state`、`tls-state`、`http-state`、H2/HTTP3 探测或任何 state 子探测只返回 `open` 而没有别的内容，最常见的原因是缺少 RST/ICMP 抑制规则。Linux 内核不知道 Xtate 在用户空间完成的握手，所以它会用自己的 RST 回应对端报文，连接在 banner、TLS 握手或协议响应到达之前就断掉了。

```bash
sudo ./firewall/add_rules.sh
sudo ./firewall/check_rules.sh
# ... run the scan ...
sudo ./firewall/rm_rules.sh
```

规则是主机全局的：扫描期间它们丢弃所有出向 TCP RST（IPv4 与 IPv6）以及 ICMP port-unreachable。绝不要在共享主机上留着它们 —— 它们会改变无关连接的行为。当需要这些规则的扫描在未安装规则的情况下运行时，Xtate 会在启动时警告：

```text
[WRN] firewall RST/ICMP suppression rules are not fully installed
[HIN] run: sudo ./firewall/add_rules.sh
```

`tcp-syn` 与无状态 TCP 端口扫描不需要这些规则。UDP 扫描不需要 TCP RST 抑制，不过 ICMP 规则可以避免无用的重传。Windows 上没有随附脚本：不要在那里运行 Linux 脚本，并记住基于握手的 banner 扫描依赖 Windows 协议栈不复位这些连接。

## 2. 模块与探测配对

Xtate 遇到不匹配的组合会拒绝启动，而不是猜测：

```text
ScanModule zbanner needs probe of tcp type.
```

规则是：

- `tcp-syn` 不接受探测；
- `zbanner` 接受 `tcp` 类型的探测（例如 `http`、`hello`、`tls-hello`、`h2c`）；
- `udp` 接受 `udp` 类型的探测（例如 `dns`、`echo`、`snmp`）；
- `tcp-state` 接受 `state` 类型的探测（例如 `tls-state`、`http-state`、`hello-state`、`h2`、`dot`、`doh`、`doh-h2`）。

检查注册表与该模块的帮助：

```bash
xtate --list-probe
xtate --list-scan
xtate --help-probe tls-state
xtate --help-scan tcp-state
```

探测参数是一整个带引号的字符串：`-probe-arg "--sni example.com -alpn h2"`。state 探测通过 `tls-state` 组合，而 `tls-state` 没有可用的默认子探测 —— 始终要传 `-subprobe`（或 `-sub-probe-module`）并指定一个 state 类型的探测。

## 3. 目标与端口不为空

有两条启动信息容易被忽略：

- `target IP address list empty.` —— 没有解析出目标。检查目标语法、`-ip` 的值以及任何文件/列表展开。
- 一条"没有给出端口"的警告，随后是一个假的 `o:0` 端点。没有 `-p` 的 TCP 扫描实际上什么都不探测。始终传端口集合。

端口还带协议前缀：`U:` 表示 UDP，`S:` 表示 SCTP，`O:` 表示非端口 slot。把 UDP 扫描指向 `443`（不带 `U:`）实际是 TCP 扫描。

## 4. 网卡与源地址

两个会静默丢弃回复的字段是 `is_my_ip` 与 `is_my_port`：如果回复的目的地址/端口与配置的源地址/端口不匹配，报文会被直接丢弃且没有任何提示。

```bash
xtate --list-if
xtate --explain-target=198.51.100.10 --check
```

- 自动检测会选择第一个有默认网关的网卡。多网卡主机上要强制指定：`-if eth0`；Windows 上用 `--list-if` 打印的数字索引（`-if 3`）。
- `-src-ip` 或 `-src-port` 配错会静默丢掉所有回复。
- 源地址/端口范围的大小必须是 2 的幂。
- Windows 上，隧道和 VPN 网卡常常表现为另一个独立网卡；确认扫描确实从你以为的那个网卡出去。

## 5. 包过滤器（BPF）

每个扫描模块都会安装自己的 BPF 过滤器。过滤范围过窄会隐藏有效回复，看起来和"目标下线"一模一样。用下面的方式检查：

```bash
sudo xtate ... --no-bpf
```

如果加上 `--no-bpf` 后结果出现了，问题就在模块的过滤器上；自定义 `--bpf-filter` 会替换它，所以要写得足够宽。一个已知情况：内置 `tcp-syn` 过滤器精确匹配裸 RST，因此在某些不寻常的网络上，用 `RST+ACK` 回应关闭端口的情况可能被过滤掉。

## 6. 路由器 MAC 与 ARP

Xtate 在发送前解析网关 MAC。如果失败，启动会停在：

```text
arp timed-out resolving MAC address for router ...
```

如果自动发现选错了网关，用 `--router-ip <gateway>`；或者用 `--router-mac 66-55-44-33-22-11` 绕过 ARP。`--lan` 会把目的 MAC 设为广播地址用于局域网扫描；它不会逐目标解析 MAC。

## 7. 路径本身

排除本地配置之后，检查路径：用普通客户端发同样的请求、用 `tcpdump` 镜像流量，或在两端都用 `--pcap`。如果有中间设备改写或丢弃流量，任何扫描器设置都解决不了。

## 端口开放但没有 banner

经典情形是：端口报告 `open`（SYN-ACK 回来了），但 banner/TLS/协议结果始终不出现。Linux 上这几乎总是第 1 节里的内核 RST 问题。它影响 `zbanner`、`tcp-state`、`tls-state`、`http-state`、H2/H3 组合以及每个 state 子探测。

第二常见：探测是无状态的，而服务器需要不止一个报文段的会话（`http` 只看到一个报文段；长 banner 和多报文段 TLS 记录需要 ZBanner 的 `-all-banner` 或有状态探测）。

第三：服务器用零窗口 SYN-ACK 应答。ZBanner 把它归类为 `fake-open`（reason 含 `zerowin`），并且不发送探测载荷 —— 这是 SYN 队列/防火墙的信号，不是 bug。

## TUN、VPN、fake-IP 与 RAW 链路类型

TUN/VPN 网卡（Clash、Meta、Surge 等）常常发布 `198.18.0.0/15`，并用假地址回答 DNS。Xtate 扫描给它的任何地址，所以你可能实际在扫隧道或一段死地址。

```bash
# resolve the real address outside the tunnel first, then scan it
dig +short example.com @1.1.1.1
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe tls-hello -show info
xtate --explain-target=203.0.113.10 --check
```

`--explain-target` 会打印路由选中的网卡和 pcap 链路类型：

```text
Route group 1:
  Interface:  \Device\NPF_{...}
  Link type:  RAW (12)
  Source IPv4: 198.18.0.1
  Gateway:    198.18.0.2
```

支持的链路类型是 Ethernet（`EN10MB`）、`NULL` 与 `RAW`。`RAW` 没有以太网头，因此没有 MAC，也没有 ARP；某些隧道驱动还会改写或丢弃报文。如果链路类型是 `UNSUPPORTED`，用 `-if` 选择物理以太网/Wi-Fi 网卡：启动时会拒绝不支持的链路类型，`RAW` 会被接受，但可能承载不了扫描。

## 权限与网卡错误

| 错误文本 | 含义 | 修复 |
|:---|:---|:---|
| `need to sudo or run as root or administrator` | 没有原始套接字权限 | `sudo` / 提权 shell |
| `can't open adapter` | 网卡不可访问 | 检查 Npcap/libpcap、权限、`-if` |
| `could not determine default interface` | 找不到默认路由 | `-if <name>` |
| `failed to detect IP of interface` | 源地址发现失败 | `-src-ip <addr>` |
| `(libpcap) failed to load` | Linux 上缺 libpcap | 安装 libpcap |
| `couldn't load wpcap.dll` | Windows 上缺 Npcap | 安装 Npcap（WinPcap API 模式） |
| `no pfring adapter available...` | 未安装 PF_RING | 没用 `--pfring` 就忽略 |
| `(pfring) 'pf_ring' driver module not found!!!` | PF_RING 内核模块缺失 | 没用 `--pfring` 时仅提示；强制使用会中止 |

Linux 上可以用 capability 授权避免每次运行都 `sudo`，但每次重新构建后都要重新授权：

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate
```

IPv6 说明：链路本地源地址必须显式指定（`-src-ip fe80::2`），NDP 扫描通常需要 `-fake-router-mac`（没有可解析的 IPv6 默认网关）。IPv6 扩展头链（Hop-by-Hop、Routing、Destination Options、AH）最多解析八个头；含 Fragment、ESP 或 No Next Header 的回复对扫描器不可见。

## 速率过高与丢包

`-rate` 是线路报文速率，不是"每秒目标数"：发送端冲刷的每个报文都计数，包括接收路径产生的后续报文。不存在通用的"每秒目标数 = rate / N"公式。

- 默认 100 报文/秒，分摊到各发送线程。
- 在实验子网上从 `-rate 1000` 起步，而不是 `-rate 1000000`。
- 速率过高会表现为所有模块都缺结果，而不是报错。把速率减半再比较。
- 观察实时状态栏的队列水位和命中率，或使用 `--print-status queue`。
- `--wait <seconds>`（默认 10）让接收/处理线程在发送结束后继续存活；停得太早的扫描看起来就像丢包。
- Linux：`--raw-socket --sendmmsg`（默认批 64）可提升吞吐；慢速有状态扫描不要用。
- Windows：`--send-queue` 提升发送吞吐但增加延迟；`zbanner`/`tcp-state` 保持关闭。

## 结果存在但看不到

按顺序逐条检查：

1. **等级过滤。** 默认只显示 `success`。`tcp-syn` 把关闭端口报为 `failed`；`zbanner` 与 `udp` 以 `info` 报告端口开放/关闭。加 `-show failed` 或 `-show info`，或用模块参数提升（UDP 的 `-port-failure`，ZBanner 的 `-port-success`/`-port-failure`）。
2. **输出模块。** 用 `-output-module csv -o results.csv` 时结果只进文件。加 `--output-screen`，或在支持时写到 `-o -`。
3. **去重。** 重复的 SYN-ACK/RST/banner 报文默认被丢弃。`--no-dedup`、更大的 `-dedup-win`，或 ZBanner 的重复标志（`-scan-arg "-repeat-banner"`、`-repeat-synack`、`-repeat-ack`、`-repeat-rst`）可以让重复可见。
4. **模块级抑制。** ZBanner 在输出前抑制重复报文；基于正则的探测把不匹配的 banner 标记为 `failed`。
5. **有状态扫描从不报告关闭端口。** 未知连接的 RST 没有 TCB，会被丢弃 —— 这是设计如此。

## 看起来像出错、其实正常的行为

- **`tcp-state` 会静默丢目标。** 它只发一次 SYN，不重传。用 `--repeat 1` 重跑，或降低速率。
- **`tcp-state` 的延迟和报文数看起来奇怪。** HLTCP 使用固定 1 秒 RTO 和默认 1024 字节窗口，所以大传输会变成很多小报文。`-tcp-win 8192`（配合相应的 `--max-packet-len`）更快。
- **ZBanner 只抓第一个 banner 报文段**，然后发 RST。长 banner、多报文段 TLS ServerHello 和大 HTTP 头需要 `-scan-arg "-all-banner"`（可选 `-all-banner-limit <n>`）。
- **TLS 探测看起来是空的。** `tls-state` 以 `info` 报告握手失败；它默认不发 SNI、不发 ALPN，所以虚拟主机和 CDN 可能用默认证书/站点应答。用 `-show info`、`-probe-arg "-sni host -alpn h2,http/1.1"`，以及（如果想把握手失败提升出来）`-probe-arg "-fail-handshake"`。没有 SNI 时，把证据当作默认虚拟主机的，而不是所请求主机名的。
- **从 QUIC 握手猜 HTTP/3。** `quic handshake` 不是 HTTP/3 成功；只有 `http3-state` 给出 `http3` 结果才算 HTTP/3 声明。

## 模块缺失与可选依赖

可选库是编译期决定；缺库会移除模块，而不是运行时失败：

| 缺失依赖 | 缺席的模块 |
|:---|:---|
| OpenSSL | `tls-state`、`jarm`、`ssh-kex`、`quic` |
| PCRE2 | `recog`、`recog-udp`、`recog-state`、`nmap`、`nmap-udp` |
| libngtcp2 + GnuTLS | `quic-state`、`http3-state` |
| libbson / libmongoc | `bson`、`mongodb` 输出 |
| Lua | Lua 探测会列出，但启动时失败 |

对照 [快速上手](../getting-started.md) 里的依赖表检查 `--list-probe`/`--list-out`，安装开发包后重新构建。Lua 探测失败时会输出：

```text
(liblua) failed to load Lua shared library
you must install Lua library
```

安装 Lua 5.3 或 5.4（Debian/Ubuntu 上是 `liblua5.3`/`liblua5.4`）。

## HTTP/3 与 QUIC 的具体问题

`quic-state` 与 `http3-state` 只存在于找到 ngtcp2 与 GnuTLS 的构建中。如果模块缺失，那是 Windows 上的预期结果，不是打包 bug：

```bash
xtate --list-capabilities      # http3 / quic_transport / http3_reason
xtate --list-scan | grep quic-state
```

- Linux：安装 `libngtcp2-dev`、`libngtcp2-crypto-gnutls-dev` 与 `libgnutls28-dev` 后重新构建（选项是 `WITH_NGTCP2`，默认 `ON`；`-DWITH_NGTCP2=OFF` 会刻意移除这些模块）。
- Windows：`http3` 为 `false`，原因 `"HTTP/3 requires ngtcp2/GnuTLS; not built for Windows"`。目前没有受支持的 Windows 原生 MSVC 构建路径；不要试图通过复制 DLL 来"修复"。
- QUIC 扫描只得到 `open` 通常是和 TCP 相同的 Linux 防火墙问题：安装 RST/ICMP 规则。
- `http3_qpack_partial: 1` 表示响应需要动态 QPACK 表更新，而客户端没有实现；解码出的字段按设计就是不完整的。
- 来自 QUIC 的证书字段仅供参考（校验已禁用）。

## JSON/CSV 输出损坏

文本值（banner、HTTP body、TLS 字段）默认转义为 `\xNN`。这不是合法的 JSON 转义；当下游消费者需要 JSON 兼容字符串时，加 `--no-escape-char`。**不要**把 `--no-escape-char` 与 BSON/MongoDB 输出一起用 —— 那些模块自己处理二进制与转义。

CSV/NDJSON 写入器会原样输出 `classification` 与 `reason`，所以来自探测的引号或换行可能破坏记录。如果在意这一点，用 BSON 或在消费端过滤。

最后一条记录损坏通常是截断，而不是转义问题：先检查 `--max-packet-len`（默认 1514）和 `--tcp-win`，再怀疑写入器。

## Windows 说明

- 安装 **Npcap**；原始扫描要提权运行。
- 没有 `add_rules.sh` 这一步。绝不要在 Windows 上运行 Linux 防火墙脚本。
- PowerShell 7.6.7 报 `totalWidth ('-17')` 崩溃来自 PowerShell/Windows Terminal 的更新通知 bug，不是 Xtate。关闭更新检查并重开每个 PowerShell 窗口：

  ```powershell
  setx POWERSHELL_UPDATECHECK Off
  ```

- `--lang zh` 不会修改控制台代码页；Xtate 通过 `WriteConsoleW` 写出 Unicode 帮助。

## 报告 bug

按这个顺序附上：

1. 命令行，从 `--echo` 的输出开始（不要转述）；
2. `xtate --version`（构建类型、编译器、日期）；
3. `-d` 或 `-dd` 级别的日志；
4. 涉及报文时，附 `--pcap` 抓到的接收流量；
5. 确切的目标/端口与观测到的 classification/reason；
6. 路由/网卡/fake-IP 问题时，附 `--explain-target` 输出。

不要附上无关的生产抓包、token 或凭据。如果问题涉及控制面，附上请求/响应行（去掉 token）与 job 状态。

另见：

- [05 · 扫描模式](../scanning-modes.md) 了解每个引擎应做什么
- [防火墙](../firewall.md)、[TUN/VPN 与链路类型](../platform-support.md)
- [已知限制](../known-limitations.md)
- [07 · 协议与 HTTP/3](./07-protocols-and-http3.md) 了解探测级限制
- [08 · 架构与安全](./08-architecture-and-security.md) 了解 token、授权与守护进程边界
