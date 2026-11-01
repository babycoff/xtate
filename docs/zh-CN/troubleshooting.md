# 故障排查

[English](../troubleshooting.md) · **中文**

大多数 Xtate 问题都出在五件事上：网卡或源地址选错、报文过滤器把回包吃掉了、内核重置了它不认识的连接、速率超出了链路承受能力，或者结果其实已经产生却没有被打印出来。

请按顺序检查下面的小节；每一节都给出可执行的命令，用来确认或排除某个原因。

## 先拿到更多诊断信息

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 443 -scan tcp-syn -rate 100 -show info -show failed -d
```

- `-d`、`-dd`、`-ddd` 会把日志等级从默认（错误、警告、提示）依次提升到 info、debug、detail。日志和实时状态栏写到 **stderr**，结果写到 **stdout**。
- `--echo` 打印生效的配置（只列与默认值不同的项）后退出——适合确认参数到底有没有被解析。
- `--packet-trace` 把每个 SENT/RCVD 报文（地址、端口、TCP flags）打印到 **stdout**，与结果混在一起。配合 `--offline`（不真正发包）和很低的 `-rate 1`，可以在不碰网络的情况下检查报文构造。
- `--pcap capture.pcap` 保存**收到**的报文（不含发出的报文）；用 Wireshark 打开即可。
- `./firewall/check_rules.sh` 显示当前 `iptables`/`ip6tables` 的 OUTPUT 规则。

继续往下读之前，可以先做一轮快速排查：

| 现象 | 最可能的原因 |
|:---|:---|
| 完全没有输出，进程立即退出 | 模块/探测配对缺失或类型不匹配、目标列表为空、网卡不对 |
| 部分目标有回应，部分没有 | 速率过高、路径上的限速/防火墙、NAT |
| 发现开放端口但 banner 始终不来 | 内核 RST、缺少防火墙规则 |
| 文件里有结果，屏幕上却没有 | 选择了输出模块、等级被过滤 |
| 什么都收不到，也没有报错 | BPF 过滤器、`-src-ip`/`-src-port` 有误、网卡不对 |

## 完全没有回包

按下面的顺序检查：

1. **模块配对。** 配对错误时 Xtate 会拒绝启动并提示 `ScanModule <x> needs probe of <type> type.`；`tcp-syn` 不需要探测模块，`zbanner` 需要 TCP 类型的探测模块，`udp` 需要 UDP 类型，`tcp-state` 需要 STATE 类型。用 `--list-scan` / `--list-probe` 确认名称，用 `--help-scan <module>` 查看参数。
2. **目标和端口非空。** 没有目标会报 `target IP address list empty.`；没有端口只会给出一条警告并塞入一个假的 `o:0` 端点，于是 TCP 扫描悄无声息地什么都不探测。务必传入 `-p`。
3. **网卡与源地址。** `sudo ./bin/xtate --list-if` 列出网卡；自动选择会挑第一个带默认网关的接口。用 `-if eth0` 指定（Windows 上也可以直接用 `--list-if` 打印的数字编号，例如 `-if 3`）。`-src-ip`/`-src-port` 配错会让回包过不了 `is_my_ip`/`is_my_port` 检查而被静默丢弃；源地址/源端口区间的大小必须是 2 的幂。
4. **报文过滤器。** 每个扫描模块都会装自己的 BPF 过滤器；`--bpf-filter` 会*替换*它，范围过窄的过滤器会藏掉有效回包。用 `--no-bpf` 重跑同一条扫描——如果结果出现了，问题就在过滤器（你的或模块的）。一个已知案例：内置的 `tcp-syn` 过滤器精确匹配裸 RST，因此用 RST+ACK 回应关闭端口的那类协议栈，其回包可能在 Xtate 看到之前就被滤掉；用 `--no-bpf` 可以确认。
5. **路由器 MAC / ARP。** 启动时可能失败并提示 `arp timed-out resolving MAC address for router ...`。如果探测到的网关不对，用 `--router-ip <gw>` 指定；或者用 `--router-mac 66-55-44-33-22-11` 跳过 ARP（把路由器 MAC 指到另一个二层网段，只有在配合 `--lan` 时才有意义）。注意：`--lan` **不会**解析每个目标的 MAC，它只是把路由器 MAC 设为广播地址；不要把 `--lan` 当作普通 TCP/UDP 扫描的通用修复，先试默认的单播/网关路径。
6. **路径本身。** 先用普通客户端确认目标到底回不回应；再用 `tcpdump` 或 Xtate 的 `--pcap` 镜像同样的端口/速率。目标前面的防火墙或 NAT 可能把探测包丢掉，导致 SYN-ACK 永远不回来。

## 端口开放但拿不到 banner，或连接立刻断开

这是典型的内核 RST 症状。内核看到属于某条它并不认识的 TCP 连接的回包，就发出 RST；服务器在载荷/banner 交换完成之前就把连接拆掉了。

测试并修复：

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http -scan-arg "-banner" -rate 500
./firewall/rm_rules.sh
```

- 如果 banner 出现了，说明问题就出在内核。脚本会 DROP 本机出向的 TCP RST（IPv4 与 IPv6），以及 ICMP 端口不可达（ICMP 3/3 与 ICMPv6 1/4）。
- 这些规则是主机全局的：生效期间，本机发出的所有 RST 都会被丢弃，无关的本地连接也会被连带影响。绝不长期保留。
- UDP 扫描存在同样的干扰，只是走的是 ICMP 端口不可达，这也是脚本要一并丢弃它的原因。
- Windows 上没有随仓库提供的脚本；同样因为上述原因，基于握手的 banner 扫描在 Windows 上并不可靠。

## 权限、网卡与平台错误

| 报错信息 | 原因与处理 |
|:---|:---|
| `need to sudo or run as root or administrator` / `can't open adapter` | 原始套接字需要权限；Linux 用 `sudo`，Windows 用管理员权限的终端 |
| `could not determine default interface` | 看不到默认网关；用 `-if <name>` 指定 |
| `failed to detect IP of interface` | 网卡上没有可用 IP；手动设置 `-src-ip` |
| `(libpcap) failed to load` / `couldn't load wpcap.dll` | Linux 上缺少 libpcap；Windows 上缺少 Npcap |
| `no pfring adapter available. Please install pfring or run xtate without the --pfring option.` | 你强制指定了 `--pfring`；去掉该开关回落到 pcap |
| `(pfring) 'pf_ring' driver module not found!!!` | 只是提示信息，除非你传了 `--pfring` |

Linux 上，`sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate` 可以免去每次运行的 `sudo`；重新构建二进制后需要重新执行。

IPv6 有自己的坑：链路本地源地址必须显式给出（`-src-ip fe80::2`）；NDP 扫描通常需要 `-fake-router-mac`，因为不存在可解析的 IPv6 默认网关——`-scan ndp-ns -src-ip fe80::2 -fake-router-mac` 是能跑通的形态。IPv6 扩展头（逐跳头之外）和分片不会被解析，带这类头的回包对扫描器不可见。

## 抓包、PF_RING 与 Npcap

- `--pcap out.pcap` 只记录**收到**的帧；发出的报文不会进文件。如果想知道 Xtate 发了什么，用 `--packet-trace`。
- 抓包同样受 `--max-packet-len`（默认 1514）限制。面对巨帧、VLAN 或多 KB 的 TLS 记录时，要同时调大 `--max-packet-len` 和 `--adapter-snaplen`（默认 65535）。
- PF_RING 通过运行时加载 `libpfring.so`，并对 DNA 风格网卡名自动启用。库缺失时只会有一条 debug 级消息，Xtate 回落到 libpcap；关于 `pf_ring` 驱动模块的那条 `ERROR` 只要没传 `--pfring` 就无害。
- 在没有可用 DNA 网卡时强制 `--pfring` 会在启动阶段失败；去掉该开关即可回落到 libpcap。
- Windows 上，网卡通过 Npcap 的 `wpcap.dll` 打开。缺少 Npcap 时扫描会失败并提示 `(libpcap) failed to load` / `can't open adapter: pcap`。安装 Npcap 后以管理员权限重跑。Windows 的接收走阻塞式 `pcap_next_ex`，所以即使发送跟得上，速率很高时也会丢回包——降低速率或缩小扫描范围。

## 速率过高、丢包，或目标网络吃不消

- 默认速率是 **100 包/秒**，由各 Tx 线程分摊总量。实验室网段从 `-rate 1000` 起步，不要一上来就用 `-rate 1000000`。
- 盯住状态栏：队列水位和命中率能反映 Tx/Rx 流水线是否饱和。`--print-status queue` 会把队列占用情况显式打出来。
- 速率过高的表现是所有模块都缺结果，而不是报错。把速率减半再对比；也可以先只扫一个主机、一个端口，排除范围因素。
- 对迟到回包，`--wait <seconds>`（默认 10）会在发送结束后继续保留接收/处理线程。
- Linux 上可以用 `--raw-socket --sendmmsg` 提高发包速率（sendmmsg 默认每次批量 64）。不要给缓慢的有状态扫描启用 sendmmsg——额外延迟会拖累基于连接的模块。
- Windows 上，`--send-queue` 能显著提高发送吞吐，但会增加延迟；对 `zbanner`/`tcp-state` 请保持关闭。

## 结果确实产生了，但你看不到

1. **等级被过滤。** 默认只打印 `success` 结果。`tcp-syn` 把关闭端口标为 `failed`；`zbanner` 和 `udp` 默认把端口开放/关闭结果标为 `info` 等级——可以用模块自己的参数提升（例如 `udp` 的 `-scan-arg "-port-failure"`，`zbanner` 的 `-port-success`/`-port-failure`）。加上 `-show failed` 和/或 `-show info`；用 `--no-show-output success` 反过来隐藏成功结果。
2. **输出模块与 stdout。** 不指定 `-output` 时结果只去 stdout。指定 `-output csv -o results.csv` 后结果只进文件——加 `--output-screen` 才能同时在屏幕上看到，或者在模块支持 stdout 时用 `-o -`。
3. **去重。** 重复的 SYN-ACK/RST/banner 报文默认会被丢弃。可以试 `--no-dedup`、调大 `-dedup-win`，或者针对 `zbanner` 显式允许重复：`-scan-arg "-repeat-banner"`（同理还有 `-repeat-synack`、`-repeat-ack`、`-repeat-rst`）。
4. **模块层面的 `no_output`。** `zbanner` 会在产生任何输出之前抑制重复报文；正则匹配失败的结果是 `failed` 等级。如果用 `-probe http -probe-arg "--regex <pattern>"` 扫描，不匹配的 banner 在没加 `-show failed` 时不会出现。
5. **有状态扫描不报告关闭端口。** `tcp-state` 只会为能建立起来的连接产生输出（见下一节）。

## 看起来不对、其实符合预期的行为

- **`tcp-state` 永远不报告关闭端口。** 未知连接的 RST 没有对应 TCB，会被直接丢弃；只有能完成握手的开放目标才会产生结果。
- **`tcp-state` 会悄悄丢目标。** SYN 只发一次且不重传；SYN 丢了就意味着该目标没有结果。重跑该范围（例如 `--repeat 1`）或降低速率。
- **`tcp-state` 的延迟和报文数看着奇怪。** HLTCP 使用固定 1 秒的 RTO，默认 TCP 窗口只有 1024 字节，会产生大量小包。`-tcp-win 8192`（同时把 `--max-packet-len` 调到匹配的大小）通常更快。
- **`zbanner` 把零窗口 SYN-ACK 判成 `fake-open`**（`because "zerowin"`），并且不会发送探测载荷。这是 SYN 队列/防火墙的信号，不一定是端口关闭。
- **`zbanner` 默认只取第一个 banner 报文段**，随后发 RST。长 banner、多段 TLS ServerHello 或很长的 HTTP 头需要 `-scan-arg "-all-banner"`（可在同一个字符串里用 `-all-banner-limit <n>` 限制段数）。
- **TLS 探测看起来没有返回。** `tls-state` 把握手失败记为 `info` 等级；默认也不发送 SNI 或 ALPN，所以虚拟主机/CDN 可能用默认证书/默认站点应答。加上 `-show info`；当目标 IP 属于一个已知 vhost 时，用 `-probe-arg "-sni <hostname> -alpn h2,http/1.1"`；或用 `-probe-arg "-fail-handshake"` 把失败提升为 `failed`。没有显式 SNI 时，请把有状态 TLS 的结果当作默认虚拟主机的证据，而不是你所请求主机名的证据。

这些是 v2.20.2 的设计取舍，不是 bug；完整清单与规避方式见[已知限制](./known-limitations.md)。

## 模块缺失或启动失败

- 编译期的可选依赖会直接移除模块：没有 OpenSSL 就没有 `tls-state`/`jarm`，没有 PCRE2 就没有 `recog`/`nmap`，没有 libbson/libmongoc 就没有 `bson`/`mongodb` 输出。对照[快速上手](./getting-started.md)里的依赖表检查 `--list-probe` / `--list-out`，安装对应开发包后重新构建。
- Lua 探测模块始终会出现在列表里，但运行时库缺失时会在启动阶段失败：`(liblua) failed to load Lua shared library` / `you must install Lua library`。安装 Lua 5.3 或 5.4（Debian/Ubuntu 上是 `liblua5.3`/`liblua5.4`），或者改用非 Lua 探测模块。
- `--version` 会打印构建类型、编译器与构建日期——报 bug 时请一并附上。

## JSON 或 CSV 输出损坏

- 文本值（banner、HTTP 响应体、TLS 字段）默认转义成 `\xNN`，这**不是**合法的 JSON 转义。加上 `--no-escape-char` 才能得到 JSON 兼容的字符串。
- 不要对 BSON/MongoDB 输出使用 `--no-escape-char`；这些模块自己会处理二进制与转义。
- `classification` 和 `reason` 由 CSV/NDJSON 写出器原样输出；来自探测模块的引号或换行可能破坏一条记录。遇到这种情况，改用 BSON，或者在下游对数据做过滤。
- JSON 记录损坏往往是截断问题而不是转义问题：先检查 `--max-packet-len` 和 `--tcp-win`，再怀疑写出逻辑。

## 报 bug 时需要提供什么

命令行（从 `--echo` 的输出开始）、`--version`、`-d`/`-dd` 级别的日志、一份收到流量的 `--pcap` 抓包，以及出问题的确切目标/端口。请不要附上无关的生产环境抓包。
