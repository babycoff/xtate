# 07 · 协议与 HTTP/3

[English](../../manual/07-protocols-and-http3.md) · **中文**

本章解释 Xtate 如何探测应用层协议、目前实现了什么，以及 HTTP/3 与 QUIC 路径与扫描器其余部分有何不同。它是实验工作中常见协议问题的参考：该用哪个探测、探测实际发送什么、结果字段意味着什么，以及哪些部分被刻意排除在范围之外。

简版：

- 每个协议都是一个**探测模块**。探测有类型（`tcp`、`udp` 或 `state`），必须与能讲该类型的扫描引擎配对。
- HTTP/1.1 和 HTTP/2 在 Linux 与 Windows 上都可用。
- HTTP/3 和 QUIC 传输层**仅限 Linux**，只在存在 ngtcp2 和 GnuTLS 时构建。Windows 保留能力探测，并把传输报告为不支持。
- `--list-capabilities` 是"这个构建有没有 QUIC 传输？"的机器可读答案 —— 用它，而不是从模块列表猜测。

## 协议探测如何选择

扫描命令总是用 `-scan` 选择一个扫描引擎。承载应用数据的引擎还需要用 `-probe` 选择探测：

```bash
xtate -ip <targets> -p <ports> -scan <engine> [-probe <probe>] [args]
```

配对会在启动时检查。探测声明三种类型之一：

| 探测类型 | 配对引擎 | 交换形态 |
|:---|:---|:---|
| `tcp` | `zbanner`（以及无状态 TCP 扫描） | 一个请求、一个回复，无每目标状态 |
| `udp` | `udp` | 一个数据报请求、一个数据报回复 |
| `state` | `tcp-state`（HLTCP） | 带用户态 TCB 的完整 TCP/TLS 会话 |

不匹配是启动错误，不是静默回退：`ScanModule <name> needs probe of <type> type.`。用 `--list-probe` 查看每个探测的类型，用 `--help-probe <name>` 查看该探测接受的参数。探测专用参数以一个带引号的字符串传递：

```bash
-probe-arg "--sni example.com --alpn h2,http/1.1"
```

协议感知的探测除了原始字节，还会发出**结构化字段**（版本、所选算法、状态码、服务器身份）。通用的 `null` 和 `hello` 探测不是协议感知的：它们只抓字节并归类响应，仅此而已。

## 覆盖一览

表中列出本代码树中有专用探测的协议。完整的生成模块参考见第 06 章；深入的协议矩阵在[协议覆盖计划](../protocol-coverage.md)。

| 协议 | 探测 | 类型 | 备注 |
|:---|:---|:---|:---|
| HTTP/1.1 | `http`、`http-state` | `tcp`、`state` | 结构化状态/头部/正文元数据；有状态变体在 HLTCP 内 |
| HTTP/2 | `h2c`、`h2` | `tcp`、`state` | `h2c` 是明文 prior knowledge；`h2` 在 `tls-state` 内以 ALPN `h2` 运行 |
| HTTP/3 | `quic-state`（扫描）上的 `http3-state`（探测） | `state` | 仅 Linux + ngtcp2/GnuTLS |
| QUIC 传输 | `quic`（能力）、`quic-state`（传输） | `udp`、`state` | `quic` 分类服务器的 Initial 响应；`quic-state` 完成握手 |
| TLS | `tls-state`、`tls-hello` | `state`、`tcp` | 证书、ALPN、SNI、版本、密码套件 |
| JARM | `jarm` | `tcp` | Salesforce 1.0 TLS 指纹 |
| DNS | `dns` | `udp` | UDP 上的明文 DNS |
| DoT | `dot` | `state` | 在 `tls-state` 内，ALPN `dot` |
| DoH | `doh`、`doh-h2` | `state` | 在 `tls-state` 内的 HTTP/1.1 或 HTTP/2 |
| SSH | `ssh`、`ssh-kex` | `tcp`、`state` | banner/软件；未认证的 curve25519 KEX |
| SMTP/IMAP/POP3/FTP/ManageSieve | `*-state` | `state` | 明文或 TLS 后的流程 |
| 数据库与服务 | `mysql`、`postgres`、`mongodb`、`redis`、`memcached`、`mqtt`、`socks5`、`telnet`、`ntp`、`ipp`、`amqp`、`pptp` | `tcp`/`udp`/`state` | 仅识别 |

`tls-hello` 是无状态探测，读取 ServerHello 而不完成握手。它适合快速检查版本/密码套件，但无法产生证书或 ALPN 决定。

## HTTP/1.1

两个探测覆盖 HTTP/1.x：

- **`http`** —— 无状态 `tcp` 探测。它发送一个请求并解析第一段响应。这是互联网级 banner 工作的探测。
- **`http-state`** —— 在 HLTCP 内运行的 `state` 探测。它通过真实 TCP 连接发送请求，并可通过 `tls-state` 承载 TLS。

两者共享第一次重写中加的结构化解析器：状态码、原因短语、HTTP 版本、响应头、`Content-Length`，以及有界的正文/chunked 元数据。原始字节和经典的 banner/regex 字段仍可用，因此现有工作流继续有效。

默认请求是：

```text
GET / HTTP/1.0
User-Agent: xtate/<version> <project URL>
Accept: */*
```

有用的请求参数（完整列表见 `--help-probe http`）：

| 选项 | 含义 |
|:---|:---|
| `--method` | 替换 `GET`（例如 `POST`） |
| `--url` | 替换请求路径 |
| `--version` | 替换 `HTTP/1.0` |
| `--host` | 添加 `Host` 头 |
| `--dynamic-host` | 每目标把 `Host` 设为目标 IP |
| `--user-agent` | 替换 `User-Agent` 头 |
| `--header Name:value` | 添加或替换一个头 |
| `--remove-header Name` | 移除默认头 |
| `--cookie` | 添加 `Cookie` 头 |
| `--payload` | 追加请求正文（同时添加 `Content-Length`） |
| `--no-record-status`、`--no-record-headers` | 抑制解析字段 |
| `--record-body`、`--max-body` | 记录解析后的正文，有界（默认 4096 字节） |
| `--keyword`、`--regex`、`--match-scope` | 对 `all`、`headers` 或 `body` 匹配 |

无状态 HTTP 请求如下：

```bash
xtate -ip 198.51.100.10 -p 80 -scan zbanner -probe http \
  -probe-arg "--host example.com --user-agent xtate-manual" -show info
```

同一请求走有状态连接，包括 TLS：

```bash
xtate -ip 198.51.100.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -sni example.com -alpn http/1.1 \
              -subprobe-arg '--host example.com --record-body'" -show info
```

两个限制是刻意的，而不是 bug：

- `http` 只看到一段响应。没有每目标状态，它无法重组跨段的 chunked 正文，那会违背无状态设计；它报告第一段的状态/头部和抓到的字节，而不是声称拿到完整正文。
- `http-state` 是有状态传输加 banner/分段收集，不是完整的 HTTP/1.1 会话解析器。那里可以实现有界的 chunked 解码器，并已作为后续工作跟踪，但默认不启用。

HTTP/1 请求构建仍在两个探测间重复。这是内部维护问题（修复可能在探测之间漂移），不是结果中可见的协议差异。

## HTTP/2

HTTP/2 支持刻意沿与 HTTP/1 相同的线拆分：

- **`h2c`** 是 `tcp` 探测，发送 HTTP/2 客户端 preface、可配置的 SETTINGS 帧和可选 PING，然后报告服务器的帧头、SETTINGS 条目，可选报告原始帧。它是带 prior knowledge 的明文 HTTP/2 —— 不是 TLS 上的 HTTP/2。
- **`h2`** 是 `state` 探测，在 `tls-state` *内部*使用，ALPN 为 `h2`。它在 HLTCP 中运行，发送 preface、SETTINGS 和一个最小的 HPACK 请求，然后解析 SETTINGS、HEADERS（静态表加 HPACK，包括 Huffman 编码的响应头）和 DATA。响应匹配支持同样的 keyword 与 regex 机制。

TLS 组合是显式的，因为 HLTCP 必须先完成握手并协商 `h2`，探测才能讲 HTTP/2：

```bash
xtate -ip 198.51.100.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe h2 -sni example.com -alpn h2" -show info
```

两个探测都不会静默回退到 HTTP/1。如果 ALPN 没有选中 `h2`，组合就失败；如果想把握手失败提升到 `failed` 等级，在 `tls-state` 上用 `-probe-arg "-fail-handshake"`。

## HTTP/3 与 QUIC

HTTP/3 是唯一有平台划分的协议领域，手册直接说明：

| 平台 | QUIC 传输（`quic-state`） | HTTP/3（`http3-state`） |
|:---|:---|:---|
| Linux，GCC/Clang，存在 ngtcp2 + GnuTLS | 支持 | 支持 |
| Windows，MSVC | **不支持** | **不支持** |
| Windows，MinGW/MSYS2 | 未测试，不支持 | 未测试，不支持 |

Windows 上没有原生的 ngtcp2/GnuTLS 构建路径，因此这两个模块直接从目录中缺席。能力探测和 `--list-capabilities` 会明确报告这一点，而不是稍后以令人困惑的模块错误失败。

### QUIC 路径如何构建

`quic-state` 是有状态传输扫描器，不是浏览器 QUIC 协议栈。Xtate 自己收发原始 IPv4/IPv6 UDP；**ngtcp2** 负责 QUIC 报文状态；**GnuTLS** 提供 TLS 1.3。Xtate 保留测量相关的部分：源端口、L3/L4 头部、节奏、流预算、定时器和输出。流水线是：

```text
target/source tuple
  -> ngtcp2_conn_writev_stream()      (QUIC UDP payload)
  -> udp_create_packet()              (IPv4/IPv6 + UDP + Ethernet)
  -> raw socket / NetStack
  -> pcap receive -> strip IP/UDP
  -> ngtcp2_conn_read_pkt()           (TLS handshake, certificate)
  -> state sub-probe (http3-state)
```

流表有界，且在第一个里程碑中由一把全局互斥锁保护。把 `quic-state` 视为正确性优先的传输：它还称不上高速率基准目标。

Debian/Ubuntu 主机上的构建依赖：

```bash
sudo apt install libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev
./build.sh --compiler gcc --config release
```

`WITH_NGTCP2` 默认为 `ON`。用 `-DWITH_NGTCP2=OFF` 配置可移除这些模块；当 ngtcp2/GnuTLS 或 pkg-config 缺失时，它们也会缺席。没有这些包的正常构建完全受支持 —— 只是不注册 `quic-state`/`http3-state`。

### 使用 `quic-state` 与 `http3-state`

确认模块存在：

```bash
xtate --list-scan | grep quic-state
```

对 QUIC 端点做只取证书的探测：

```bash
sudo xtate -ip 192.0.2.10 -p U:443 -scan quic-state -probe close-state \
  -scan-arg "--sni example.com" -show info
```

完整的 HTTP/3 请求：

```bash
sudo xtate -ip 192.0.2.10 -p U:443 -scan quic-state -probe http3-state \
  -scan-arg "--alpn h3" -probe-arg "--path / --authority example.com" \
  --wait 5 --no-status -show info
```

`quic-state` 的关键选项（`--help-scan quic-state`）：

| 选项 | 含义 |
|:---|:---|
| `--alpn` | ALPN 列表；默认 `h3`，使用第一个 token |
| `--sni` | TLS 服务器名；默认无 |
| `--max-flows` | 最大并发流数（默认 100000） |
| `--flow-timeout` | 流超时秒数（默认 30） |
| `--max-udp-payload` | 通告的最大 UDP 载荷，1200–65527（默认 1200） |
| `--handshake-timeout` | 握手中超时秒数（默认 10） |
| `--initial-rtt` | 初始 RTT 估计，例如 `100ms` |
| `--max-data`、`--max-stream-data`、`--max-streams` | 流控限制 |
| `--idle-timeout` | 空闲超时毫秒数 |
| `--cc-algo` | 拥塞控制：`reno`、`cubic`、`bbr` 或 `bbr2` |
| `--no-cert` | 跳过证书抓取 |

`http3-state` 接受 `--path`、`--authority`、`--method`、`--header`、`--content-type`、`--data`、`--data-file`、`--max-body`、`--max-headers`、`--record-body` 和 `--record-headers`。匹配使用标准的 `--keyword`/`--regex` 加 `--match-scope all|headers|body`。

成功 QUIC 握手后的输出字段：

```text
quic_version  quic_tls_version  quic_alpn
quic_cert_subject  quic_cert_issuer  quic_cert_sha256
```

HTTP/3 请求后的字段：

```text
http3_status  http3_header_count  http3_body_len  http3_body_total
http3_header_<n>_name / http3_header_<n>_value
http3_content_type  http3_server  http3_location
```

证书验证被刻意禁用：证书是关于端点的证据，不是信任决定。也没有基于 SNI 的主机名校验，因此请把这些字段读作对端所呈现内容的观察。

### QUIC 与 HTTP/3 限制

这些是当前边界，不是路线图承诺：

- 仅 QUIC **版本 1**。
- 没有 0-RTT、会话恢复、连接迁移或多路径。
- 每目标一个连接；没有跨连接的后续。
- HTTP/3 支持可配置的方法、请求头/正文、Huffman QPACK 字符串字面量和完整的 QPACK 静态表。
- 动态 QPACK 表更新、服务器推送、服务器发起的流和 HTTP/3 CONNECT 未实现。需要动态插入的响应会标记 `http3_qpack_partial: 1`，而不是被静默误解码。
- 尚无 QUIC 上的 DNS（DoQ），也没有 HTTP/3 上的 DoH。
- 仅 QUIC 握手响应不等于 HTTP/3 成功；分类会区分 `quic handshake` 与 `http3`。
- Windows（MSVC）明确不支持；不要把 `quic-state` 的缺席当作打包 bug。

## 用 `--list-capabilities` 报告能力

任何需要知道二进制能做什么的客户端都应该问它：

```bash
xtate --list-capabilities
```

该命令打印一个 JSON 对象并以 `0` 退出，不启动扫描。对象报告构建的平台、原始套接字是否可用、QUIC 传输与 HTTP/3 是否编译进来、不可用时的原因，以及模块计数。节选结构（版本和计数因构建而异）：

```json
{
  "version": "<build version>",
  "platform": "linux",
  "raw_sockets": true,
  "http3": true,
  "quic_transport": true,
  "http3_reason": null,
  "modules": "<scan/probe/output/generate counts>"
}
```

（真实对象有一个 `modules` 对象，含四个数字成员；此处节选是因为模块增加时计数会变。）

传输未编译进来时，两个布尔值都是 `false`，`http3_reason` 是字符串：

- Windows：`"HTTP/3 requires ngtcp2/GnuTLS; not built for Windows"`
- 其他平台：`"HTTP/3 requires ngtcp2/GnuTLS; not present in this build"`

请用 `platform` 和 `http3`/`quic_transport`，而不是从 `--list-scan` 输出推断支持：模块可能因多种原因缺席，而能力对象直接说明构建决策。如果模块目录无法读取，命令会以 `xtate: cannot read module catalog` 和非零退出失败，而不是打印部分对象。

`raw_sockets` 目前在所有受支持的构建上都报告为 `true`；使用原始套接字仍需第 01 章所述的操作系统权限。

## DNS over TLS 与 DNS over HTTPS

DoT 和 DoH 是 **state 子探测**：TLS 由 `tls-state` 拥有，子探测只讲 TLS 通道内的 DNS 映射。

```text
DoT:  tcp-state -> tls-state (ALPN dot)      -> dot
DoH:  tcp-state -> tls-state (ALPN http/1.1) -> doh
      tcp-state -> tls-state (ALPN h2)       -> doh-h2
```

DNS over TLS（`dot`，RFC 7858）发送一个带长度前缀的 DNS 查询并解析响应：

```bash
sudo xtate -ip 203.0.113.10 -p 853 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe dot -alpn dot -sni dns.example \
              -subprobe-arg '--req-name=example.com --dnssec'" -show info
```

选项：`--req-name`（必需）、`--req-type`（默认 `A`）、`--recursive-desired`、`--dnssec`（EDNS0 DO=1）、`--edns-size`（默认 1232）。输出：`dot_dns_len`、`dot_rcode`、`dot_ad`、`dot_answer`、`dot_rrsig_count`、`dot_dnskey_count`、`dot_ds_count`、`dot_nsec_count`、`dot_dnssec_present`。

DNS over HTTPS（HTTP/1.1 用 `doh`，HTTP/2 用 `doh-h2` —— 常见的公网部署）把原始 DNS 消息作为 HTTP 正文承载；没有 2 字节长度前缀：

```bash
sudo xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe doh-h2 -alpn h2 -sni dns.example \
              -subprobe-arg '--dns-name=example.com --authority=dns.example \
                             --path=/dns-query'" -show info
```

`doh` 选项：`--req-name`、`--req-type`、`--doh-path`（默认 `/dns-query`）、`--doh-host`、`--dnssec`、`--edns-size`。`doh-h2` 使用 `--dns-name`、`--dns-type`、`--path`、`--authority` 和 `--dnssec`。输出字段与 DoT 对应，但前缀为 `doh_`，另有 `doh_status` 和 `doh_content_type`。

两者的注意事项：

- `-alpn` 值必须与你要的传输匹配。不协商 `dot`、`http/1.1` 或 `h2` 的服务器会在子探测运行前失败。
- `*_dnssec_present` 是部署证据（观察到 RRSIG/DNSKEY/DS/NSEC 记录），不是经验证的 DNSSEC 链。
- 每连接只发送一个查询/响应。
- 在 Linux 上，这一切完成之前都需要 RST/ICMP 抑制规则；见 [09 · 故障排查](./09-troubleshooting.md)。

## 有状态 TLS 与 STARTTLS 组合

`tls-state` 不是应用探测。它是 HLTCP 内的 TLS 中间层：

```text
tcp-state -> tls-state -> state sub-probe inside TLS
```

存在两种组合模式：

- **隐式 TLS** —— 服务器立即讲 TLS（SMTPS 465、IMAPS 993、POP3S 995、FTPS 990、MySQL/PostgreSQL/MongoDB 的 TLS 端口，或任何 TLS 服务）：`tls-state` 完成握手并在 TLS 内启动子探测。
- **STARTTLS** —— 连接以明文开始再升级（SMTP `EHLO`/`STARTTLS`、IMAP `STARTTLS`、POP3 `STLS`、FTP `AUTH TLS`、ManageSieve `STARTTLS`、PostgreSQL `SSLRequest`）。`tls-state` 消费明文问候与升级响应；子探测在握手之后启动。

子探测 flag `--after-tls` **不**启用 TLS。它告诉子探测的状态机：明文问候已经发生过（或已经身处 TLS 内），跳过该阶段：

```bash
# STARTTLS SMTP: tls-state handles the plaintext upgrade, then SMTP state runs
sudo xtate -ip 203.0.113.10 -p 25 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe smtp-state --starttls smtp \
              -subprobe-arg --after-tls -sni mail.example" -show info
```

不要在明文直连扫描中传 `--after-tls`：它会跳过真实的服务器问候，探测会失败或误解析。`mysql-state --after-tls` 和 `managesieve-state --after-tls` 是实验/兼容性唤醒手段，不是标准握手；严格的服务器可能拒绝它们。

`tls-state` 参数包括 `--sni`、`--alpn`、`--version`、`--cipher`、`--starttls <proto>`、`--subprobe <name>`、`--subprobe-arg "<args>"`、`--dump-cert`、`--dump-cert-details`、`--dump-subject`、`--dump-version`、`--dump-cipher`、`--fail-handshake`、`--graceful-tls-close` 和 `--ssl-keylog`。证书细节是证据；扫描器不判断证书是否可信。

两个实用说明：

- `tls-state` **默认不发送 SNI，也不发送 ALPN**。虚拟主机和 CDN 常常用默认证书/站点应答。知道主机名时传 `--sni`，并传你真正想要的 ALPN（`h2,http/1.1`、`dot` 等）。没有 SNI 时，把结果读作"默认虚拟主机"，而不是所请求的主机名。
- `tls-state` 没有可用的默认子探测。始终传 `-subprobe` 加一个 state 类型探测，否则 TLS 会话会立即结束。

## 原始套接字、链路类型、TUN 与 fake-IP

Xtate 从原始套接字发送（`raw_sockets: true`）。这使无状态握手和 HLTCP 成为可能，也是 Linux 需要防火墙规则、Windows 需要管理员权限的 Npcap 的原因。

接收路径接受三种 pcap 链路类型：

| 链路类型 | 头部 | 后果 |
|:---|:---|:---|
| `EN10MB`（Ethernet） | 以太网 | 正常 MAC/ARP；首选情形 |
| `NULL` | BSD 回环 | 回环抓包 |
| `RAW` | 原始 IP | 无以太网头、无 MAC、无 ARP |

TUN/VPN 网卡通常发布 `198.18.0.0/15`（RFC 2544 基准测试范围），并用假地址应答 DNS。Xtate 仍然扫描给它的内容，因此先解析真实地址（例如通过 `--doh` 或隧道外的解析器），再用 `--explain-target` 检查所选路由和链路类型：

```bash
xtate --explain-target=203.0.113.10 --check
```

预检会打印网卡、链路类型、源地址和网关，并在链路类型无法承载 IP 扫描时告警。`RAW` 链路会被接受，但可能静默失败：没有 MAC/ARP 就没有 L2 解析，某些隧道驱动还会改写或丢弃报文。看到 `UNSUPPORTED` 链路类型时，用 `-if` 显式选择物理以太网/Wi-Fi 网卡。

当前二进制的发布说明更详细地描述了 `RAW` 链路类型报告；见 [发布说明 2.44.2](../release-notes/2.44.2.md)。

## 本章不承诺什么

有几个边界值得重复，以免被误认为构建缺口：

- HTTP/3 和 QUIC 传输仅限 Linux。Windows 上的答案是 `http3: false` 和明确原因，而不是偷偷经 TCP 重试。
- 没有 QUIC 上的 DNS（DoQ），也没有 HTTP/3 上的 DoH。
- HTTP/1 解析器冻结在当前结构化解析阶段；完整的 chunked HTTP/1.1 会话解析器属于后续工作，无状态探测从不跨段重组正文。
- 原始字节输出始终可用；协议结论来自结构化字段和分类，而不是 banner 文本。
- 这里没有任何内容绕过授权、速率限制或防火墙前提。

另见：

- [05 · 扫描模式](../scanning-modes.md)（引擎与探测的深入参考）
- [协议覆盖计划](../protocol-coverage.md)
- [QUIC 状态](../quic-state.md)、[DoT](../dns-over-tls.md)、
  [DoH](../dns-over-https.md)、[TLS 组合](../tls-composition.md)
- [HTTP 探测审计](../http-probes-audit.md) 了解解析器范围
- [08 · 架构与安全](./08-architecture-and-security.md) 了解各部分如何拼合
- 协议探测只返回 `open` 时见 [09 · 故障排查](./09-troubleshooting.md)
