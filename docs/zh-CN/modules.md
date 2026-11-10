# 模块

[English](../modules.md) · **中文**

Xtate 由四类模块拼装而成。每一类都是一个 C 结构体，加上以 `NULL` 结尾的注册表里的一行；没有运行期插件加载。完整构建会注册 **11 个基础扫描 + 55 个探测 + 7 个输出 + 5 个生成**模块；另有可选的 `quic-state` 和 `http3-state`（需要 ngtcp2/GnuTLS）。缺少可选库的模块会直接从构建中消失（也从 `--list-*` 中消失）。

| 类别 | 职责 | 参数 | 注册表 |
|:---|:---|:---|:---|
| 扫描 | L3/L4 报文、接收校验、后续报文 | `-scan` / `--scan-module` | `src/scan-modules/scan-modules.c` |
| 探测 | L5+ 载荷与响应解析器、嵌套子探测 | `-probe` / `--probe-module` | `src/probe-modules/probe-modules.c` |
| 输出 | 结果的格式化与落点 | `-output-module` | `src/output-modules/output-modules.c` |
| 生成 | `(target, port)` 对的枚举与排列 | `-generate-module` | `src/generate-modules/generate-modules.c` |

扫描模块是必需的，生成模块默认是 `blackrock`，探测模块只在扫描模块声明需要时才必需（并会做类型检查）。模块子参数以单个带引号字符串的形式，通过 `-scan-arg`、`-probe-arg`、`-output-arg` 和 `-gen-arg` 传递（主名分别为 `-scan-module-args`、`-probe-module-args`、`-output-module-args`、`-generate-module-args`）。

```bash
xtate --list-scan      # 11，若有 quic-state 则为 12
xtate --list-probe     # 55 个探测模块
xtate --list-out       # 7 个输出模块
xtate --list-gen       # 5 个生成模块

xtate --help-scan zbanner
xtate --help-probe tls-state
xtate --help-output mongodb
xtate --help-gen blackrock
```

## 扫描模块（11，另有可选 `quic-state`）

| 模块 | 探测 | 功能 |
|:---|:---:|:---|
| `tcp-syn` | - | SYN 扫描；收到 SYN-ACK 即 open，收到 RST 即 closed。可选 `--send-rst`、`--fail-zerowin`。 |
| `zbanner` | tcp | 无状态 TCP 握手；载荷搭在第三个 ACK 上；首个 banner 由探测模块解析。 |
| `tcp-state` | state | HLTCP 用户态 TCP；为 TLS/HTTP 状态探测模块提供完整会话。 |
| `udp` | udp | 携带探测载荷的单包 UDP 扫描；ICMP port-unreachable 表示 closed。 |
| `quic-state` | state | 原始 UDP + ngtcp2/GnuTLS 的有状态 QUIC 握手；输出版本、TLS/ALPN、证书字段并运行 state 子探测。可选构建。 |
| `http3-state` | state | `quic-state` 之上的 HTTP/3 请求；方法/header/body、Huffman QPACK 字符串、完整 static table、结构化响应 header。可选构建。 |
| `icmp-echo` | - | ICMP echo 主机发现；可记录 TTL 和 IPID。 |
| `icmp-time` | - | ICMP 时间戳发现，仅 IPv4。 |
| `sctp-init` | - | SCTP INIT 扫描；INIT-ACK 为 open，ABORT 为 closed。 |
| `arp-req` | - | 局域网模式下的二层 ARP 扫描；报告 MAC 地址。仅 IPv4。 |
| `ndp-ns` | - | IPv6 邻居请求；报告 MAC 地址。 |
| `yarrp-echo` | - | 用 ICMP echo 做无状态 traceroute；TTL 范围通过 `o:` 端口表示。 |
| `yarrp-udp` | - | 用 UDP 和 ICMP 错误报文做无状态 traceroute；TTL 装在端口里。 |

每个扫描模块都通过 `--help-scan <name>` 暴露自己的选项（记录 TTL/IPID/窗口、重复/去重开关、TTL 覆盖等）。如何选择模式、哪些模式需要防火墙规则，见[扫描模式](./scanning-modes.md)。

## 探测模块（27，另有可选 `http3-state`）

探测模块会声明一个**类型**，必须与扫描模块匹配：`zbanner` 用 `tcp`，`udp` 用 `udp`，`tcp-state` 用 `state`。它可以声明 `ProbeSlotPlan`（JARM 和 `slot-test` 示例）；见[扫描模式](./scanning-modes.md#探测-slot)。

### ProbeSlotPlan（多 slot 探测）

大多数探测模块是单 flow，省略 slot plan。需要多个独立伪连接的探测模块在
`Probe` 中声明 `ProbeSlotPlan`：

```c
typedef struct ProbeSlotPlan {
    unsigned             count;       /* 0 或 1 = 单 flow；JARM 用 10 */
    ProbeSlotTrigger     trigger;     /* None、Always、AfterFirstReply */
    probe_slots_continue continue_cb; /* 可选 */
} ProbeSlotPlan;
```

- 引擎把 slot `i` 映射到 `source_port_start + i`；`ProbeTarget.index` 是
  从 0 开始的 slot 编号。
- `Always`：从第一次扫描迭代起发送所有 slot。
- `AfterFirstReply`：slot 0 正常发送；只有 `continue_cb()` 接受第一个响应后，
  才发送剩余 slot；没有 callback 时默认继续。
- 源端口范围必须至少覆盖 plan 的 `count`，启动时会拒绝过小的范围。
- 引擎**不保存 group**，也不做聚合。每个 slot 输出自己的 `OutItem`。JARM
  输出 `jarm_slot`、`jarm_slots` 和 `jarm_part`，由
  `tools/jarm_aggregate.py` 在扫描后合并。
- 同一 TCP 连接上的多步交互不属于这里；请使用 HLTCP/state 探针。

目前只有 JARM 使用多 slot plan，但 plan 不是 JARM 专用：`Always` 适合并行
变体，`AfterFirstReply` 适合条件 fan-out。后续的协议版本变体、
challenge-response 探针可以复用同一引擎路径，不需要新增模式。

### JARM 发送顺序

`jarm` 发送 10 个 Salesforce JARM 1.0 探针。默认第一个请求是**标准探针 1**
（TLS 1.2、cipher 全量正序、ALPN 全量、supported_versions TLS 1.2、扩展逆序）。
第一个可接受的 TLS 回复到达后，其余 9 个 slot 会连续批量发出，不逐个等待回复；
因此回复到达顺序可以任意。

```bash
# 默认：1,2,3,4,5,6,7,8,9,10（slot 1 先等回复）
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe jarm

# 首选探针 7；总发送顺序是 7,8,9,10,1,2,3,4,5,6。
# 探针 7 收到回复后的批量顺序是 8,9,10,1,2,3,4,5,6。
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe jarm \
  -probe-arg "--first-probe 7"
```

- `--first-probe N` 轮换哪个标准探针获得第一个 SYN；仍然发送全部 10 个。
- `jarm_slot` 始终记录标准探针编号，不是发送位置，因此聚合与顺序无关。
- `--probe-index N` 只发一个探针，是调试用途，不能产生完整 JARM 指纹。

### QUIC 能力探测

`quic` 是 **transport 能力** UDP 探针。它构造一个合法 QUIC v1 Initial
（至少 1200 字节），带 TLS 1.3 ClientHello 和 ALPN `h3`，然后分类第一个
long-header 响应：

```bash
xtate -ip 203.0.113.10 -p U:4433 -scan udp -probe quic --show info
```

输出：

```text
quic_response          initial | handshake | retry | version-negotiation
quic_version           32-bit QUIC 版本
quic_dcid / quic_scid  十六进制 connection ID
quic_token_len         Retry/Initial token 长度
quic_payload_len       long-header payload 长度
quic_versions_count    Version Negotiation 版本数
quic_version_<n>       每个 Version Negotiation 版本
quic_raw               可选 --record-raw 原始字节
```

响应通过由无状态 UDP cookie 派生的 client SCID 匹配；不保存 per-target 状态。
成功结果只证明 QUIC transport 响应，**不证明** TLS 握手完成，也**不证明**
HTTP/3。不要把 `quic_response: initial` 标成 `http3`。

### TLS 证据、证书细节与 STARTTLS

`tls-state` 是 HLTCP 中间层，必须指定一个 `state` 子探测。证书和 TLS 字段在
握手成功后输出，与子探测之后做什么无关。

```bash
# 直接 TLS，只取证书
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe close-state --dump-cert-details" -show info

# SMTP STARTTLS，只取证书
xtate -ip 203.0.113.10 -p 25 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe close-state --starttls smtp --dump-cert-details" -show info

# TLS 内跑 HTTP
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -subprobe-arg '--all-banner'" -show info
```

`--starttls` 值与明文流程：

| 值 | 问候 | 升级命令 | 成功响应 |
|:---|:---|:---|:---|
| `smtp` | `220` | `EHLO`，然后 `STARTTLS` | `250` 然后 `220` |
| `imap` | `* OK` | `a001 STARTTLS` | `a001 OK` |
| `pop3` | `+OK` | `STLS` | `+OK` |
| `ftp` | `220` | `AUTH TLS` | `234` |

子探测生命周期：

```text
STARTTLS 明文协商
-> TLS 握手
-> 证书/cipher/version 输出
-> 子探测 conn_init
-> 子探测在 TLS 内运行
```

子探测看不到明文 STARTTLS 交换。明文协商或 TLS 握手失败时子探测不会初始化；
STARTTLS 失败输出 `starttls error`。`--dump-cert-details` 输出
`cert_subject`、`cert_issuer`、`cert_not_before`、`cert_not_after`、
`cert_serial`、`cert_signature_algorithm`、`cert_public_key`、
`cert_public_key_bits`、`cert_san`、`tls_version`、`tls_cipher` 和 `tls_alpn`。

### 通用（21）

| 探测 | 类型 | 功能 |
|:---|:---:|:---|
| `http` | tcp | 在无状态 TCP 会话上发送用户指定的 HTTP 请求。 |
| `http-state` | state | 在 HLTCP 上做同样的事，包括经 TLS。 |
| `hello` | tcp | 用户载荷（string、base64、nmap-string、file）外加可选正则。 |
| `hello-udp` | udp | UDP 版本。 |
| `hello-state` | state | 在有状态 TCP 连接上的同一功能。 |
| `tls-hello` | tcp | 固定 ClientHello；读取 ServerHello 的版本/记录层线索，但不完成握手。 |
| `tls-state` | state | OpenSSL 驱动的 TLS 握手；`--starttls smtp|imap|pop3|ftp` 先完成明文升级；导出证书/密码套件/版本；`--dump-cert-details` 增加结构化 X.509/SAN/公钥/有效期/ALPN；可在 TLS 之上跑子探测。 |
| `ssh` | tcp | 可配置 SSH banner，以及 KEX/host-key、cipher/MAC/压缩算法列表。 |
| `h2c` | tcp | cleartext h2c preface、可配置 SETTINGS/PING 指纹、帧/settings 解析；不是 TLS 上的 HTTP/2。 |
| `h2` | state | 通过 HLTCP + TLS ALPN h2 的 HTTP/2：preface、SETTINGS、最小 HPACK 请求、帧/HEADERS/DATA。 |
| `redis` | tcp | 只读 `INFO server` 识别 Redis，输出 version/mode/os/role。 |
| `memcached` | tcp | `version` 命令和版本行解析。 |
| `ntp` | udp | NTP v4 mode-3 请求、cookie 校验、leap/stratum/refid/root 字段。 |
| `mqtt` | tcp | MQTT 3.1.1 CONNECT 与 CONNACK return-code。 |
| `socks5` | state | SOCKS5 greeting 和方法选择。 |
| `telnet` | state | 初始 Telnet banner 和 IAC 选项解析。 |
| `jarm` | tcp | 通过 10 个 ClientHello slot 做 JARM；`--first-probe 1..10` 轮换哪个标准探针先发，`jarm_slot` 保留标准编号；`--probe-index` 只发一个；`jarm_part` 由 `tools/jarm_aggregate.py` 聚合。 |
| `dot` | state | `tls-state` 内的 DNS over TLS（`-alpn dot`），带 2 字节长度前缀。 |
| `dns` | udp | DNS 记录请求，可配置名称/类型/递归；`--dnssec` 发送 EDNS0 DO 并报告 DNSSEC 证据（非完整验证）。 |
| `snmp` | udp | SNMP（v1/v2c）请求，并按 MIB 提取主机信息。 |
| `echo` | udp | 四个由 cookie 派生的字节；接受包含它们的回包。 |

### Batch B 协议（15）

| Probe | Type | What it does |
|:---|:---:|:---|
| `mysql` | tcp | 读取 MySQL greeting；protocol/version/capabilities/auth plugin。 |
| `mysql-state` | state | 有状态 greeting；不认证。`--after-tls` 仅为 lab COM_PING 唤醒，不是标准握手。 |
| `postgres` | tcp | PostgreSQL SSLRequest 能力检查。 |
| `postgres-state` | state | SSLRequest + 认证边界 StartupMessage。 |
| `mongodb` | tcp | OP_MSG `hello`/BSON 识别。 |
| `smtp` | tcp | 读取 SMTP 220 banner。 |
| `smtp-state` | state | SMTP greeting + EHLO 能力/STARTTLS。 |
| `imap` | tcp | 读取 IMAP greeting。 |
| `imap-state` | state | IMAP CAPABILITY/STARTTLS。 |
| `pop3` | tcp | 读取 POP3 +OK banner。 |
| `pop3-state` | state | POP3 CAPA/STLS。 |
| `ftp` | tcp | 读取 FTP 220 banner。 |
| `ftp-state` | state | FTP FEAT/AUTH TLS。 |
| `managesieve` | tcp | 读取 ManageSieve capability greeting。 |
| `managesieve-state` | state | ManageSieve 能力/STARTTLS/SASL。`--after-tls` 仅为 lab NOOP 唤醒。 |

### Batch C 第一批（6）

| Probe | Type | What it does |
|:---|:---:|:---|
| `ipp` | tcp | IPP Get-Printer-Attributes over HTTP。 |
| `ipp-state` | state | IPP over tcp-state/TLS。 |
| `amqp` | tcp | AMQP 0-9-1 protocol header/Connection.Start。 |
| `amqp-state` | state | AMQP over tcp-state/TLS。 |
| `pptp` | tcp | PPTP SCCRQ/SCCRP。 |
| `pptp-state` | state | PPTP 控制连接。 |

### 指纹识别（5）

| 探测 | 类型 | 功能 |
|:---|:---:|:---|
| `recog` | tcp | 用 Recog XML 指纹匹配 banner。 |
| `recog-udp` | udp | UDP 版本。 |
| `recog-state` | state | 在有状态 TCP 上的同一功能。 |
| `nmap` | tcp | 运行一条 `nmap-service-probes` 探测并解析其匹配项。 |
| `nmap-udp` | udp | UDP 版本。 |

### 可脚本化（2）

| 探测 | 类型 | 功能 |
|:---|:---:|:---|
| `lua-tcp` | tcp | 加载实现 `Make_payload` / `Get_payload_length` / `Handle_response` 的 Lua 脚本。 |
| `lua-udp` | udp | UDP 版本。 |

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe lua-tcp \
  -probe-arg "-script lua-probes/tcp-example.lua" -show info
```

Lua 在运行期加载；如果没有可用的 Lua 共享库，这些探测仍会出现在列表里，但会在启动时因加载错误而失败（请安装 Lua 5.3 或 5.4）。Lua 探测使用分离的 tx/rx/handler Lua state；选中 `lua-tcp`/`lua-udp` 时当前会强制 `--tx-thread-count 1` 和 `--rx-handler-count 1`。`lua-probes/` 里的示例脚本在脚本头部声明 `ProbeName`、`ProbeType` 和 `ProbeDesc`。

### 辅助（3）

| 探测 | 类型 | 功能 |
|:---|:---:|:---|
| `null` | tcp | 不发送载荷；收到的任何数据都作为 banner 报告。 |
| `get-state` | state | 调试用探测：在有状态连接上发一个 HTTP GET。 |
| `close-state` | state | 什么都不发，立即关闭连接。 |

当扫描模块要求探测模块、而你只想要服务器的问候语时，`null` 很有用。状态探测只能配合 `-scan tcp-state` 使用；`tls-state` 还额外需要一个 `state` 类型的子探测（`-subprobe`），因为 TLS 是中间层，而不是叶子层。

## 输出模块（7）

| 模块 | 需要 `-output-file` | 说明 |
|:---|:---:|:---|
| `text` | 是 | 写入文件的 stdout 风格行 |
| `ndjson` | 是 | 每行一个 JSON 对象 |
| `bson` | 是 | 二进制 BSON 流；需要 libbson |
| `csv` | 是 | 表头加每条结果一行 |
| `list` | 是 | `ip` 和可选的 `port` |
| `mongodb` | 是 | "文件"是 MongoDB URI；需要 libmongoc |
| `null` | 否 | 丢弃结果 |

格式、等级过滤与转义见[输出](./output.md)。

## 生成模块（5）

| 模块 | 输入 | 说明 |
|:---|:---|:---|
| `blackrock` | `-ip` / `-iL` + `-p` | 默认。地址 × 端口空间的无状态排列；63 位上限。 |
| `ip-list` | 文件/stdin，每行一个 IP 或范围 | 使用 `-gen-arg "-ip-file list.txt -default-port 80"`；仅支持单个 tx 线程。 |
| `addr-list` | 文件/stdin，每行 `IP PORT` | 使用 `-gen-arg "-address-file targets.txt"`；默认分隔符是空格；仅支持单个 tx 线程。 |
| `ip-stream` | 流式文件/stdin，每行一个 IP 或范围 | 类似 `ip-list`，但在扫描期间持续读取；阻塞式读取会干扰速率整形。 |
| `addr-stream` | 流式文件/stdin，每行 `IP PORT` | 类似 `addr-list`，流式读取。 |

`blackrock` 的目标来自[目标与端口](./targets-and-ports.md)所述的全局选项；列表与流式生成器从自己的子参数取输入，只在注明处使用全局目标选项。`ip-list`/`addr-list` 以及流式变体都要求 `-tx-thread-count 1`。

## 找到合适的模块

- 名称匹配比较宽容：大小写以及 `-`、`_`、`.` 都会被忽略，所以 `tls_state` 能选中 `tls-state`。`--search-module <text>` 会在四个注册表中做模糊搜索。
- `--list-scan`、`--list-probe`、`--list-out`、`--list-gen` 按顺序打印注册表并附一行描述；`--help-<kind> <name>` 打印类型、多探测模式、数量以及模块自己的参数表。
- 可选依赖会改变清单。没有 OpenSSL 的构建没有 `jarm` 或 `tls-state`；没有 PCRE2 就没有 `hello-udp`、`recog*` 或 `nmap*`；没有 libbson / libmongoc 就没有 `bson` / `mongodb` 输出；带 Lua 支持的构建仍会列出 `lua-tcp` / `lua-udp`，但缺少共享库时它们会在启动阶段失败。Recog 还需要 libxml2 才能加载指纹文件。

## 参见

- [扫描模式](./scanning-modes.md) — 哪种扫描/探测组合产生什么，以及为什么
- [输出](./output.md) — 结果等级与格式
- [目标与端口](./targets-and-ports.md) — BlackRock 的输入侧
- [架构](./architecture.md) — 四类模块如何接入流水线
- [README](../../README.zh-CN.md) — 功能概览与模块注册表
