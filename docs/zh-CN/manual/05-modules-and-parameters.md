# 05 · 模块与参数

[English](../../manual/05-modules-and-parameters.md) · **中文**

Xtate 由四类模块组装而成。一次扫描恰好选择一个扫描模块，可选一个探测模块、一个输出模块和一个目标生成器。

| 类别 | 数量（完整构建） | 选择器 | 作用 |
|:---|:---:|:---|:---|
| 扫描 | 12 | `-scan` | 发送报文并归类响应 |
| 探测 | 60 | `-probe` | 在扫描之上做可选的深入解析 |
| 输出 | 7 | `-output-module` | 写结果记录 |
| 生成 | 5 | `-gen` | 产生目标/端口流 |

没有 ngtcp2（及其可用的 TLS 提供方）的构建不注册 `quic-state` 和一个探测，数量为 11 / 59 / 7 / 5。本章描述完整构建；被省略的模块只是不出现在列表里。

## 查找模块及其参数

```bash
xtate --list-scan
xtate --list-probe
xtate --list-out
xtate --list-gen

xtate --help-scan=tcp-syn
xtate --help-probe=tls-state
xtate --help-output=mongodb
xtate --help-gen=ip-stream
```

`--list-modules-json` 把同一份注册表打印成 JSON，包含名称、类别、探测类型和参数表，便于工具使用。`--search-module` 用模糊名称匹配（编辑距离 2），因此 `--search-module zbannr` 这样的拼写错误仍能找到 `zbanner`：

```bash
xtate --search-module banner
```

模块名是稳定的标识符。它们区分大小写并使用连字符，例如 `tcp-syn`、`tcp-state`、`tls-state` 和 `http-state`。

3.0 GUI 使用同一份注册表和同样的四类名称：**Scan modules**、**Probe modules**、**Output modules** 和 **Generate modules**。点击模块卡片会展开完整说明和参数表，可在选择前查看名称、类型、说明和别名。控制台还提供一个受控的 **Global parameters** 列表：其中暴露 23 个安全的扫描级选项，并作为 `global_args` 发送。进程/文件/脚本选项、控制面或 job 内部选项，以及表单已覆盖的字段（目标、端口、速率、接口、模块名）都被刻意排除。

## 传递参数

模块选项不是全局 flag。它们以每个模块一个带引号的字符串传递：

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-syn \
  -scan-arg "--record-ttl --record-win"

xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe tls-hello \
  -probe-arg "--support-tls13"
```

- `-scan-arg`（全称 `--scan-module-arg`，也写作 `--scanner-arg`）作用于扫描模块。
- `-probe-arg`（全称 `--probe-module-arg`，也写作 `--probe-args`）作用于探测模块。
- `-output-arg`（全称 `--output-module-arg`/`--output-module-args`、`--out-arg`）作用于输出模块。
- `-gen-arg`（全称 `--generate-module-arg`/`--generate-module-args`、`--generator-arg`）作用于生成器。

每个字符串由 Xtate 拆分，而不是由你的 shell 拆分，因此整个参数列表只能加一层引号。不要给单个选项再加一层引号；内层引号会变成字面字符。如果选项值包含空格，请在参数字符串内部给它加引号，例如 `-probe-arg "-user-agent 'Mozilla/5.0 (compatible)'"`。

有状态探测再多嵌套一层。`tls-state` 需要一个具体的 state 子探测，通过 `-subprobe` 传入：

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -subprobe-arg '--url /admin --all-banner'" \
  -show info
```

嵌套的单引号由 Xtate 自己的参数拆分器消费。整个 `-subprobe-arg` 值必须是一个用单引号包住的字符串；没有这层单引号时，只有第一个嵌套选项会赋给子探测，后面的选项会被 `tls-state` 解析。嵌套引号是 `subprobe` 错误最常见的来源；像 `-subprobe-arg --path=/h2` 这样的单个 token 可以完全避开该问题。

## 扫描模块

扫描模块要求的探测类型必须与所选探测匹配，否则 Xtate 拒绝启动。`none` 表示"没有探测模块"。

| 扫描模块 | 探测类型 | 用途 |
|:---|:---|:---|
| `tcp-syn` | 无 | 无状态 SYN 扫描；开放/关闭 |
| `zbanner` | tcp | 无状态握手加 banner 抓取 |
| `tcp-state` | state | 带真实 TCB 的有状态 TCP（HLTCP） |
| `udp` | udp | 单报文 UDP 扫描 |
| `quic-state` | state | 有状态 QUIC 握手（可选构建） |
| `icmp-echo` | 无 | ICMP echo 可达性 |
| `icmp-time` | 无 | ICMP 时间戳可达性 |
| `sctp-init` | 无 | SCTP INIT 开放/关闭 |
| `arp-req` | 无 | 本地链路 ARP（IPv4） |
| `ndp-ns` | 无 | NDP 邻居请求（IPv6） |
| `yarrp-echo` | 无 | 无状态 ICMP traceroute |
| `yarrp-udp` | 无 | 无状态 UDP traceroute |

通用约定：

- `--record-*` 选项把证据加入 `scan report`：`--record-ttl`、
  `--record-ipid`、`--record-win`、`--record-mss`、`--record-seqno`、
  `--record-ackno`、`--record-data`、`--record-data-len`、`--record-utf8`。
- `-ttl` 选项控制出向 TTL，例如 `tcp-syn` 的 `--syn-ttl` 和
  `--rst-ttl`，`zbanner` 的 `--probe-ttl` 和 `--ack-banner-ttl`。
- 去重和重传是引擎本地的：`tcp-syn` 有
  `--no-dedup-synack`、`--no-dedup-rst`、`--repeat-synack` 和
  `--repeat-rst`；`zbanner` 有 `--no-dedup-*` 和 `--repeat-*`。
- 端口状态等级可配置，使结果出现在 `--show
  info`/`--show failed` 下：`--port-success`、`--port-failure`（`udp`、
  `zbanner`）、`--ack-success`（`zbanner`）。

### tcp-syn

```bash
xtate -ip 203.0.113.10 -p 80,443,8000-8100 -scan tcp-syn \
  -scan-arg "--send-rst --record-ttl --record-win"
```

| 选项 | 含义 |
|:---|:---|
| `--send-rst` | 对开放端口发送 RST（Windows 上需要，以避免操作系统复位） |
| `--fail-zerowin` | 把窗口为零的 SYN-ACK 报告为失败 |
| `--synack-limit N` / `--synack-floor N` | 抑制或限制重复的 SYN-ACK |
| `--record-ipid` | 报告 IP ID（仅 IPv4） |
| `--syn-ttl`, `--rst-ttl` | SYN 和 RST 的出向 TTL |

`tcp-syn` 每目标发送一个 SYN。它的分类是 `open`/`syn-ack` 或 `closed`/`rst`；关闭的结果属于失败，在 `-show failed` 之前隐藏。

### zbanner

```bash
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe tls-hello \
  -probe-arg "--support-tls13" \
  -scan-arg "--with-ack --record-banner --record-ttl"
```

`zbanner` 不使用 TCB 完成握手。常用选项：`--with-ack`、`--no-rst`、`--probe-zerowin`、`--all-banner`、`--all-banner-limit`、`--all-banner-floor` 以及 `--record-*` 系列。banner 字节存放在 `probe report`/`scan report` 中，可用 `--record-utf8` 以文本打印。开放端口默认是信息级；如果想让它们进入默认的 success 流，加 `--port-success`。`--all-banner` 模式记录连接上看到的每个 banner，并在 TCP 窗口或快照缓冲区太小、无法抓取多 banner 时告警；依赖它之前先看它的帮助。

### tcp-state

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state --dump-cert-details" -show info
```

`tcp-state` 为每个处理线程构建一个真实的 TCP 状态机。内存按线程设限：

| 选项 | 默认值 | 含义 |
|:---|:---:|:---|
| `--tcb-mem MiB`（`--tcb-memory`） | 128 | TCB 内存预算，分摊到各处理线程表 |
| `--conn-expire SEC` | 30 | 空闲连接过期时间 |
| `--port-success` | 关 | 把开放端口报告为 success 而不是 info |
| `--record-all-ttl/ipid/win/seqno/ackno/len` | 关 | 记录每个分段的字段 |

`tcp-state` 是唯一能与 `tls-state`、`http-state`、`get-state` 等 state 探测配合的扫描模块。只要需要协议会话而不只是端口判定，就选它。

### udp

```bash
xtate -ip 203.0.113.10 -p u:53,u:123 -scan udp -probe echo \
  -scan-arg "--record-ttl --record-icmp-id"
```

UDP 收到回包时结果是 `responsed`，ICMP 错误表明不可达时是 `closed`/`port
unreachable`。选项包括 `--no-port-unreachable`（隐藏由 ICMP 得出的关闭）、`--port-failure`、`--no-pre-validate`、`--repeat-packets`、`--packet-limit` 和 `--packet-floor`。

### icmp-echo、icmp-time、sctp-init、arp-req、ndp-ns

这些引擎不用端口定目标：

```bash
xtate -ip 203.0.113.0/24 -scan icmp-echo -scan-arg "--record-ttl"
xtate -ip 2001:db8::/64 -scan ndp-ns -scan-arg "--record-ttl"
xtate -ip 203.0.113.10 -scan sctp-init -p s:38412
```

`arp-req` 需要 `--lan-mode` 和 IPv4 在链路上的目标；`ndp-ns` 对路由目标需要 IPv6 链路本地 `-src-ip` 和 `--fake-router-mac`。两者都是本地链路工具，不是互联网扫描器。`sctp-init` 使用 `-p s:PORT`。

### yarrp-echo 与 yarrp-udp

```bash
xtate -ip 203.0.113.10 -scan yarrp-echo -p o:1-20 -gen blackrock
xtate -ip 203.0.113.10 -p o:1-20 -scan yarrp-udp \
  -scan-arg "--init-target-port 33434"
```

`yarrp-*` 把 TTL 或端口偏移编码进 `o:` 端口空间，因此必须提供 `-p o:1-20`。结果带有 `path`、`destination` 和 `distance`。它们只能与 `-gen blackrock` 一起工作。

### quic-state（可选）

使用 ngtcp2/GnuTLS 构建。它执行真实的 QUIC 握手，报告版本、ALPN，可选报告证书：

| 选项 | 含义 |
|:---|:---|
| `--alpn` | ALPN 列表（默认 `h3`） |
| `--sni` | TLS 服务器名 |
| `--max-flows`、`--flow-timeout` | 流表大小与空闲移除 |
| `--max-udp-payload` | 通告的最大 UDP 载荷（1200–65527） |
| `--no-cert` | 跳过证书提取 |
| `--handshake-timeout`、`--idle-timeout` | QUIC 定时器 |

## 探测模块

探测只有配合兼容的扫描模块才有用。`tcp` 探测配合 `zbanner`；`state` 探测配合 `tcp-state`；`udp` 探测配合 `udp`。探测类型由 `--list-probe` 和 `--help-probe` 打印。

探测分组（基础列表 59 个探测；带 ngtcp2 的构建增加一个 HTTP/3 探测，共 60 个）：

- 25 个通用探测（HTTP、TLS、SSH、DNS、邮件及其他常见协议）。
- 两批共 16 + 6 个应用/协议探测（数据库、VoIP、文件传输、隧道及类似握手）。
- 5 个指纹探测（nmap/recog 匹配、JARM、TLS ClientHello 指纹、SSH 密钥交换）。
- 2 个可脚本探测（`lua-tcp`、`lua-udp`）。
- 2 个开发者探测（原始 hello 交换，TCP 和 UDP 变体）。
- 3 个基础探测（null、echo、连接关闭）。

### http

默认请求是 `GET / HTTP/1.0`，带 Xtate `User-Agent` 和 `Accept: */*`。

```bash
xtate -ip 203.0.113.10 -p 80 -scan zbanner -probe http \
  -probe-arg "--url /admin --method GET --record-body --max-body 8192" \
  -show info
```

选项：`--no-record-status`、`--no-record-headers`、`--record-body`、`--max-body`（默认 4096）、`--method`、`--url`、`--version`、`--host`、`--dynamic-host`、`--user-agent`、`--payload`、`--cookie`、`--header`、`--remove`、`--keyword`、`--regex`、`--match-scope all|headers|body`、`--case-insensitive`、`--include-newlines`。

### tls-state

需要 state 子探测、OpenSSL 和有状态扫描：

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -subprobe-arg '--url / --all-banner'" \
  -show info
```

| 选项 | 含义 |
|:---|:---|
| `--subprobe NAME` | 在 TLS 内部运行的 state 探测（必需） |
| `--subprobe-arg "..."` | 该子探测的参数 |
| `--starttls smtp, imap, pop3, ftp, managesieve` | TLS 之前的明文升级 |
| `--sni`、`--alpn` | TLS 握手参数 |
| `--dump-version`、`--dump-cipher`、`--dump-cert-details`、`--dump-subject` | 证据 |
| `--dump-cert`、`--fail-handshake`、`--graceful-tls-close` | 证书/行为控制 |

`--starttls` 执行问候/升级交换，并在同一连接上启动 TLS；子探测永远看不到明文阶段。

### jarm

`jarm` 有十个 slot，触发条件是 `after first reply`：第一个 ClientHello 正常发送，一旦收到看起来像 TLS 的回复，其余九个就以突发方式发送。

```bash
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe jarm -show info
python3 tools/jarm_aggregate.py scan.ndjson --complete-out jarm.jsonl
```

`--first-probe N` 改变哪个探测先发；其余九个仍按轮换顺序跟随。`--probe-index N` 只发送第 N 个探测，产生不完整的指纹（仅用于调试）。每个 slot 发出 `jarm_part` 和 `jarm_slot`；用工具聚合它们得到 JARM 哈希。

### 其他指纹与脚本探测

```bash
# nmap service probes
xtate -ip 203.0.113.10 -p 22 -scan zbanner -probe nmap \
  -probe-arg "--probe-file nmap-service-probes"

# recog fingerprints
xtate -ip 203.0.113.10 -p 80 -scan zbanner -probe recog \
  -probe-arg "--file recog-fingerprints.txt --unprefix"

# scripted probe
xtate -ip 203.0.113.10 -p 8080 -scan zbanner -probe lua-tcp \
  -probe-arg "--script myscript.lua"
```

- `nmap` 接受 `--probe-file`、`--probe-name`、`--softmatch`；需要 PCRE2。
- `recog` 接受 `--string`、`--base64-string`、`--nmap-string`、`--file`、`--recog-xml`、`--unprefix`、`--unsuffix`；需要 PCRE2 和 libxml2。
- `lua-tcp`/`lua-udp` 接受 `--script`；如果构建时没有 Lua 支持，探测会在启动时失败，而不是静默跳过扫描。
- `hello`/`hello-udp` 是开发者探测：`--string`、`--base64-string`、`--nmap-string`、`--file`、`--regex`、`--case-insensitive`、`--include-newlines`。
- `tls-hello` 是单个 ClientHello，带 `--support-tls13`、`--regex`、`--case-insensitive`、`--include-newlines`；它不执行握手。

### 多 slot 探测

多数探测使用一个 slot。探测可以声明 slot 计划：

- `Always`：每个目标立即为每个 slot 发送一个报文。ZBanner/TCP 和 UDP 引擎使用。
- `AfterFirstReply`：先发送第一个 slot，只有收到可接受的首次回复后，其余 slot 才展开。`jarm` 是显著用户。

slot `i` 使用源端口 `src_port_start + i`，因此配置的源端口范围至少要覆盖 slot 数量。每个 slot 产生自己的结果记录（`jarm_part`）；Xtate 内部没有组状态，也没有跨 slot 聚合。

## 输出模块

| 模块 | 目的地 | 显著选项 |
|:---|:---|:---|
| `text` | 文件（或 `-` 表示 stdout） | 无 |
| `ndjson` | 文件（或 `-`） | 无 |
| `csv` | 文件（或 `-`） | 无 |
| `list` | 文件（或 `-`） | `--no-port` |
| `bson` | 二进制文件 | `--compact-mode` |
| `mongodb` | 通过 `-o` 的 MongoDB URI | `--database-name`、`--collection-name`、`--insert-bulk`、`--bulk-size`、`--retry-count`、`--retry-delay` |
| `null` | 丢弃 | 无 |

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -show all \
  -output-module ndjson -o out.ndjson

xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -show all \
  -output-module list -output-arg "--no-port" -o addresses.txt

xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -show all \
  -output-module mongodb -o "mongodb://127.0.0.1:27017" \
  -output-arg "--database-name scans --collection-name run1"
```

格式细节与转义见 [06 · 结果与文件](./06-results-and-files.md)。

## 生成模块

| 生成器 | 输入 | 用途 |
|:---|:---|:---|
| `blackrock` | `-ip`、`-p` | 默认；随机化地址 × 端口空间 |
| `ip-list` | 文件/stdin | 每行一个地址，固定端口 |
| `addr-list` | 文件/stdin | 每行地址/端口对 |
| `ip-stream` | 文件/stdin | 流式地址，固定端口 |
| `addr-stream` | 文件/stdin | 流式地址/端口对 |

```bash
xtate -gen ip-list -gen-arg "--ip-file hosts.txt --default-port 443" \
  -tx-thread-count 1 -scan tcp-syn -show all

xtate -gen addr-list -gen-arg "--address-file targets.txt --splitter ','" \
  -tx-thread-count 1 -scan tcp-syn
```

生成器选项：

- `blackrock`：`--rounds N`（默认 14）、`--no-random`（自然顺序）。
- `ip-list`、`ip-stream`：`--ip-file FILE`（默认 stdin）、`--default-port`（或 `--port`）、`--rounds`、`--no-random`。
- `addr-list`、`addr-stream`：`--address-file FILE`（默认 stdin）、`--splitter STRING`（默认单个空格）。
- 四个行/流生成器共享 `--strict-errors`、`--max-errors` 和 `--max-error-rate`；见 [03 · CLI 与 job](./03-cli-and-jobs.md)。

四个行/流生成器要求单个发送线程：`-tx-thread-count 1`。它们在等待输入时会阻塞发送线程，因此刻意放宽速率保证（它们绝不会超过配置的速率）。

## 依赖与限制

| 功能 | 需要 |
|:---|:---|
| `tls-state`、`tls-hello`、`jarm`、TLS 握手、SSH 密钥交换 | OpenSSL |
| `quic-state`、QUIC 探测、HTTP/3 | ngtcp2 + GnuTLS |
| `http` 正则、`hello` 正则、`nmap`、`recog` | PCRE2 |
| `recog` XML 解析 | libxml2 |
| BSON 输出 | libbson |
| MongoDB 输出 | libmongoc |
| 压缩结果分片 | zstd |
| `lua-*` 探测 | 构建中的 Lua 支持 |

值得记住的限制：

- 一个扫描模块，最多一个探测、一个输出模块和一个生成器。
- 探测的类型必须匹配扫描模块要求的类型。
- 参数字符串由 Xtate 解析，不是你的 shell；对 `tls-state` 子探测而言，嵌套引号必须经过两层仍能存活。
- 探测和扫描参数记录在帮助里；`--help-*` 是名称、别名和默认值的权威来源。
- 模块名是稳定 API：工具可以依赖 `tcp-syn`、`zbanner`、`tls-state` 及其他列出的标识符。

## 另见

- [04 · 目标与扫描](./04-targets-and-scanning.md) —— 目标语法、引擎与速率语义
- [模块](../modules.md) —— 完整注册表与描述
- [TLS 组合](../tls-composition.md) —— 更深入的 `tls-state` 配方
- [扫描模式](../scanning-modes.md) —— 选哪个引擎
- [输出](../output.md) —— 输出格式
- [JSON 契约](../json-contracts.md) —— 供工具使用的模块 schema
