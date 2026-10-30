# 模块

[English](../modules.md) · **中文**

Xtate 由四类模块拼装而成。每一类都是一个 C 结构体，加上以 `NULL` 结尾的注册表里的一行；没有运行期插件加载。完整构建会注册 **11 个扫描 + 60 个探测 + 7 个输出 + 5 个生成**模块，而缺少可选库的模块会直接从构建中消失（也从 `--list-*` 中消失）。

| 类别 | 职责 | 参数 | 注册表 |
|:---|:---|:---|:---|
| 扫描 | L3/L4 报文、接收校验、后续报文 | `-scan` / `--scan-module` | `src/scan-modules/scan-modules.c` |
| 探测 | L5+ 载荷与响应解析器、嵌套子探测 | `-probe` / `--probe-module` | `src/probe-modules/probe-modules.c` |
| 输出 | 结果的格式化与落点 | `-output-module` | `src/output-modules/output-modules.c` |
| 生成 | `(target, port)` 对的枚举与排列 | `-generate-module` | `src/generate-modules/generate-modules.c` |

扫描模块是必需的，生成模块默认是 `blackrock`，探测模块只在扫描模块声明需要时才必需（并会做类型检查）。模块子参数以单个带引号字符串的形式，通过 `-scan-arg`、`-probe-arg`、`-output-arg` 和 `-gen-arg` 传递（主名分别为 `-scan-module-args`、`-probe-module-args`、`-output-module-args`、`-generate-module-args`）。

```bash
xtate --list-scan      # 11 个扫描模块
xtate --list-probe     # 60 个探测模块
xtate --list-out       # 7 个输出模块
xtate --list-gen       # 5 个生成模块

xtate --help-scan zbanner
xtate --help-probe tls-state
xtate --help-output mongodb
xtate --help-gen blackrock
```

## 扫描模块（11）

| 模块 | 探测 | 功能 |
|:---|:---:|:---|
| `tcp-syn` | - | SYN 扫描；收到 SYN-ACK 即 open，收到 RST 即 closed。可选 `--send-rst`、`--fail-zerowin`。 |
| `zbanner` | tcp | 无状态 TCP 握手；载荷搭在第三个 ACK 上；首个 banner 由探测模块解析。 |
| `tcp-state` | state | HLTCP 用户态 TCP；为 TLS/HTTP 状态探测模块提供完整会话。 |
| `udp` | udp | 携带探测载荷的单包 UDP 扫描；ICMP port-unreachable 表示 closed。 |
| `icmp-echo` | - | ICMP echo 主机发现；可记录 TTL 和 IPID。 |
| `icmp-time` | - | ICMP 时间戳发现，仅 IPv4。 |
| `sctp-init` | - | SCTP INIT 扫描；INIT-ACK 为 open，ABORT 为 closed。 |
| `arp-req` | - | 局域网模式下的二层 ARP 扫描；报告 MAC 地址。仅 IPv4。 |
| `ndp-ns` | - | IPv6 邻居请求；报告 MAC 地址。 |
| `yarrp-echo` | - | 用 ICMP echo 做无状态 traceroute；TTL 范围通过 `o:` 端口表示。 |
| `yarrp-udp` | - | 用 UDP 和 ICMP 错误报文做无状态 traceroute；TTL 装在端口里。 |

每个扫描模块都通过 `--help-scan <name>` 暴露自己的选项（记录 TTL/IPID/窗口、重复/去重开关、TTL 覆盖等）。如何选择模式、哪些模式需要防火墙规则，见[扫描模式](./scanning-modes.md)。

## 探测模块（60）

探测模块会声明一个**类型**，必须与扫描模块匹配：`zbanner` 用 `tcp`，`udp` 用 `udp`，`tcp-state` 用 `state`。它还声明多探测模式和数量；见[扫描模式](./scanning-modes.md#多探测模式)。

### 通用（11）

| 探测 | 类型 | 功能 |
|:---|:---:|:---|
| `http` | tcp | 在无状态 TCP 会话上发送用户指定的 HTTP 请求。 |
| `http-state` | state | 在 HLTCP 上做同样的事，包括经 TLS。 |
| `hello` | tcp | 用户载荷（string、base64、nmap-string、file）外加可选正则。 |
| `hello-udp` | udp | UDP 版本。 |
| `hello-state` | state | 在有状态 TCP 连接上的同一功能。 |
| `tls-hello` | tcp | 固定 ClientHello；读取 ServerHello 的版本/记录层线索，但不完成握手。 |
| `tls-state` | state | OpenSSL 驱动的 TLS 握手，导出证书/密码套件/版本，并可在 TLS 之上跑子探测。 |
| `jarm` | tcp | 通过 10 个 ClientHello 变体做 JARM 指纹。 |
| `dns` | udp | DNS 记录请求，可配置名称/类型/递归。 |
| `snmp` | udp | SNMP（v1/v2c）请求，并按 MIB 提取主机信息。 |
| `echo` | udp | 四个由 cookie 派生的字节；接受包含它们的回包。 |

### 指纹识别（44）

| 探测 | 类型 | 功能 |
|:---|:---:|:---|
| `recog` | tcp | 用 Recog XML 指纹匹配 banner。 |
| `recog-udp` | udp | UDP 版本。 |
| `recog-state` | state | 在有状态 TCP 上的同一功能。 |
| `nmap` | tcp | 运行一条 `nmap-service-probes` 探测并解析其匹配项。 |
| `nmap-udp` | udp | UDP 版本。 |
| `lzr` | tcp | LZR 风格的服务识别器：发送配置好的握手，匹配所有已知服务。 |

LZR 家族由一个聚合模块（`lzr`）加 **38 个握手模块**组成。每个握手也可以单独作为 `lzr-<name>` 使用；作为 `lzr` 的子探测时省略前缀，例如 `-probe-arg "-handshake http,tls"`。这 38 个是：

```text
http tls ftp pop3 imap smtp ssh socks5 telnet fix smb mqtt amqp mysql mongodb
redis postgres mssql oracle rdp x11 vnc k8s rtsp modbus siemens bgp pptp dns
ipmi dnp3 fox memcached_ascii memcached_binary ipp wait newlines newlines50
```

它们都以 `lzr-<name>` 注册，因此两个 Memcached 握手的写法是 `lzr-memcached_ascii` 与 `lzr-memcached_binary`（下划线，不是连字符）。每个握手都会发送协议相关的载荷，并从回复中识别服务；`wait` 什么都不发，`newlines` / `newlines50` 则分别发送 2 / 50 个换行来诱发问候语。

### 可脚本化（2）

| 探测 | 类型 | 功能 |
|:---|:---:|:---|
| `lua-tcp` | tcp | 加载实现 `Make_payload` / `Get_payload_length` / `Handle_response` 的 Lua 脚本。 |
| `lua-udp` | udp | UDP 版本。 |

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe lua-tcp \
  -probe-arg "-script lua-probes/tcp-example.lua" -show info
```

Lua 在运行期加载；如果没有可用的 Lua 共享库，这些探测仍会出现在列表里，但会在启动时因加载错误而失败（请安装 Lua 5.3 或 5.4）。`lua-probes/` 里的示例脚本在脚本头部声明 `ProbeName`、`ProbeType`、`MultiMode` 和 `MultiNum`。

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
