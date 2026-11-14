<div align="center">
  <img src="screenshots/poster.jpg" alt="Xtate — 面向互联网测量的模块化全栈网络扫描器" width="820">
  <br>

  <h3>Xtate — 面向专业互联网测量的模块化全栈扫描器</h3>

  <p>
    <a href="README.md">English</a> · <b>简体中文</b>
  </p>

  <p>
    <b>无状态 TCP banner。</b> <b>混合状态 TCP/TLS。</b>
    <b>完整 Linux 构建 84 个模块。</b> <b>CLI、GUI 与 MCP。</b><br>
    <sub>C99 · Linux glibc/musl 与 Windows · GCC/Clang/MSVC/MinGW · Make/Ninja · IPv4 与 IPv6</sub>
  </p>

  <p>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/version-3.0.0-blueviolet?style=flat-square" alt="version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="license"></a>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/C-99-00599C?style=flat-square&amp;logo=c" alt="C99"></a>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-informational?style=flat-square" alt="platform"></a>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/CMake-3.13%2B-064F8C?style=flat-square&amp;logo=cmake" alt="CMake"></a>
    <a href="https://github.com/knownsec/404StarLink"><img src="https://img.shields.io/badge/404Starlink-member-orange?style=flat-square" alt="404Starlink"></a>
    <a href="https://arxiv.org/abs/2405.07409"><img src="https://img.shields.io/badge/arXiv-2405.07409-B31B1B?style=flat-square&amp;logo=arxiv" alt="arXiv"></a>
  </p>
</div>

> **God is Stateless.** —— Xtate 箴言

Xtate 面向以互联网测量为职业的人：网络与安全研究者、测量平台运营者，以及
需要在互联网规模上获得可复现证据的工程师。它是报文引擎，不是爬虫：
**ZBanner** 不保留逐目标连接状态，却能获得真实 TCP 响应；**HLTCP** 在无状态
不够用时完成 TLS 握手并获取 HTTPS 响应。

**命令行是主要接口。** 目标集合、scan/probe 组合、速率、输出格式和复现配方，
用命令行表达最直接；GUI、MCP 和 Agent Skill 底层驱动的也是同一个引擎。它们
适合探索和自动化，但不替代命令行。

> **Linux 前置条件（Windows 不适用）：** `zbanner`、`tcp-state`、`tls-state`
> 及其所有 state 子探针，在扫描前都必须在扫描主机执行
> `sudo ./firewall/add_rules.sh`（`tcp-syn`/无状态端口扫描不需要）。缺少规则时
> 常见现象是显示 `open`，但没有 banner、TLS 或探针输出。参见
> [Linux 防火墙](./docs/zh-CN/firewall.md)。

> [!WARNING]
> Xtate 发送原始报文。只扫描你拥有或获得明确书面授权的网络。未经授权的扫描
> 在部分国家和地区可能违法。你对自己发送的速率和目标选择负责。

> **3.0 已正式发布。** 3.0 系列增加了以扫描为中心的浏览器控制台、一条命令启动的
> MCP 服务、双语文档、明确的协议能力报告，并强化了命令行。命令行仍是测量专家
> 的主要接口；2.44.2 是上一个稳定版本。

## 目录

- [为什么测量专家使用 Xtate](#为什么测量专家使用-xtate)
- [安装与第一次扫描](#安装与第一次扫描)
- [命令行](#命令行)
- [Xtate 如何工作](#xtate-如何工作)
- [扫描引擎](#扫描引擎)
- [模块](#模块)
- [其它客户端：GUI、MCP 与 Skill](#其它客户端gui-mcp-与-skill)
- [构建](#构建)
- [平台与工具链](#平台与工具链)
- [文档](#文档)
- [研究与引用](#研究与引用)

## 为什么测量专家使用 Xtate

- **命令行优先，可脚本化、可复现。** 一个二进制文件就能表达完整实验：目标空间、
  模块组合、速率、输出、恢复点和元数据。`--echo` 记录有效配置，
  `--list-capabilities` 报告当前构建真实具备的能力。
- **ZBanner：不建逐目标表也能拿到真实 TCP 响应。** 对端 TCP 栈保存状态，
  SipHash cookie 证明响应属于本次扫描。这是互联网级 banner 普查的引擎。
- **HLTCP：只在值得的地方保留状态。** 收到 SYN-ACK 后才创建 TCB，随后在用户态
  TCP/TLS 会话中收集证书、密码套件和 HTTP 证据，不把主机内核放进这条路径。
- **协议覆盖广，能力报告诚实。** HTTP/1.0、HTTP/1.1、HTTP/2（含 Huffman 的
  HPACK）、构建支持时的 QUIC 上的 HTTP/3、TLS 证据、DNS/DNSSEC/DoT/DoH、
  JARM、SSH、邮件、数据库、工业与 IoT 协议。Windows 构建会明确报告 HTTP/3 和
  QUIC transport 不可用，而不是假装支持。
- **为大目标空间设计。** CIDR、范围、分量范围、排除、ASN 输入、流式文件、
  BlackRock 置换、分片与可恢复运行。
- **双语设计。** 人类可读帮助提供英文和中文；GUI 与手册保持同样的划分。

## 安装与第一次扫描

### Linux：构建并运行

```bash
git clone https://github.com/babycoff/xtate.git
cd xtate
sudo apt install build-essential cmake pkg-config libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev \
  libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev libzstd-dev
./build.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 100
```

第一条命令是无状态 SYN 扫描，不需要修改防火墙。若要真正抓取 banner，需要阻止
Linux 内核对未知连接回 RST：

```bash
sudo ./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 \
  -scan zbanner -probe http -show info
sudo ./firewall/rm_rules.sh
```

> [!WARNING]
> **`zbanner` 以及所有 `tcp-state`/`tls-state`/state 探针扫描都必须先加载
> Linux 防火墙规则。** 规则会抑制内核 RST，否则半开连接会被立即终止。缺少规则
> 时常见现象是端口显示 `open`，但没有 banner、没有 TLS 输出，或 state 探针超时。
> 规则是主机级的，生效期间会丢弃本机所有出站 RST/ICMP unreachable。

> [!TIP]
> 从 `-rate 100` 开始，不要一上来就用 `-rate 100000`。实验网不是互联网，
> 交换机也会感谢你。

Windows 上请安装 [Npcap](https://npcap.com/)，用 CMake 构建，并在管理员终端
运行 `xtate.exe`。新手先从 [Windows 快速开始](docs/zh-CN/windows-quickstart.md)
读起。

### 发送前先检查路由

```bash
./bin/xtate --list-if
./bin/xtate --explain-target 203.0.113.10
./bin/xtate --check -ip 203.0.113.0/24 -p 443
```

`--list-if` 列出抓包网卡及其地址、MAC、网关和链路类型；`--explain-target`
显示某个目标会走哪块网卡、使用哪个源地址；`--check` 对一组目标执行同样的只读
检查。三者都不发送探测报文。TUN/VPN 网卡的链路类型可能是 `RAW`，
`--explain-target` 会说明是否支持原始 IP、是否有 Ethernet 头和 MAC。

### 几个常用命令

```bash
# 无状态 TLS hello：不做完整握手，获取 ServerHello 线索
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan zbanner -probe tls-hello -show info

# 有状态 TLS 证据：证书、签发者、SAN、ALPN
sudo ./firewall/add_rules.sh
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan tcp-state -probe tls-state -show info

# UDP DNS 探针
sudo ./bin/xtate -ip 10.0.0.0/24 -p u:53 -scan udp -probe dns -show info

# 局域网 ARP 扫描
sudo ./bin/xtate -ip 192.168.1.0/24 -scan arp-req -lan

# 本地链路上的 IPv6 邻居发现
sudo ./bin/xtate -ip fe80::1/120 -scan ndp-ns -src-ip fe80::2 -fake-router-mac

# SCTP INIT 扫描
sudo ./bin/xtate -ip 10.0.0.0/24 -p s:38412 -scan sctp-init -show info
```

## 命令行

### 一条扫描命令的构成

```text
xtate [options] -ip TARGETS [-p PORTS] -scan SCANMODULE [-probe PROBEMODULE]
```

| 部分 | 含义 | 示例 |
|:---|:---|:---|
| `-ip` | IPv4/IPv6 目标、范围、CIDR 或分量范围 | `10.0.0.0/8`、`192.168.1.1-254`、`2001:db8:1-5::1` |
| `-p` | 端口；前缀选择传输层 | `80,443`、`20-25`、`u:53`、`s:38412` |
| `-scan` | 如何发包、保留什么状态 | `tcp-syn`、`zbanner`、`tcp-state`、`udp`、`icmp-echo` |
| `-probe` | L5+ 载荷与解析器，scan 需要时使用 | `http`、`tls-state`、`dns`、`ssh`、`jarm` |
| `-rate` | 所有发送线程合计的每秒报文数 | `100`、`0.1`、`100000` |

CLI、控制面和 MCP 接受任意正速率，包括 `0.1` 这样的小数（十秒一个包）和每秒
数百万包的速率。浏览器 GUI 为了界面稳定性把输入限制在 10000，这不是 Xtate
引擎的限制。持续高速测量请使用 CLI。
| `-show` | 要打印的结果级别 | `success`、`info`、`fail` |
| `-o` | 输出模块与文件 | `-o ndjson -output-file run.ndjson` |
| `-scan-arg` / `-probe-arg` | 模块专用参数 | `-scan-arg "-banner"` |

`xtate --usage` 给出精简示例，`xtate --help` 列出全部全局参数，
`xtate --help-scan <module>` / `--help-probe <module>` /
`--help-out <module>` / `--help-gen <module>` 给出模块参数。帮助文本由解析器
使用的同一份元数据生成，因此与当前构建一致。

### 常用工作流

| 任务 | 命令 |
|:---|:---|
| 主机发现 | `-ip 10.0.0.0/24 -scan icmp-echo` |
| 快速端口扫描 | `-ip 10.0.0.0/24 -p 80,443 -scan tcp-syn` |
| 无状态 banner | `-ip 10.0.0.0/24 -p 80 -scan zbanner -probe http` |
| TLS 证据 | `-ip 10.0.0.0/24 -p 443 -scan tcp-state -probe tls-state` |
| UDP 服务探针 | `-ip 10.0.0.0/24 -p u:53 -scan udp -probe dns` |
| 检查目标展开 | `-ip 10.0.0.0/8 --list-target` |
| 从文件读目标 | `-include-file targets.txt -scan tcp-syn -p 443` |
| 恢复扫描 | `-ip 10.0.0.0/8 -p 443 -scan tcp-syn --resume-index N` |
| 机器可读输出 | `-o ndjson -output-file run.ndjson` |

目标与端口详见[目标与端口](docs/zh-CN/targets-and-ports.md)；scan/probe 组合与
配方见[扫描模式](docs/zh-CN/scanning-modes.md)；结果级别与格式见
[输出](docs/zh-CN/output.md)。

### 让实验可复现

```bash
./bin/xtate -ip 203.0.113.0/24 -p 443 -scan tcp-syn -rate 100 \
  --echo > experiment.conf
./bin/xtate --config-file experiment.conf
```

`--meta-filename` 会把实际使用的网卡、速率和版本写到结果旁边。
`--list-capabilities` 是当前二进制的机器可读能力声明；实验日志和 CI 应读取它，
而不是假设某个模块或协议一定存在。

### 交互式 shell

```bash
./bin/xtate -interactive
```

不依赖 ncurses、readline 包或 Python/Go 启动器。提供分组 `help`、命令/参数/
模块/取值/路径补全、历史、`set`、`show diff`、`show all`、`list-param`，
以及确定性的非 TTY 脚本模式。它适合探索；脚本应优先使用非交互 CLI。

### 查看当前构建能做什么

```bash
xtate --usage                  # 精简用法与示例
xtate --help                   # 全部全局参数
xtate --intro                  # 架构介绍
xtate --list-capabilities      # JSON：模块数量、HTTP/3、QUIC、zstd
xtate --list-scan              # Windows 11；Linux 完整构建 12
xtate --list-probe             # Windows 59；Linux 完整构建 60
xtate --list-out               # 7 个输出模块
xtate --list-gen               # 5 个生成模块
xtate --help-scan zbanner      # 模块专用参数
xtate --lang zh --help         # 中文帮助，未翻译项回退英文
```

## Xtate 如何工作

<p align="center">
  <img src="screenshots/architecture.png" alt="Xtate 运行路径：目标与 TX、合并的 RX 与分发、处理器与输出；ZBanner 和 HLTCP 挂在处理器上；绕过主机 TCP 栈" width="100%">
</p>

报文路径是：入口侧进行目标生成与 TX，中间经过合并的 `RX + Dispatch`，然后是
处理器与输出。ZBanner 保持无状态；HLTCP 只为用户态 TCP/TLS 会话保留状态。
主机内核 TCP 栈被有意排除在这条路径之外。

- **Tx：** N 个线程；目标生成、速率控制、报文构造、原始发送。
- **Rx：** 一个线程；预处理、校验、去重、可选 pcap 抓包、分发。
- **Handle：** M 个线程；scan/probe 状态机、结果格式化、后续报文。
- **有状态扫描：** 每个 handle 线程一张 TCP 连接表，热路径无需加锁。

handle 线程通过无锁环把后续报文（ACK、RST、下一个探针）送回 Tx。报文模板在
启动时预生成并按目标打补丁；目标空间展平为 `ip × port` 后用 BlackRock 置换。
结果是带 scan/probe/output 类型化链的 `OutItem`，流式交给所选输出模块。

## 扫描引擎

| | **ZBanner**（无状态） | **HLTCP**（混合状态） |
|:---|:---|:---|
| 逐目标状态 | 无 | SYN-ACK 后创建 TCB |
| 本方行为 | SYN + 带探针载荷的 ACK | 完整 TCP 状态机 |
| 获得内容 | 开放/关闭 + 首批 banner | TLS 握手、证书、密码套件、TLS 上的 HTTP |
| 内存 | 仅去重表 | 小型 TCB；TLS 会话为 OpenSSL 量级 |
| 适用场景 | 互联网级 banner 普查 | 对感兴趣主机做定向取证 |
| 入口 | `-scan zbanner -probe <tcp>` | `-scan tcp-state -probe <state>` |

<p align="center">
  <img src="screenshots/zbanner-sequence.png" alt="ZBanner 序列：带 SipHash cookie 的无状态 SYN、确认 cookie+1 的 SYN-ACK、携带探针载荷的 ACK、携带 banner 的 ACK、解析为 OutItem，然后 RST" width="100%">
</p>

没有 TCB、没有超时表、没有重传记账——只有对端 TCP 栈帮助验证的算术。完整序列
见 [ZBanner](docs/zh-CN/zbanner.md)。

无状态不够时，HLTCP 先发无状态 SYN，只在收到 SYN-ACK 后创建 TCB，在用户态完成
可选 TLS 握手，最后用 RST 结束流。详见 [HLTCP](docs/zh-CN/hltcp.md)。

## 模块

数量按启用全部可选依赖的完整构建计算。缺少依赖的模块会从构建和 `--list-*` 中
消失。

| 类型 | Windows | 完整 Linux | 用途 |
|:---|:---:|:---:|:---|
| Scan | 11 | 12 | L3/L4 报文引擎与状态模型 |
| Probe | 59 | 60 | L5+ 载荷、解析器与 state 探针 |
| Output | 7 | 7 | `text`、`csv`、`ndjson`、`bson`、`mongodb`、`list`、`null` |
| Generate | 5 | 5 | `blackrock`、`ip-list`、`addr-list`、`ip-stream`、`addr-stream` |

完整 Linux 构建在有 ngtcp2/GnuTLS 时额外提供 `quic-state`（QUIC v1 握手与证书
探针）和 `http3-state`。Windows 构建会把 HTTP/3 和 QUIC transport 报告为不可用。

模块元数据同时驱动 `--help-*`、参数解析、模糊搜索和交互补全。模块目录、注册点
和扩展方法见[模块](docs/zh-CN/modules.md)与
[模块开发](docs/zh-CN/module-development.md)。

## 其它客户端：GUI、MCP 与 Skill

这些客户端驱动同一个控制面和扫描引擎，不增加扫描能力，也不是使用 Xtate 的
必需方式。

### 浏览器控制台

```bash
xtate --gui
```

<p align="center">
  <img src="screenshots/gui-console.png" alt="Xtate GUI：新建扫描的目标范围、方式卡片、模块与全局参数、预检与授权" width="100%">
</p>

GUI 是以扫描为中心的浏览器控制台：新建扫描、实时扫描、结果、网卡、模块、系统。
它在不发送报文的前提下预检路由和模块组合，在受管 worker 中运行任务，并为每次
运行建立带时间戳的独立目录。界面支持中英文切换。`xtate --gui` 会打印 URL 和
本次会话 token，但**不会自动打开浏览器**；请自行打开地址。详见
[GUI 控制台](docs/zh-CN/gui.md)。

### MCP 服务与 Agent Skill

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --mcp
```

MCP 服务提供 14 个工具：能力、网卡、模块、路由解释、预检、配置校验、任务
启动/状态/列表/取消、结果清单和有界结果记录。`start_scan` 要求
`authorized: true`，请求体是扁平对象。服务从不执行 shell 命令。Agent Skill 是
给外部 AI 客户端使用的、经过审查的 Markdown 操作手册；它不是内嵌智能体，也不是
权限边界。参见 [Agent Skill](docs/zh-CN/agent-skill.md)、
[MCP 服务](docs/zh-CN/mcp-server.md)、
[控制面](docs/zh-CN/control-plane.md)与[任务模型](docs/zh-CN/job-model.md)。

## 构建

构建就是普通 CMake。`./build.sh` 是选择编译器、配置和生成器的交互式包装；
Windows 对应脚本是 `scripts\build-windows.ps1`。

### Linux

```bash
sudo apt install build-essential cmake pkg-config libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev \
  libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev libzstd-dev

./build.sh                                  # 交互选择编译器与配置
./build.sh --compiler gcc --config release  # 显式指定
./build.sh --compiler clang --config debug  # 显式 Debug
./build.sh --generator ninja                # 使用 Ninja
./build.sh --static --minimal               # 基础 musl 静态构建
```

产物：`bin/xtate`（Release 别名）、`bin/xtate_debug`（Debug 别名），以及
`bin/xtate-<compiler>-<config>` 工具链专用文件。Ubuntu 22.04/24.04 是参考环境；
Fedora/Arch 安装对应开发包即可。参见
[平台支持](docs/zh-CN/platform-support.md)与
[构建产物](docs/zh-CN/build-artifacts.md)。

可复现的完整 Linux 构建（含 HTTP/3、QUIC、zstd 和 GUI）使用 Ubuntu 24.04
Docker 镜像：

```bash
docker/ubuntu24-build/build.sh
docker run --rm xtate:ubuntu24-full --list-capabilities
```

参见 [Ubuntu 24.04 Docker 构建](docs/zh-CN/docker-build.md)。

### Windows

安装 **Npcap**（运行时）、CMake，以及 Visual Studio 2022/2026 或 MinGW-w64。
逐步说明见 [Windows 快速开始](docs/zh-CN/windows-quickstart.md)。

```powershell
# MSVC
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
  -DOPENSSL_ROOT_DIR="$env:USERPROFILE\scoop\apps\openssl-lts\current"
cmake --build build-msvc --config Release -j 8

# MinGW
cmake -S . -B build-mingw -G "MinGW Makefiles" `
  -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Release
cmake --build build-mingw -j 8
```

`scripts\build-windows.ps1` 不带参数运行时会询问一个编译器和一个配置。主二进制
为 `bin\xtate.exe`；工具链专用副本为
`bin\xtate-<toolchain>-<config>.exe`。MSVC、ClangCL、MinGW UCRT64 和
MinGW MINGW64 均支持 Release/Debug。运行时需要 Npcap，`wpcap.dll` 动态加载。

### 可选依赖

| 依赖 | 解锁能力 | 关闭开关 |
|:---|:---|:---|
| OpenSSL ≥ 1.1.1 | TLS/state 探针、JARM、SSH KEX、部分 QUIC 构建 | `-DWITH_OPENSSL=OFF` |
| PCRE2（8-bit） | HTTP/recog/nmap 与协议探针的正则匹配 | `-DWITH_PCRE2=OFF` |
| LibXml2 | Recog XML 指纹 | `-DWITH_LIBXML2=OFF` |
| libbson / libmongoc | BSON 与 MongoDB 输出 | `-DWITH_BSON=OFF`、`-DWITH_MONGOC=OFF` |
| zstd | 分块结果压缩 | `-DWITH_ZSTD=OFF` |
| ngtcp2 + GnuTLS | `quic-state`、`http3-state`（Linux） | `-DWITH_NGTCP2=OFF` |
| libpcap / Npcap | 报文 I/O（运行时） | 动态加载 |
| PF_RING | Linux 高性能报文 I/O（运行时） | 可选 |
| Lua 5.3/5.4 | `lua-tcp`、`lua-udp`（运行时） | 可选 |

缺少可选库时对应模块消失，核心扫描器仍可构建。vcpkg/MinGW 配置见
[Windows 可选依赖](docs/zh-CN/windows-dependencies.md)。

> [!NOTE]
> 原始套接字在 Linux 需要 root，在 Windows 需要管理员权限。Linux 上也可以在
> 明确了解风险的前提下使用
> `sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate`，避免每次 `sudo`。

## 平台与工具链

| 范围 | 支持 |
|:---|:---|
| 构建系统 | **CMake 3.13+**、Unix Makefiles 或 **Ninja** |
| Linux glibc | **GCC / Clang**，Release/Debug；Debian 10 级 CMake 3.13 基线 |
| Linux musl | **Alpine/musl**，动态构建与基础 `--static --minimal` 构建 |
| Windows | **MSVC / ClangCL / MinGW UCRT64 / MinGW MINGW64**，Release/Debug，Npcap + 可选 vcpkg DLL |
| 二进制布局 | 项目内 `bin/`，别名加精确的工具链文件名 |

Xtate 要求 64 位小端主机；CMake 会提前拒绝其它平台。Windows CI 覆盖全部四种
工具链。参见[平台支持](docs/zh-CN/platform-support.md)、
[Windows 快速开始](docs/zh-CN/windows-quickstart.md)与
[构建产物](docs/zh-CN/build-artifacts.md)。

## 文档

README 是入口页，手册与参考位于 [`docs/zh-CN/`](docs/zh-CN/README.md)：

- [3.0 手册](docs/zh-CN/manual/README.md) —— 以 CLI 为主线，覆盖安装、第一次
  扫描、scan/probe、目标、输出与协议；GUI 和 MCP 作为附加客户端
- [迁移到 3.0](docs/zh-CN/migration-3.0.md) —— 从 2.44.x 升级的破坏性变更、
  结果路径、MCP 形状与回滚
- [快速开始](docs/zh-CN/getting-started.md) —— 构建、权限、第一次扫描、防火墙
- [目标与端口](docs/zh-CN/targets-and-ports.md) —— IPv4/IPv6 输入、文件、ASN、排除、分片
- [扫描模式](docs/zh-CN/scanning-modes.md) —— 无状态与有状态、scan/probe 组合、配方
- [输出](docs/zh-CN/output.md) —— 结果级别、格式、MongoDB
- [模块](docs/zh-CN/modules.md) —— 四类模块与随附模块
- [模块开发](docs/zh-CN/module-development.md) —— C 接口、注册与 slot-plan 示例
- [架构](docs/zh-CN/architecture.md) · [ZBanner](docs/zh-CN/zbanner.md) · [HLTCP](docs/zh-CN/hltcp.md)
- [GUI 控制台](docs/zh-CN/gui.md) · [MCP 服务](docs/zh-CN/mcp-server.md) · [Agent Skill](docs/zh-CN/agent-skill.md)
- [控制面](docs/zh-CN/control-plane.md) · [任务模型](docs/zh-CN/job-model.md)
- [平台支持](docs/zh-CN/platform-support.md) · [构建产物](docs/zh-CN/build-artifacts.md)
- [测试策略](docs/zh-CN/testing.md) · [故障排查](docs/zh-CN/troubleshooting.md) · [已知限制](docs/zh-CN/known-limitations.md)

English documentation: [`docs/`](docs/README.md)

## 研究与引用

Xtate 的两个引擎来自我们的研究：

- **ZBanner: Fast Stateless Scanning Capable of Obtaining Responses over TCP** —
  [arXiv:2405.07409](https://arxiv.org/abs/2405.07409) ·
  [IPCCC 2024](https://doi.org/10.1109/IPCCC59868.2024.10850469)
- **Efficient Application-Layer Scanning with Hybrid-State Lightweight TCP Stack
  for TLS-based Service Monitoring** —
  [ICCT 2024](https://doi.org/10.1109/ICCT62411.2024.10946306)
- **硕士学位论文：**《基于应用层扫描的网络协议与设备识别技术研究》（国防科技大学，2024）

<details>
<summary><b>BibTeX</b></summary>

```bibtex
@misc{chen2024zbanner,
  title         = {ZBanner: Fast Stateless Scanning Capable of Obtaining Responses over TCP},
  author        = {Chen, Chiyu and Lu, Yuliang and Yang, Guozheng and Xie, Yi and Guo, Shasha},
  year          = {2024},
  eprint        = {2405.07409},
  archivePrefix = {arXiv},
  primaryClass  = {cs.NI}
}

@inproceedings{chen2024hltcp,
  title     = {Efficient Application-Layer Scanning with Hybrid-State Lightweight TCP Stack for TLS-based Service Monitoring},
  author    = {Chen, Chiyu and Lu, Yuliang and Yang, Guozheng and Xie, Yi and Guo, Shasha},
  booktitle = {2024 IEEE 24th International Conference on Communication Technology (ICCT)},
  pages     = {2067--2073},
  year      = {2024},
  doi       = {10.1109/ICCT62411.2024.10946306}
}
```
</details>

如果 Xtate 对你的研究有帮助，引用比 star 更让我们高兴。

## 贡献

欢迎贡献。构建/测试矩阵、C 与模块规范、PR 检查清单见
[CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请按 [SECURITY.md](SECURITY.md)
私下报告，不要公开提交漏洞 issue。

## 许可证与负责任使用

AGPL-3.0，见 [LICENSE](LICENSE)。如果把修改后的 Xtate 作为网络服务运行，
AGPL 的网络使用条款适用。

> [!WARNING]
> Xtate 是用于测量和安全研究的双用途工具。只在你拥有或获得书面授权的网络上
> 使用。你有责任遵守当地法律、ISP 政策和目标网络的规则。

Xtate 起源于 [Masscan](https://github.com/robertdavidgraham/masscan) 的代码库；
感谢 Robert Graham 以及源码中列出的所有上游项目。Xtate 是
[404Starlink](https://github.com/knownsec/404StarLink) 成员。

作者：**Alvin Chen**（陈驰昱）· [shineccy@aliyun.com](mailto:shineccy@aliyun.com)。
原始代码写于国防科技大学硕士研究期间，以及网络空间安全态势感知与评估安徽省
重点实验室。

<div align="center">
  <sub>God is Stateless. Physical layer? We stop at the wire.</sub>
</div>
