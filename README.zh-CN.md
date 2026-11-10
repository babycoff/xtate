<div align="center">
  <img src="screenshots/poster.jpg" alt="Xtate——模块化全栈网络扫描器" width="820">
  <br>

  <h3>Xtate —— 面向互联网级测量的模块化全栈网络扫描器</h3>

  <p>
    <b>无状态 TCP banner。</b> <b>混合状态 TCP/TLS。</b> <b>50 个已注册模块。</b><br>
    <sub>C99 · Linux glibc/musl &amp; Windows · GCC/Clang/MSVC/MinGW · Make/Ninja · IPv4 &amp; IPv6</sub>
  </p>

  <p>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/version-2.41.0-blueviolet?style=flat-square" alt="version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="license"></a>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/C-99-00599C?style=flat-square&amp;logo=c" alt="C99"></a>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-informational?style=flat-square" alt="platform"></a>
    <a href="https://github.com/babycoff/xtate"><img src="https://img.shields.io/badge/CMake-3.13%2B-064F8C?style=flat-square&amp;logo=cmake" alt="CMake"></a>
    <a href="https://github.com/knownsec/404StarLink"><img src="https://img.shields.io/badge/404Starlink-member-orange?style=flat-square" alt="404Starlink"></a>
    <a href="https://arxiv.org/abs/2405.07409"><img src="https://img.shields.io/badge/arXiv-2405.07409-B31B1B?style=flat-square&amp;logo=arxiv" alt="arXiv"></a>
  </p>
</div>

[English](README.md) · **中文**

> **God is Stateless.** —— Xtate 的格言

> **Linux 前置条件（不适用于 Windows）：** `zbanner`、`tcp-state`、`tls-state` 和所有 state 子探针
> 在扫描端必须先执行 `sudo ./firewall/add_rules.sh`（`tcp-syn` 等无状态扫描不需要）。缺失规则会出现
> `open` 但没有 banner/TLS/探针输出。见 [Linux 防火墙](./docs/firewall.md)。

Xtate 是一款面向大规模主动测量的网络扫描器。它把扫描栈拆成四种可插拔的模块类型——**扫描**（L3/L4 数据包）、**探测**（L5 及以上载荷与解析器）、**生成**（目标）和**输出**（结果）——并自带两个原创引擎：

- **ZBanner** 无需保存每个目标的连接状态，也能拿到真实的 TCP 响应。
- **HLTCP** 是一个混合状态的用户态 TCP 协议栈；当无状态方式不够用时，它负责完成 TLS 握手并获取 HTTPS 响应。

它不是爬虫，也从不假装是。它是一台数据包引擎，只保留刚好够用的协议状态，从而拿到多数高速扫描器拿不到的答案。

<p align="center">
  <a href="#为什么选择-xtate">为什么</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#架构">架构</a> ·
  <a href="#模块">模块</a> ·
  <a href="#构建">构建</a> ·
  <a href="#探索-cli">CLI</a> ·
  <a href="docs/zh-CN/README.md">文档</a> ·
  <a href="#论文与引用">论文</a> ·
  <a href="#许可证与负责任使用">许可证</a>
</p>

## 为什么选择 Xtate

多数高速扫描器止步于“端口开放”，多数服务扫描器在互联网规模下力不从心。Xtate 就活在这两者的交集里。

- ⚡ **ZBanner**——无需为每个目标维护连接表，也能拿到真实的 TCP 响应。状态由对端的 TCP 协议栈保存，一个 SipHash cookie 就能证明这条回应是给你的。
- 🧬 **HLTCP**——按需创建的混合状态用户态 TCP 协议栈。它能完成 TLS 握手，并在握手之上直接讲 HTTP。
- 🛰 **QUIC 能力探测**——发送真实 QUIC v1 Initial，识别 Version Negotiation/Retry/Initial/Handshake；不声称完成 HTTP/3 握手。
- 🔄 **QUIC state**——可选 ngtcp2/GnuTLS 有状态 QUIC 握手，输出版本、TLS/ALPN、证书字段并支持 state 子探测；原始 UDP 与源端口仍由 Xtate 控制。
- 🔐 **TLS 证据**——完整握手后可输出结构化证书细节（subject、issuer、SAN、有效期、序列号、公钥、签名、ALPN），并支持 SMTP/IMAP/POP3/FTP STARTTLS 升级。
- 🧪 **JARM**——十个标准 Salesforce 探针，可用 `--first-probe` 轮换首个标准探针；后续探针批量发送，输出与顺序无关。
- 🧩 **模块**——11 个基础扫描模块（有 ngtcp2/GnuTLS 时另有 `quic-state`）/ 27 个基础探测模块（另有 `http3-state`）/ 7 个输出模块 / 5 个生成模块。四套接口，一条流水线，没有运行时的插件魔法。
- 🪟 **Windows 限制**——`quic-state`/`http3-state` 当前仅支持 Linux + ngtcp2/GnuTLS；Windows MSVC 会省略它们，OpenSSL backend 已列入 roadmap TODO。
- 🌐 **中文帮助**——`--lang zh` 或 `XTATE_LANG=zh` 可切换人类可读帮助；支持 UTF-8 宽度换行，未翻译内容安全回退英文。
- 🎯 **稀疏目标模式**——支持 `132.80-88.90.15`、`2001:db8:1-5::1` 这类分量范围；单个 token 最多 4 个范围组成笛卡尔积（上限 1,048,576 个地址），大范围连续空间仍用 CIDR/区间。

## 工具链、平台与交互式模式

Xtate 用 C99 编写，除 libpcap/Npcap 外没有硬依赖；构建工具链和交互式 shell
都是一等公民，而不是附加功能。

### 工具链与环境

| 范围 | 支持 |
|:---|:---|
| 构建系统 | **CMake 3.13+**，Unix Makefiles 或 **Ninja** |
| Linux glibc | **GCC / Clang**，Release/Debug；Debian 10 级别 CMake 3.13 基线 |
| Linux musl | **Alpine/musl**，动态构建和基础 `--static --minimal` 静态构建 |
| Windows | **MSVC / ClangCL / MinGW UCRT64 / MinGW MINGW64**，Release/Debug，Npcap + 可选 vcpkg DLL |
| 产物布局 | 项目内 `bin/`，别名 + 精确的按工具链命名文件 |

Windows CI 覆盖上述四种工具链。详见[平台支持](docs/zh-CN/platform-support.md)、[Windows 快速上手](docs/zh-CN/windows-quickstart.md)和[构建产物](docs/zh-CN/build-artifacts.md)。

### 交互式模式

`xtate -interactive` 是自带实现，不依赖 ncurses、readline 包或额外运行时。

- 分组 `help` / `help <command>`，支持中文帮助（`--lang zh`）；
- `<TAB>` 补全命令、参数名、模块名、常见值和文件路径；
- 选择 scan/probe/output/generate 模块后补全该模块的 `--选项`；
- 命令历史、`set`、`show diff`、`show all`、`list-param <过滤词>`；
- 真实 TTY 模式 + 确定性的非 TTY 脚本模式，退出时恢复终端；
- Linux 和 Windows 同一个二进制，不需要 Python/Go 启动器。

详见[交互式模式](docs/zh-CN/interactive-mode.md)。

## 快速开始

```bash
# Linux: build from source (dependencies are covered under Build)
git clone https://github.com/babycoff/xtate.git
cd xtate
./build.sh                 # 交互选择编译器和 Release/Debug
./bin/xtate -interactive   # 可选：带补全的交互式 shell

# A classic SYN scan — no firewall tricks needed
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

要做真正的 banner 抓取握手，得先让 Linux 内核不再重置它不认识的连接：

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http -show info
./firewall/rm_rules.sh
```

> [!WARNING]
> **Linux 防火墙规则对 `zbanner` 以及所有 `tcp-state`/`tls-state`/state 探针都是必需的。** 不加载规则时，内核会对这些半开连接回 RST，导致“端口 open 但没有 banner / 没有 TLS 输出 / state 探针超时”。这类问题事后很难排查。扫描前运行 `./firewall/add_rules.sh`，扫描结束立即运行 `./firewall/rm_rules.sh`；规则是主机级的，会丢弃本机所有出站 RST/ICMP unreachable。

> [!TIP]
> 从 `-rate 1000` 起步，而不是 `-rate 1000000`。实验室网段不是互联网，你的交换机会感谢你。

> [!WARNING]
> Xtate 发送原始数据包。请只扫描你拥有、或已获得明确授权测试的网络。未经授权的扫描在你所在地区可能违法。

在 Windows 上，安装 [Npcap](https://npcap.com/)，用 CMake 构建，并在管理员权限的终端中运行 `xtate.exe`。第一次用 Windows？请从 [Windows 快速上手](docs/zh-CN/windows-quickstart.md) 开始。

<details>
<summary><b>更多可尝试的命令</b></summary>

```bash
# Stateless TLS hello: grab ServerHello hints without a full handshake
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan zbanner -probe tls-hello -show info

# UDP with a generic echo probe
sudo ./bin/xtate -ip 10.0.0.0/24 -p u:80 -scan udp -probe echo -show info

# LAN ARP sweep
sudo ./bin/xtate -ip 192.168.1.0/24 -scan arp-req -lan

# IPv6 neighbor discovery on a local link
sudo ./bin/xtate -ip fe80::1/120 -scan ndp-ns -src-ip fe80::2 -fake-router-mac

# SCTP INIT scan
sudo ./bin/xtate -ip 10.0.0.0/24 -p s:38412 -scan sctp-init -show info
```

</details>

## 架构

<p align="center">
  <img src="screenshots/architecture.png" alt="Xtate 运行架构：从目标与 TX 经 Internet、RX + Dispatch、处理线程到输出的 U 形路径；ZBanner 与 HLTCP 挂在处理线程下；明确绕过主机 TCP 协议栈" width="100%">
</p>

这张总览把数据包路径折成 U 形：入口侧是目标和 TX，中间是合并的 `RX + Dispatch`，之后是处理线程和输出。ZBanner 不保留状态，HLTCP 只为用户态 TCP/TLS 会话保留状态；主机内核 TCP 协议栈不在这条路径上。

- **Tx：** N 个线程；目标生成、速率控制、数据包构造、raw 发送。
- **Rx：** 1 个线程；预处理、校验、去重、可选 pcap 抓包，然后分发。
- **处理（Handle）：** M 个线程；扫描/探测状态机、结果格式化、后续数据包。
- **有状态扫描：** 每个处理线程一张 TCP 连接表，因此热路径无需加锁。

处理线程通过无锁环形队列，把后续数据包（ACK、RST、下一次探测）注回 Tx；正因如此，“无状态”的 Rx 路径依然能驱动一次真正的 TCP 会话。

**简单说说底层：**

- 数据包模板在启动时预先生成，之后按目标逐字段打补丁，并重新计算校验和。
- 目标空间被展平成 `ip × port`，再用 BlackRock 置换；源 IP 和源端口同样可以随机化（63 位扫描空间）。
- 结果是一个 `OutItem`，内含三条带类型的键值链（scan、probe、output），流式交给所选的 OutputModule。
- `--pcap`、`--resume`、`--shard` 和实时状态栏都是内置功能。

## 两种扫描方式

| | **ZBanner**（无状态） | **HLTCP**（混合状态） |
|:---|:---|:---|
| 每个目标的状态 | 无 | 收到 SYN-ACK 后建立 TCB |
| 我方发送 | SYN + 携带探测载荷的 ACK | 完整的 TCP 状态机 |
| 你能得到 | 开放/关闭 + 首条 banner | TLS 握手、证书、密码套件、TLS 之上的 HTTP |
| 内存占用 | 仅去重表 | 小型 TCB；TLS 会话的内存开销与 OpenSSL 相当 |
| 适用场景 | 互联网范围的 banner 普查 | 对感兴趣主机的定向取证 |
| 入口 | `-scan zbanner -probe <tcp>` | `-scan tcp-state -probe <state>` |

招牌技巧，一条时序就能讲完：

<p align="center">
  <img src="screenshots/zbanner-sequence.png" alt="ZBanner 时序：无状态 SYN 携带 SipHash cookie，SYN-ACK 确认 cookie 加一，带探测载荷的 ACK，带 banner 的 ACK，内部解析为 OutItem，最后是 RST；全程没有 TCB，也没有超时表" width="100%">
</p>

没有 TCB，没有超时表，也没有重传记录。只有一点算术，而对端的 TCP 协议栈会帮你验证它。

### HLTCP：无状态结束之后

<p align="center">
  <img src="screenshots/hltcp-sequence.png" alt="HLTCP 时序：先发无状态 SYN；只有收到 SYN-ACK 才创建 TCB；之后是 ACK、可选的 TLS 握手、内部证据收集和 RST" width="100%">
</p>

第一个 SYN 是无状态的；只有收到 SYN-ACK 后才建立 TCB，可选的 TLS 握手运行在这份用户态状态里。原始帧绕过主机 TCP 协议栈，最后由 RST 结束这条流。

## 模块

下面的数量基于启用全部可选依赖的完整构建；缺少对应库的模块会直接消失。

### 扫描模块（11）

| 模块 | 探测 | 作用 |
|:---|:---:|:---|
| `tcp-syn` | — | 经典 SYN 扫描，用 SipHash cookie 作 ISN；可选 `--send-rst`。 |
| `udp` | UDP | 发送 UDP 载荷并校验响应。 |
| `zbanner` | TCP | 无状态 TCP 握手；载荷挂在第三个 ACK 上；抓取 banner。 |
| `tcp-state` | STATE | HLTCP 有状态 TCP；与 TLS/HTTP 状态探测配合使用。 |
| `icmp-echo` | — | ICMP echo 主机发现；可记录 TTL 和 IPID。 |
| `icmp-time` | — | ICMP 时间戳扫描。 |
| `sctp-init` | — | SCTP INIT 扫描。 |
| `arp-req` | — | LAN 模式下的二层 ARP 扫描。 |
| `ndp-ns` | — | IPv6 NDP 邻居请求。 |
| `yarrp-echo` | — | 用 ICMP echo 做无状态拓扑探测。 |
| `yarrp-udp` | — | 用 UDP + ICMP 错误包做无状态拓扑探测。 |

### 探测模块（27）

- **通用：** `http`（+ 状态）、`hello`（+ UDP/状态）、`tls-hello`、`tls-state`、`dns`、`snmp`、`echo`、`ssh`、`jarm`、`h2c`、`h2`。
- **指纹识别：** `recog`（+ UDP/状态，Recog XML）、`nmap`（+ UDP，nmap-service-probes）。
- **可脚本化：** `lua-tcp`、`lua-udp`——丢一个 Lua 脚本进去，你就有了一个探测。
- **基础件：** `get-state`、`close-state`、`null`。
- **开发示例：** `slot-test`、`slot-test-udp`——两个 `ProbeSlot_Always` 示例，可直接当模板阅读。

### 输出与生成模块

- **输出：** `text`、`csv`、`ndjson`、`bson`、`mongodb`、`list`、`null`。
- **生成：** `blackrock`（默认，无状态置换）、`ip-list`、`addr-list`、`ip-stream`、`addr-stream`。

自己写模块刻意保持朴素：每个模块就是一个 struct，再加 NULL 结尾的注册表里的一行；同一份元数据即可驱动 `--help-*`、参数解析、模糊搜索和交互式补全。可以在 [`src/scan-modules/scan-modules.c`](src/scan-modules/scan-modules.c) 及同类文件中找 `REGISTER YOUR ... MODULE HERE` 字样。

## 文档

README 是落地页，手册在 [`docs/`](docs/zh-CN/README.md) 目录下：

- [快速上手](docs/zh-CN/getting-started.md)——构建、权限、首次扫描、防火墙
- [目标与端口](docs/zh-CN/targets-and-ports.md)——IPv4/IPv6 输入、文件、ASN、排除、分片
- [扫描模式](docs/zh-CN/scanning-modes.md)——无状态与有状态、扫描/探测配对、常用配方
- [输出](docs/zh-CN/output.md)——结果级别、格式、MongoDB
- [模块](docs/zh-CN/modules.md)——四种模块类型以及 Xtate 自带的模块
- [模块开发](docs/zh-CN/module-development.md)——C 接口、注册和 slot plan 示例
- [架构](docs/zh-CN/architecture.md) · [ZBanner](docs/zh-CN/zbanner.md) · [HLTCP](docs/zh-CN/hltcp.md)
- [中文帮助与 i18n](docs/zh-CN/help-i18n.md)——`--lang`、catalog 回退与 UTF-8 排版
- [交互式模式](docs/zh-CN/interactive-mode.md)——TTY/脚本模式、补全、历史与中文帮助
- [平台支持](docs/zh-CN/platform-support.md)——CMake 3.13、旧发行版、Ninja 与 musl 构建
- [构建产物](docs/zh-CN/build-artifacts.md)——别名、按工具链命名、Debug/DLL 布局
- [测试规范](docs/zh-CN/testing.md)——改动后的 Tier 0/1/2 检查
- [故障排查](docs/zh-CN/troubleshooting.md) · [已知限制](docs/zh-CN/known-limitations.md)

英文文档：[`docs/`](docs/README.md)

## 构建

修改代码后的构建/测试矩阵见[测试规范](docs/zh-CN/testing.md)。

### Linux

```bash
sudo apt install build-essential cmake pkg-config libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev \
  libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev
./build.sh                                  # 交互：选择编译器和配置
./build.sh --compiler gcc --config release  # 显式指定
./build.sh --compiler clang --config debug  # 显式 Debug
./build.sh --generator ninja                # 使用 Ninja
./build.sh --static --minimal               # 基础 musl 静态构建
```

输出：`bin/xtate`（Release 别名）、`bin/xtate_debug`（Debug 别名），以及
`bin/xtate-<compiler>-<config>` 按工具链命名的文件。`--generator ninja|make`
选择 CMake 生成器；见[平台支持](docs/zh-CN/platform-support.md)。别名规则见[构建产物](docs/zh-CN/build-artifacts.md)。构建目录为
`build-<compiler>-<config>-<generator>`；`./clean.sh` 清理它们和 `bin/xtate*`，保留
`bin/.gitignore`。

Ubuntu 22.04/24.04 是参考环境。在 Fedora/Arch 上，请安装对应的开发包（`libpcap`、`openssl`、`pcre2`、`libxml2`、`libbson`、`mongo-c-driver`）。

PCRE2 的发现优先使用 CMake 包配置；在 Debian/Ubuntu 上会回退到 `pkg-config`，因此需要同时安装 `libpcre2-dev` 和 `pkg-config`。

推荐的编译器：GCC、Clang、MSVC 和 MinGW-w64。Xtate 要求 64 位小端主机；不满足时 CMake 会提前终止。

<details>
<summary><b>Windows 构建</b></summary>

安装 **Npcap**（运行时）、CMake，以及 Visual Studio 2022/2026 或 MinGW-w64。新手分步说明见 [Windows 快速上手](docs/zh-CN/windows-quickstart.md)；完整平台/工具链矩阵和问题排查见[快速上手](docs/zh-CN/getting-started.md)。

可选依赖可以用 Scoop 安装（MSVC/clang-cl）：

```powershell
scoop install openssl-lts lua54
```

Scoop 没有 PCRE2、libbson 或 libmongoc；需要完整 probe/output 集合时用 vcpkg，或接受较少的模块。

MSVC：

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
  -DOPENSSL_ROOT_DIR="$env:USERPROFILE\scoop\apps\openssl-lts\current"
cmake --build build-msvc --config Release -j 8
```

MinGW：

```powershell
cmake -S . -B build-mingw -G "MinGW Makefiles" `
  -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Release
cmake --build build-mingw -j 8
```

不带参数运行 `scripts\build-windows.ps1` 时，会交互选择**一种编译器和一种配置**；脚本会在复制源码到 ASCII 中转目录前询问，并在构建后清理中转目录。主二进制写入 `bin\xtate.exe`（Debug 为 `bin\xtate_debug.exe`），各工具链副本写入 `bin\xtate-<toolchain>-<config>.exe`（对应 Linux `build.sh` 的 `bin/xtate` 约定）。

三种工具链都支持 Release/Debug：使用 `-Config Debug` 配合
`-Toolchain msvc|clangcl|mingw`。只有显式传 `-Toolchain all` 才构建整套矩阵。

Npcap 是报文收发的必需项；`wpcap.dll` 在运行时加载。

清理 Windows 构建目录和二进制（对应 Linux 的 `clean.sh`）：

```powershell
pwsh -File .\scripts\clean-windows.ps1
pwsh -File .\scripts\clean-windows.ps1 -IncludeStage  # 同时删除 %LOCALAPPDATA%\xtate-build
```
</details>

<details>
<summary><b>可选依赖及其解锁的功能</b></summary>

| 依赖 | 解锁 | 开关 |
|:---|:---|:---|
| OpenSSL ≥ 1.1.1 | `tls-state`、`jarm`、TLS 相关探测 | `-DWITH_OPENSSL=OFF` |
| PCRE2（8 位） | `hello`、`http`、`recog`、`nmap` 中的正则匹配 | `-DWITH_PCRE2=OFF` |
| LibXml2 | Recog XML 指纹文件 | `-DWITH_LIBXML2=OFF` |
| libbson / libmongoc | BSON 和 MongoDB 输出 | `-DWITH_BSON=OFF`、`-DWITH_MONGOC=OFF` |
| libpcap / Npcap | 数据包 I/O（运行时） | 动态加载 |
| PF_RING | Linux 上的零拷贝数据包 I/O（运行时） | 可选 |
| Lua 5.3/5.4 | `lua-tcp`、`lua-udp`（运行时） | 可选 |

缺少可选库只会在编译时移除相应模块——核心扫描器仍可正常构建。Windows 上 CMake 可能提示 Conda 里的 PCRE2 找到但配置不完整，或提示 LibXml2/libbson/libmongoc 未安装；这些依赖都是可选的。需要对应模块时，请安装匹配的 vcpkg triplet（例如 `vcpkg install pcre2 libxml2 mongo-c-driver --triplet x64-windows`；MinGW/MSYS2 与完整安装说明见 [Windows 可选依赖](docs/zh-CN/windows-dependencies.md)）。
</details>

> [!NOTE]
> 原始套接字在 Linux 上需要 root，在 Windows 上需要管理员权限。在 Linux 上，如果你清楚自己在做什么，可以用 `sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate` 来替代每次运行都加 `sudo`。

## 探索 CLI

```bash
xtate --usage                 # short usage and examples
xtate --help                  # every global parameter
xtate --intro                 # the architecture tour
xtate --list-scan             # 11，若有 quic-state 则为 12
xtate --list-probe            # 27 probe modules
xtate --list-out              # 7 output modules
xtate --list-gen              # 5 generate modules
xtate --help-scan zbanner     # module-specific parameters
xtate --lang zh --help        # 中文人类帮助（未翻译内容回退英文）
xtate --interact              # interactive shell with tab completion
```

## 论文与引用

Xtate 的两个引擎源自我们的研究：

- **ZBanner: Fast Stateless Scanning Capable of Obtaining Responses over TCP**——[arXiv:2405.07409](https://arxiv.org/abs/2405.07409) · [IPCCC 2024](https://doi.org/10.1109/IPCCC59868.2024.10850469)
- **Efficient Application-Layer Scanning with Hybrid-State Lightweight TCP Stack for TLS-based Service Monitoring**——[ICCT 2024](https://doi.org/10.1109/ICCT62411.2024.10946306)
- **硕士学位论文：** *Research on Technologies of Network Protocol and Device Identification Based on Application-Layer Scanning*（NUDT，2024）

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

如果 Xtate 对你的研究有帮助，一次引用比一个 star 更让我们高兴。

## 参与贡献

欢迎贡献。构建/测试矩阵、C 与模块规范、PR 检查项见
[CONTRIBUTING.md](CONTRIBUTING.md)。安全漏洞请按 [SECURITY.md](SECURITY.md)
私密报告，不要开公开 issue。

## 许可证与负责任使用

AGPL-3.0。见 [LICENSE](LICENSE)。如果你把修改过的 Xtate 作为网络服务运行，AGPL 的网络使用条款就会生效。

> [!WARNING]
> Xtate 是用于测量与安全研究的双用途工具。请只在你自己拥有、或已获得书面许可测试的网络上使用。遵守当地法律、ISP 政策以及目标网络的规则，是你的责任。

Xtate 起源于 [Masscan](https://github.com/robertdavidgraham/masscan) 的代码库；感谢 Robert Graham 以及源码中提到的所有上游项目。Xtate 是 [404Starlink](https://github.com/knownsec/404StarLink) 的成员。

作者 **Alvin Chen**（陈驰昱）· [shineccy@aliyun.com](mailto:shineccy@aliyun.com)。最初的代码写于他在国防科技大学攻读硕士期间，以及安徽省网络空间安全态势感知与评估重点实验室。

<div align="center">
  <sub>God is Stateless. 物理层？我们止步于网线。</sub>
</div>
