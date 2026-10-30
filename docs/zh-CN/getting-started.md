# 快速上手

[English](../getting-started.md) · **中文**

Xtate 是一款面向大规模主动测量的模块化全栈网络扫描器。它发送原始 IPv4/IPv6 报文，尽量不在本地保留逐目标状态，并把回包转换成结构化结果——从一个 SYN 到一次完整的 TLS 握手。

本页带你在 Linux 或 Windows 上从源码检出走到第一次扫描。阅读前你应当熟悉 shell、`sudo` 和 TCP/IP 基础；本页不是扫描方法本身的教程。

> 本文档针对 Xtate v2.14.0 编写。若你的构建行为与此不同，以 `--help` 和模块帮助为准。

## 环境要求

| 项目 | 要求 |
|:---|:---|
| 操作系统 | Linux（参考环境为 Ubuntu 22.04/24.04）或 Windows |
| CPU | 仅支持 64 位**小端**；否则 CMake 会提前终止 |
| 构建系统 | CMake ≥ 3.20 与 C99 编译器（GCC、Clang、MSVC、MinGW-w64） |
| 报文收发 | libpcap（Linux）或 Npcap（Windows，运行时） |
| 权限 | root，或 `CAP_NET_RAW`+`CAP_NET_ADMIN`；Windows 上为管理员 |

## 在 Linux 上构建

```bash
sudo apt install build-essential cmake libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev

git clone https://github.com/babycoff/xtate.git
cd xtate
./build.sh                 # release build -> ./bin/xtate
./build.sh debug clang     # debug build with Clang -> ./bin/xtate_debug
```

`build.sh` 会清空 `build/`、配置 CMake，并把生成的二进制复制到 `bin/`。Fedora/Arch 上安装对应的软件包（`libpcap`、`openssl`、`pcre2`、`libxml2`、`libbson`、`mongo-c-driver`）。

### 可选依赖

缺少这些库不会让构建失败：依赖它们的模块会在编译期直接消失。

| 依赖 | 解锁的功能 | 关闭开关 |
|:---|:---|:---|
| OpenSSL ≥ 1.1.1 | `tls-state`、`jarm`、TLS 相关探测 | `-DWITH_OPENSSL=OFF` |
| PCRE2（8-bit） | `hello`、`http`、`recog`、`nmap` 中的正则匹配 | `-DWITH_PCRE2=OFF` |
| LibXml2 | Recog XML 指纹文件 | `-DWITH_LIBXML2=OFF` |
| libbson / libmongoc | `bson` 与 `mongodb` 输出 | `-DWITH_BSON=OFF`、`-DWITH_MONGOC=OFF` |

Lua 5.3/5.4 与 PF_RING 在运行时加载，而不是链接期依赖：`lua-tcp`/`lua-udp` 需要 Lua 共享库，PF_RING 则是 Linux 上可选的加速手段。

## 在 Windows 上构建

安装 **Npcap**（负责报文收发）、CMake，以及 MSVC 或 MinGW-w64。可选库可以通过 vcpkg 获取：

```powershell
vcpkg install openssl pcre2 libxml2 mongo-c-driver

cmake -B build -G "Visual Studio 17 2022" `
  -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
```

MinGW/Clang 配 Unix Makefiles 的写法：

```powershell
cmake -B build -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc
cmake --build build
```

Npcap 是报文收发的必需项；`wpcap.dll` 在运行时加载。请在管理员权限的终端中运行 `xtate.exe`。

## 权限

原始套接字在 Linux 上需要 root，在 Windows 上需要管理员权限。如果不想每次运行都加 `sudo`，可以给二进制授予所需的 Linux capability：

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate
```

每次重新构建后都要重新执行：capability 附着在可执行文件上，而不是源码树上。Windows 上，提升权限即可达到同样效果。

## 第一次扫描

经典的**无状态** SYN 扫描不需要任何防火墙技巧：

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

预期现象：

- 回包到达时结果实时写到 **stdout**，每个主机/端口一行：`[+] host: 192.168.1.10 port: 80 "open" because "syn-ack"`。
- 默认只显示 `success` 等级的结果。对 `tcp-syn` 来说，关闭端口属于 `failed` 等级（`"closed" because "rst"`）；`zbanner` 的开放/关闭结果默认是 `info` 等级，除非你主动提升。加上 `-show failed` 和/或 `-show info` 才能看到更多。
- 实时状态栏（速率、进度、队列水位）画在 **stderr** 上，所以 `... > results.txt` 重定向不会弄脏结果文件。`--no-status` 可以关掉状态栏。
- 网卡会自动选为第一个带默认网关的接口；用 `--list-if` 列出网卡，用 `-if eth0` 指定。
- TCP/UDP 扫描务必给出 `-p`。完全不给端口时 Xtate 会告警并替换成一个假的 `o:0` 端点，它不是 TCP/UDP 端口，扫描因此不会发出任何报文。
- 按一次 `Ctrl-C` 即可停止：发送停止后，迟到的回包仍会在 `--wait` 秒内（默认 10）被继续收集。再按一次 `Ctrl-C` 会强制中止。

## banner 扫描：阻止内核代为应答

`zbanner` 和 `tcp-state` 会完成真实的 TCP 握手。Linux 内核并不认识这些连接，会用 RST 回应收到的 SYN-ACK/数据，在 banner 到达前就把连接打断。扫描期间需要抑制这种行为：

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http \
  -scan-arg "-banner" -rate 1000 -show info
./firewall/rm_rules.sh
```

- `add_rules.sh` 会追加 `OUTPUT` 链上的 DROP 规则，丢弃 TCP RST（IPv4 与 IPv6），以及 ICMP 端口不可达（ICMP 3/3、ICMPv6 1/4）。`rm_rules.sh` 负责删除；`check_rules.sh` 打印当前规则。
- 这些规则是**主机全局**的：生效期间，本机发出的每一个 RST 都会被丢弃，包括无关的 SSH/浏览器会话。扫描前添加，扫描后立即删除——绝不要长期保留。
- 模块专属参数通过 `-scan-arg` 和 `-probe-arg` 以带引号的字符串传入；例如 `-scan-arg "-banner -ttl"` 会把 `-banner` 和 `-ttl` 传给扫描模块。
- Windows 上没有随仓库提供的等价脚本。SYN 扫描照常工作，但基于握手的 banner 扫描能否成功，取决于 Windows 协议栈是否会重置该连接。

## 下一步

| 目标 | 阅读 |
|:---|:---|
| 构建目标列表与端口范围 | [目标与端口](./targets-and-ports.md) |
| 选择扫描/探测组合 | [扫描模式](./scanning-modes.md) |
| 保存或转换结果 | [输出](./output.md) |
| 排查“没有结果”的问题 | [故障排查](./troubleshooting.md) |
| 了解 Xtate 不做什么 | [已知限制](./known-limitations.md) |
| 查看特性列表与论文 | [README](../../README.zh-CN.md) |

CLI 本身也能说明用法：`--usage`、`--help`、`--intro`、`--list-scan`、`--list-probe`、`--list-out`、`--list-gen`，以及按模块查看参数的 `--help-scan <module>` / `--help-probe <module>`。
