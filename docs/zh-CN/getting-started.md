# 快速上手

[English](../getting-started.md) · **中文**

Xtate 是一款面向大规模主动测量的模块化全栈网络扫描器。它发送原始 IPv4/IPv6 报文，尽量不在本地保留逐目标状态，并把回包转换成结构化结果——从一个 SYN 到一次完整的 TLS 握手。

本页带你在 Linux 或 Windows 上从源码检出走到第一次扫描。阅读前你应当熟悉 shell、`sudo` 和 TCP/IP 基础；本页不是扫描方法本身的教程。

> 本文档针对 Xtate v2.20.3 编写。若你的构建行为与此不同，以 `--help` 和模块帮助为准。

## 环境要求

| 项目 | 要求 |
|:---|:---|
| 操作系统 | Linux（Ubuntu 22.04/24.04 为参考环境）或 Windows 10/11 |
| CPU | 仅支持 64 位**小端**；不满足时 CMake 会提前终止 |
| 构建系统 | CMake ≥ 3.20 与 C99 编译器（GCC、Clang、MSVC、MinGW-w64） |
| 报文 I/O | Linux 用 libpcap，Windows 用 Npcap（运行时依赖） |
| 权限 | root，或 `CAP_NET_RAW`+`CAP_NET_ADMIN`；Windows 上为管理员 |

## 构建矩阵

这些组合会在发布前实际验证。“完整”表示所有可选依赖都找到，模块全部编译进来。

| 平台 | 编译器 | 状态 | 可选依赖 |
|:---|:---|:---|:---|
| Ubuntu 24.04 | GCC 13.3 | 构建 + `--selftest` 通过，模块 11/60/7/5 | OpenSSL、PCRE2、LibXml2、BSON、mongoc |
| Ubuntu 24.04 | Clang 18.1 | 构建 + `--selftest` 通过，模块 11/60/7/5 | OpenSSL、PCRE2、LibXml2、BSON、mongoc |
| Windows 10/11 | MSVC 19.5x（Visual Studio 2022/2026） | 构建 + `--selftest` 通过，模块 11/54/5/5 | 通过 Scoop 装 OpenSSL；未装 PCRE2/BSON/mongoc |
| Windows 10/11 | Clang 23（clang-cl） | 构建 + `--selftest` 通过，模块 11/54/5/5 | 通过 Scoop 装 OpenSSL；未装 PCRE2/BSON/mongoc |
| Windows 10/11 | MinGW-w64 GCC 16 | 构建 + `--selftest` 通过，模块 11/52/5/5 | 无 OpenSSL（Scoop 包是 MSVC ABI） |

模块数量是最快的自检方式：**60 probe + 7 output** 表示依赖齐全；数量变少说明至少有一个可选库没有被找到。

## 在 Linux 上构建

在 Debian/Ubuntu 上安装完整依赖：

```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev

git clone https://github.com/babycoff/xtate.git
cd xtate
```

### 使用 build.sh 快速构建

```bash
./build.sh                 # Release，GCC   -> ./bin/xtate
./build.sh clang           # Release，Clang -> ./bin/xtate
./build.sh debug           # Debug，GCC     -> ./bin/xtate_debug
./build.sh debug clang     # Debug，Clang   -> ./bin/xtate_debug
```

`build.sh` 会清空 `build/`、配置 CMake，并把产物复制到 `bin/`。双参数形式分别接受 `debug` 和/或编译器名。

### 手动 CMake 构建

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 8
./build/xtate --version
./build/xtate --selftest
```

Clang 构建：

```bash
cmake -S . -B build-clang -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang
cmake --build build-clang -j 8
```

Fedora/Arch 上安装对应软件包（`libpcap`、`openssl`、`pcre2`、`libxml2`、`libbson`、`mongo-c-driver`）。

### Linux 可选依赖

缺少这些库不会让构建失败：依赖它们的模块会在编译期直接消失。

| 依赖 | 解锁的功能 | 关闭开关 |
|:---|:---|:---|
| OpenSSL ≥ 1.1.1 | `tls-state`、`jarm`、TLS 相关探测 | `-DWITH_OPENSSL=OFF` |
| PCRE2（8-bit） | `hello`、`http`、`recog`、`nmap` 中的正则匹配 | `-DWITH_PCRE2=OFF` |
| LibXml2 | Recog XML 指纹文件 | `-DWITH_LIBXML2=OFF` |
| libbson / libmongoc | `bson` 与 `mongodb` 输出 | `-DWITH_BSON=OFF`、`-DWITH_MONGOC=OFF` |

Debian/Ubuntu 的 `libpcre2-dev` 只提供 pkg-config 元数据，不提供 CMake 包配置；构建时会自动回退到 `pkg-config`。因此需要同时安装 `pkg-config` 和 `libpcre2-dev`，否则 `--version` 会显示 `PCRE2 (null)`，并少 6 个 probe。

Lua 5.3/5.4 与 PF_RING 在运行时加载，而不是链接期依赖：`lua-tcp`/`lua-udp` 需要 Lua 共享库，PF_RING 则是 Linux 上可选的加速手段。

## 在 Windows 上构建

### 前置条件

1. **Visual Studio 2022 或 2026**，安装“使用 C++ 的桌面开发”工作负载；或者安装 **MinGW-w64**（`scoop install mingw`）。
2. **CMake ≥ 3.20**（`scoop install cmake`）。
3. **Npcap**，安装时启用 WinPcap 兼容模式，用于报文收发。`wpcap.dll` 是运行时依赖，编译时不需要，但没有它无法真正扫描。
4. 64 位小端主机。以下命令在普通 PowerShell 或 `cmd.exe` 中执行；真正扫描时使用管理员终端。

Visual Studio 是功能最完整的方案；`clang-cl` 共用 MSVC ABI，也可以正常工作。MinGW 受两个限制：

- Scoop 的 OpenSSL 包是 MSVC ABI，MinGW 无法直接链接。
- 源码路径包含非 ASCII 字符（例如中文目录）时，`MinGW Makefiles` 生成器可能失败。此时应使用 ASCII 中转路径，或使用下面介绍的构建脚本。

### Windows 可选依赖

用 Scoop 安装 OpenSSL 和 Lua 最方便：

```powershell
scoop install openssl-lts
scoop install lua54
```

- `openssl-lts` 提供 OpenSSL 3.x 的 MSVC 导入库，适用于 MSVC 和 `clang-cl`，**不能用于 MinGW**。
- 选择 `lua54` 是因为运行时只查找 `lua53.dll`、`lua54.dll` 或 `lua.dll`。Scoop 默认的 `lua` 是 5.5，只提供 `lua55.dll`，当前代码不会加载。
- 如果 CMake 没有自动找到 Scoop 的 OpenSSL，显式传入根目录：
  `-DOPENSSL_ROOT_DIR="$env:USERPROFILE\scoop\apps\openssl-lts\current"`。

Scoop 目前没有 PCRE2 开发文件、libbson 或 libmongoc。要获得完整的 probe/output 集合，请使用 vcpkg（可先通过 Scoop 安装）：

```powershell
scoop install vcpkg
vcpkg install pcre2 libxml2 mongo-c-driver --triplet x64-windows

cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$env:USERPROFILE\scoop\apps\vcpkg\current\scripts\buildsystems\vcpkg.cmake"
```

没有 PCRE2 时，Windows 构建得到 54 个 probe 而不是 60 个；没有 libbson/mongoc 时，得到 5 个 output 而不是 7 个。这是依赖缺失的预期结果，不是构建失败。

### MSVC

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
  -DOPENSSL_ROOT_DIR="$env:USERPROFILE\scoop\apps\openssl-lts\current"
cmake --build build-msvc --config Release -j 8

.\build-msvc\Release\xtate.exe --version
.\build-msvc\Release\xtate.exe --selftest
```

Visual Studio 2026 使用 `-G "Visual Studio 18 2026"`。`--selftest` 现在是发布门槛的一部分：任何回归测试失败都会返回非零退出码。

### ClangCL

`clang-cl` 需要 MSVC 链接器和 Windows SDK。先进入 Visual Studio 开发者环境：

```powershell
cmd /c "call ""C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat"" && cmake -S . -B build-clang -G Ninja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=""%USERPROFILE%\scoop\apps\openssl-lts\current"" && cmake --build build-clang -j 8"
```

请根据你的 Visual Studio 安装位置和版本调整路径。如果不想手动管理 `vcvars64.bat` 和 Ninja，可以直接使用下面的构建脚本。

### MinGW

```powershell
cmake -S . -B build-mingw -G "MinGW Makefiles" `
  -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Release
cmake --build build-mingw -j 8

.\build-mingw\xtate.exe --version
.\build-mingw\xtate.exe --selftest
```

如果源码路径包含非 ASCII 字符，不要直接原地构建，改用构建脚本的 ASCII 中转模式：

```powershell
pwsh -File .\scripts\build-windows.ps1 -Toolchain mingw
```

脚本会说明复制位置，征得确认后再复制，并在构建结束后删除中转的源码/构建目录。

### 自动化 Windows 构建脚本

`scripts/build-windows.ps1` 可以构建 MSVC、MinGW 和 ClangCL，对每个产物运行 `--version` 和 `--selftest`，并把可执行文件放到固定目录。

```powershell
# 复制源码到中转目录前会先询问
pwsh -File .\scripts\build-windows.ps1

# 非交互：预先同意中转，构建三种工具链
pwsh -File .\scripts\build-windows.ps1 -Toolchain all -Yes

# 只构建一个工具链，使用 Debug 配置
pwsh -File .\scripts\build-windows.ps1 -Toolchain msvc -Config Debug -Yes
```

脚本流程：

1. 显示源码路径、中转路径和产物路径。
2. **复制前请求你确认**。默认中转根目录是 `%LOCALAPPDATA%\xtate-build`，源码会复制到 `%LOCALAPPDATA%\xtate-build\src`。
3. 复制时排除 `.git`、`build`、`bin` 和 `results`。
4. 在 `%LOCALAPPDATA%\xtate-build\build-*` 下构建请求的工具链。
5. 逐个运行 `--version` 和 `--selftest`，任一失败则脚本失败。
6. 把可执行文件复制到 `%LOCALAPPDATA%\xtate-build\artifacts`。
7. 删除中转的源码和构建目录；**产物目录保留**。

可用参数：

| 参数 | 作用 |
|:---|:---|
| `-Toolchain msvc|mingw|clangcl|all` | 选择要构建的编译器 |
| `-Config Release|Debug` | 构建配置 |
| `-Yes` | 预先同意中转，跳过询问 |
| `-KeepStage` | 保留中转源码/构建目录，便于排查 |
| `-StageRoot <path>` | 指定其他中转根目录 |

脚本不会静默复制：不加 `-Yes` 时会等待你的确认，并且不会删除 artifacts 目录。

### 运行与验证

```powershell
.\build-msvc\Release\xtate.exe --version
.\build-msvc\Release\xtate.exe --selftest
```

`--version` 会显示编译器、OpenSSL/PCRE2/BSON 版本以及哪些可选库被找到；`--selftest` 运行内置回归测试，失败时返回非零退出码。真正扫描时，请在管理员终端中运行 `xtate.exe`，并确保 Npcap 已安装。

## 构建问题排查

| 现象 | 原因与处理 |
|:---|:---|
| `CMake Error: Not a file: .../CMakeFiles/VerifyGlobs.cmake` | 源码路径含非 ASCII 字符，MinGW Makefiles 编码错乱。使用 ASCII 中转路径或 `scripts/build-windows.ps1`。 |
| MinGW 报 `Could NOT find OpenSSL ... missing OPENSSL_CRYPTO_LIBRARY` | Scoop 的 OpenSSL 是 MSVC 包。改用 MSVC/clang-cl，或提供 MinGW 版本的 OpenSSL。 |
| `--version` 显示 `PCRE2 (null)` | 没找到 PCRE2 头文件/库。Debian/Ubuntu 安装 `libpcre2-dev` 和 `pkg-config`；Windows 用 vcpkg（Scoop 没有 PCRE2 开发包）。 |
| `OpenSSL (null)`，probe 只剩 52 个 | OpenSSL 被跳过。Windows 用 MSVC/clang-cl + Scoop OpenSSL；Linux 安装 `libssl-dev`。 |
| 缺少 `bson`/`mongodb` 输出模块 | 没找到 libbson/libmongoc；安装它们，或接受较少的 output 集合。 |
| `--selftest` 报 `timing error` | 2.20.3 已修复 Windows 上过严的 1% 计时容差；旧版本请更新到当前代码。 |
| `--selftest` 返回非零 | 现在会把它当作真实失败；输出会打印 `Regression test: failed`，进程退出码非零。 |
| 运行时提示 `wpcap.dll`/`Npcap` 错误 | 安装 Npcap 并启用 WinPcap 兼容模式；它是运行时依赖，不是编译依赖。 |
| 找不到 `lua53.dll`/`lua54.dll` | 用 Scoop 安装 `lua54`，把 `%USERPROFILE%\scoop\apps\lua54\current` 加入 `PATH`，或把 `lua54.dll` 复制到 `xtate.exe` 旁边。 |

构建成功后遇到的运行时问题，见[故障排查](./troubleshooting.md)。

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
- Windows 上没有随仓库提供的等价脚本。Windows 协议栈不会对未知半开连接发 RST，所以 `tcp-syn` 需要加 `-scan-arg "--send-rst"`，在收到 SYN-ACK 后主动关闭半开连接。`zbanner` 默认在 banner 后自己发 RST（除非 `--no-rst`）；`tcp-state` 关闭时也会发 RST。Windows 仍需要 Npcap 和管理员权限。

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
