# 01 · 安装与快速上手

[English](../../manual/01-install-and-quickstart.md) · **中文**

本章带你从源码检出走到一个已验证的二进制、第一次命令行扫描，以及 3.0 控制台的第一次会话。假定你有 shell、Linux 上的 `sudo`，或 Windows 上已提权的 PowerShell。

只在你拥有或已获得书面许可测试的网络上使用。Xtate 发送真实报文；真实扫描没有无害的"测试模式"。

## 你需要什么

| 项目 | 要求 |
|:---|:---|
| 操作系统 | Linux（参考 Ubuntu 22.04/24.04）或 Windows 10/11 |
| CPU | 仅 64 位小端；否则构建会提前停止 |
| 数据包 I/O | libpcap（Linux）或 WinPcap 兼容模式的 Npcap（Windows） |
| 权限 | Linux 上 root 或 `CAP_NET_RAW`+`CAP_NET_ADMIN`；Windows 上管理员 |
| 构建 | CMake ≥ 3.13 与 C99 编译器（GCC、Clang、MSVC 或 MinGW-w64） |

## 验证或构建二进制

检出目录里可能已有预编译的 `bin/xtate.exe`（Windows）或 `bin/xtate`（Linux）。先验证它：

```bash
./bin/xtate --version
./bin/xtate --selftest
```

`--version` 打印发布版本、编译器、操作系统以及找到的可选库（OpenSSL、PCRE2、LibXml2、libbson、libmongoc）。`--selftest` 运行内置回归套件，有测试失败时以非零码退出。

### 在 Linux 上构建

```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev \
  libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev

./build.sh --compiler gcc --config release
./bin/xtate --version
./bin/xtate --selftest
```

不带参数的 `./build.sh` 会询问编译器和构建配置。手动 CMake 构建也可以：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 8
./build/xtate --version
```

### 在 Windows 上构建

1. 安装 Visual Studio 2022 或 2026，勾选 **使用 C++ 的桌面开发**。
2. 安装 CMake ≥ 3.13 和 Npcap（WinPcap 兼容模式）。
3. 安装 OpenSSL：`scoop install openssl-lts`。
4. 可选：安装 vcpkg 依赖，获得完整模块集与 zstd 结果压缩：

   ```powershell
   scoop install vcpkg
   vcpkg install pcre2 libxml2 mongo-c-driver zstd --triplet x64-windows
   ```

   `scripts\build-windows.ps1` 会自动读取 `VCPKG_ROOT` 并传入工具链。若手动执行下面的 CMake 命令，还需加
   `-DCMAKE_TOOLCHAIN_FILE="$env:USERPROFILE\scoop\apps\vcpkg\current\scripts\buildsystems\vcpkg.cmake"`。

5. 在普通 PowerShell 中构建（扫描仍需要提权的 shell）：

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
  -DOPENSSL_ROOT_DIR="$env:USERPROFILE\scoop\apps\openssl-lts\current"
cmake --build build-msvc --config Release -j 8
.\build-msvc\Release\xtate.exe --version
.\build-msvc\Release\xtate.exe --selftest
```

或者让构建脚本选择工具链并验证结果：

```powershell
pwsh -File .\scripts\build-windows.ps1 -Toolchain msvc -Config Release -Yes
```

完整构建有 12 个扫描、60 个探测、7 个输出模块和 5 个生成模块。没有 ngtcp2/GnuTLS（Windows 上的默认情况）时应为 11 个扫描、59 个探测；缺少 PCRE2 或 OpenSSL 会再移除一些探测。模块变少不是构建失败——它表示某个可选库没有被找到。没有 zstd 时，`--result-compress=zstd` 会回退为未压缩分片，`--list-capabilities` 显示 `zstd:false`。完整依赖矩阵见[快速上手](../getting-started.md)。

### 权限

原始套接字需要权限。在 Linux 上，可以给每次构建出的二进制授予一次 capabilities，不必每次都 `sudo`：

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate
```

在 Windows 上，先安装 Npcap，再从提权的 shell 运行扫描。

## 第一次扫描

无状态 TCP SYN 扫描不需要改防火墙：

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

你应该看到：

- **stdout** 上每个主机/端口一行结果，例如
  `[+] host: 192.168.1.10 port: 80 "open" because "syn-ack"`。
- 默认只有 `success` 等级的结果。加 `-show failed` 查看关闭端口，加 `-show info` 查看提示记录，加 `-show all` 查看全部。
- **stderr** 上有一条实时状态栏，因此 `> results.txt` 能保持文件干净。`--no-status` 可关闭它。
- `Ctrl-C` 停止发送；迟到的回包会在 `--wait` 秒内被继续收集（默认 10）。再按一次 `Ctrl-C` 立即中止。

端口型扫描（`tcp-syn`、`zbanner`、`tcp-state`、`udp`、`sctp-init`、`yarrp-udp`）必须提供端口。没有 `-p` 时 Xtate 会警告并塞入一个假的 `o:0` 端点，它什么都不发。

### 扫描前检查路由

```bash
./bin/xtate --list-if
./bin/xtate --explain-target 192.168.1.0/24
./bin/xtate --check --explain-target 192.168.1.0/24
```

`--list-if` 列出网卡及其 IPv4、MAC、网关和状态。`--explain-target` 对目标集合做只读的路由摘要。`--check` 额外做网卡、源地址、网关和 Linux 防火墙规则的预检；检查失败时以非零码退出。

如果有多个默认接口而省略了 `-if`，Xtate 会以歧义错误失败关闭，而不是猜测。用 `-if 3` 或唯一的描述子串固定一个接口，例如 `-if "Intel(R) Wi-Fi"`。

## 有状态扫描在 Linux 上需要防火墙规则

`zbanner`、`tcp-state`、`tls-state`、`http-state` 以及所有 state 子探测都用原始报文完成真实 TCP 握手。Linux 内核不认识这些连接，会用 RST 回应对端，打断流程。在这样的扫描期间，抑制出向 RST：

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe http \
  -scan-arg "-banner" -rate 1000 -show info
./firewall/rm_rules.sh
```

这些规则是主机全局的，生效期间会影响无关流量。扫描前添加，扫描后立即删除。Windows 上没有随附的等价脚本；运行有状态扫描前，请阅读[快速上手](../getting-started.md)与[已知限制](../known-limitations.md)中的 Windows 说明。

## 第一次 GUI 会话

不接已有控制面时，控制台会启动它自己的私有控制面：

```bash
sudo ./bin/xtate --gui
```

进程会打印监听 URL、控制端点和每会话 token。它**不会**启动浏览器；请自行打开打印出的地址。默认地址是 `http://127.0.0.1:8787/`；`--gui-listen=127.0.0.1:0` 会挑选一个空闲端口。只接受回环地址。

在浏览器中：

1. 在 **New scan** 页保留或修改目标范围。**Use sample** 会填入一个可以安全输入、但不是真实目标的文档示例范围。
2. 选择扫描卡片、端口（默认 `80,443`）、可选的探测、速率和超时。
3. 除非路由有歧义或你要通过 TUN/VPN 网卡扫描，否则把 **Interface** 留在 *Auto (from route)*。
4. 等待 **Preflight** 通过。它检查模块目录、端口、目标和路由，不发送报文。
5. 勾选授权复选框。只有预检通过且确认授权后，**Start scan** 才会启用。

扫描开始后会停在 **Live scan** 页面。你可以离开该页；守护进程会继续运行扫描。通过私有 GUI 启动的 job 会随 GUI 进程退出而停止；用 `--control-connect` 接入一个比控制台活得更久的守护进程（见 [02 · GUI 控制台](./02-gui-console.md)）。

## 下一步

| 目标 | 阅读 |
|:---|:---|
| 逐页了解控制台页面与字段 | [02 · GUI 控制台](./02-gui-console.md) |
| 扫描/探测示例、控制面、托管 job | [03 · CLI 与 job](./03-cli-and-jobs.md) |
| 目标与端口语法 | [目标与端口](../targets-and-ports.md) |
| 选择扫描引擎与探测 | [扫描模式](../scanning-modes.md) |
| 保存、分片或转换结果 | [输出](../output.md) |
| 解决空结果或异常结果 | [故障排查](../troubleshooting.md) |
| Windows 专项 | [Windows 快速上手](../windows-quickstart.md) |
| 防火墙规则详解 | [防火墙](../firewall.md) |
