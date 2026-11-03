# Windows 快速上手（新手版）

[English](../windows-quickstart.md) · **中文**

本文面向 **第一次在 Windows 10/11 x64 上尝试 Xtate** 的用户。由于 Release
不一定附带 Windows 可执行文件，本文按“从源码构建”的方式说明。这里只构建核心
扫描器；`tcp-syn` 和基础 TCP 探测不需要可选库。TLS/PCRE2/XML/MongoDB 等可选依赖见
[Windows 可选依赖](./windows-dependencies.md)。

> 真正扫描需要管理员权限和 Npcap 驱动；构建和 `--selftest` 不需要 Npcap。

## 1. 需要什么

| 组件 | 用途 | 首次构建是否必须 |
|:---|:---|:---|
| Windows 10/11 x64 | 支持平台 | 是 |
| PowerShell | 构建和运行命令 | 是 |
| Git for Windows | 下载源码 | 是 |
| Visual Studio 2022 Build Tools，带 **使用 C++ 的桌面开发** | MSVC 编译器、Windows SDK | 是 |
| CMake | 配置项目 | 是 |
| [Npcap](https://npcap.com/#download) | 抓包/发包驱动 | 只在真正扫描时需要 |
| Ninja | 更快的构建；ClangCL 需要 | 可选 |
| OpenSSL / PCRE2 / LibXml2 / MongoDB | 仅可选模块 | 否 |

Npcap 请只从官网下载，不要用第三方镜像。

## 2. 安装依赖

打开普通 PowerShell（先不用管理员），执行：

```powershell
winget install --id Git.Git -e
winget install --id Kitware.CMake -e
winget install --id Microsoft.VisualStudio.2022.BuildTools -e `
  --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --id Ninja-build.Ninja -e
```

如果 `winget` 不可用，手动安装：

- Git：<https://git-scm.com/download/win>
- CMake：<https://cmake.org/download/>
- Visual Studio Build Tools / Community：
  <https://visualstudio.microsoft.com/downloads/>
  - 勾选 **使用 C++ 的桌面开发**；
  - 包含 Windows 10/11 SDK 和 MSVC 编译器。

安装完成后关闭并重新打开 PowerShell，让 `git`、`cmake` 和编译器进入 `PATH`。

验证：

```powershell
git --version
cmake --version
```

### 安装 Npcap

从官网下载安装包：

<https://npcap.com/#download>

安装时：

1. 允许以管理员权限运行；
2. **勾选 “Install Npcap in WinPcap API-compatible Mode”**。
   Xtate 运行时动态加载 `wpcap.dll`，兼容模式会把 DLL 放到 Windows 能直接找到的位置；
3. 没有特殊需求就使用默认服务/驱动选项；
4. 如果安装器要求重启，请重启。

检查服务：

```powershell
Get-Service *npcap*
```

> 构建 Xtate **不需要** Npcap SDK；源码在运行时动态加载 pcap API。Npcap
> 运行时/驱动只在真正扫描时需要。

## 3. 下载并构建

在 PowerShell 中：

```powershell
git clone https://github.com/babycoff/xtate.git
cd xtate
```

构建推荐的 MSVC Release：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1 `
  -Toolchain msvc -Config Release -Yes
```

脚本会：

- 把源码复制到 `%LOCALAPPDATA%\xtate-build` 下的 ASCII 路径；
- 查找 Visual Studio 并用 CMake 构建；
- 把主程序写到 `bin\xtate.exe`；
- 在 `bin\` 和 `artifacts\` 保留各工具链的副本。

如果 PowerShell 拒绝运行脚本：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

这只影响当前窗口。

### 验证

以下命令不需要管理员权限，也不需要 Npcap：

```powershell
.\bin\xtate.exe --version
.\bin\xtate.exe --selftest
```

成功时会看到：

```text
Regression test: success!
```

需要 Debug 版本时：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1 `
  -Toolchain msvc -Config Debug -Yes
.\bin\xtate_debug.exe --selftest
```

## 4. 第一次扫描

打开 **管理员终端**：

- 右键开始菜单 → **终端（管理员）**，或
- 右键 PowerShell → **以管理员身份运行**。

进入仓库目录：

```powershell
cd C:\path\to\xtate
```

列出网卡：

```powershell
.\bin\xtate.exe --list-if
```

选择连接测试网络的网卡，然后扫描一个**你拥有或获准测试的私有网段**：

```powershell
.\bin\xtate.exe -if "Ethernet" -ip 192.168.1.0/24 -p 80 `
  -scan tcp-syn -rate 1000 -show failed
```

说明：

- 网卡名带空格时要加引号；
- `-show failed` 才会显示 closed 端口；
- 先用 `-rate 1000` 这种低速率；
- **不要**扫描公网或未授权网络；
- Windows 上 `tcp-syn` 可加 `-scan-arg "--send-rst"` 主动关闭半开连接。

输出可能类似：

```text
open  192.168.1.10:80
closed 192.168.1.11:80
```

## 5. 可选功能

核心构建足够运行 `tcp-syn` 和基础 TCP 探测。可选模块：

| 功能 | 依赖 | 安装方式 |
|:---|:---|:---|
| TLS 探测（`tls-hello`、`tls-state`） | OpenSSL | 见 [Windows 可选依赖](./windows-dependencies.md) |
| regex/Recog 探测 | PCRE2 | 同上 |
| XML/Recog 解析 | LibXml2 | 同上 |
| BSON/MongoDB 输出 | libbson + libmongoc | 同上 |

`--version` 对缺失的可选库显示 `(null)`，这不是构建失败。

`zbanner` 和 `tcp-state` 在 Linux 上需要内核 RST 抑制；Windows 上走 Npcap，行为不同。
第一次尝试请先用 `tcp-syn` 和私有目标。使用这两个引擎前请阅读
[ZBanner](./zbanner.md) 和 [HLTCP](./hltcp.md)。

## 6. 常见问题

| 现象 | 可能原因 | 解决 |
|:---|:---|:---|
| `Visual Studio not found` / 找不到 MSVC | 没装 C++ 工作负载 | 打开 Visual Studio Installer，勾选 **使用 C++ 的桌面开发** |
| `cmake`/`git` 找不到 | 安装后没有重开终端 | 关闭并重新打开 PowerShell |
| `wpcap.dll` 找不到 / 没有网卡 | Npcap 未安装或未开兼容模式 | 重新安装 Npcap，勾选 WinPcap 兼容模式 |
| `--list-if` 没有网卡 | 非管理员、驱动未运行或网卡禁用 | 用管理员终端；检查 `Get-Service *npcap*`；启用网卡 |
| `Access is denied` / 没有包 | 没有管理员权限 | 以管理员身份运行终端 |
| 构建脚本因路径失败 | MinGW + 非 ASCII 路径 | 先用 MSVC 构建；脚本本身会把构建目录放到 ASCII 路径 |
| Windows Defender/防火墙弹窗 | Npcap 驱动/发包权限 | 在测试网络中允许该驱动/终端 |
| 扫描没有回包 | 目标/防火墙/路由问题 | 先用已知主机测试；见[故障排查](./troubleshooting.md) |

## 7. 清理

删除项目构建目录和二进制：

```powershell
pwsh -File .\scripts\clean-windows.ps1
```

同时删除 staging 目录：

```powershell
pwsh -File .\scripts\clean-windows.ps1 -IncludeStage
```

不再需要抓包时，可在 **设置 → 应用** 中卸载 Npcap。

## 8. Windows CI 覆盖什么

仓库的 Windows CI 使用 **MSVC 和 ClangCL** 构建，运行 `--version`、`--selftest`
以及 parser/i18n 测试。它**不安装 Npcap 驱动**，也**不运行真实抓包/发包测试**。
真实扫描仍然需要本地安装 Npcap，并使用管理员终端。
