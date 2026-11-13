# 浏览器 GUI

Xtate 提供一个仅监听环回地址的浏览器控制平面面板。它和 MCP、TUI 一样是客户端：
负责展示任务、启动已授权扫描和取消任务；worker、超时、结果文件与真实扫描过程仍由
控制平面掌握。

GUI 面向本机分析工作站，不是公网 Web 服务，也不会通过 TCP 暴露控制平面。

## 前提

- 一个控制平面端点（Unix socket 或 Windows Named Pipe）。
- 如果控制平面设置了 `XTATE_CONTROL_TOKEN`，GUI 必须使用同一个值。
- 支持 `fetch` 与 `<dialog>` 的现代浏览器。

控制平面的启动方式见 [control-plane.md](control-plane.md)。

## 启动

本机日常使用只需一条命令。省略 `--control-connect` 时，GUI 会在子进程中启动一个
私有控制面，等待其就绪，并在 GUI 退出时停止它：

```bash
xtate --gui
```

Windows PowerShell：

```powershell
.\bin\xtate.exe --gui
```

这种私有模式下启动的任务会随 GUI 退出而停止。若要连接已有控制面（用于长任务或其他
客户端），显式传入端点：

```bash
export XTATE_CONTROL_TOKEN='change-me'
xtate --control-plane=/tmp/xtate-ctl.sock

# 另一个终端
xtate --gui --control-connect=/tmp/xtate-ctl.sock
```

Windows PowerShell：

```powershell
$env:XTATE_CONTROL_TOKEN = 'change-me'
.\bin\xtate.exe --control-plane=\\.\pipe\xtate-ctl

# 另一个终端
.\bin\xtate.exe --gui --control-connect=\\.\pipe\xtate-ctl
```

默认监听 `127.0.0.1:8787`，打印随机会话 token，并在默认浏览器中打开页面。选项：

| 选项 | 含义 |
|---|---|
| `--gui-listen=127.0.0.1:PORT` | 监听端口；只接受环回地址，`:0` 表示自动选择空闲端口。 |
| `--gui-no-open` | 只打印 URL 与 token，不自动打开浏览器。 |
| `--control-connect=...` | 可选端点。指定时连接已有控制面；省略时自动启动私有控制面。 |

浏览器 URL 形如 `http://127.0.0.1:<port>/`。会话 token 只打印一次，同时注入页面；
没有匹配 `X-Xtate-GUI-Token` 请求头的调用会被拒绝。

## 控制台功能

GUI 以扫描为中心：默认页是 **New scan**，不是任务表格。

- **New scan** 接受逗号、范围或 CIDR 形式的 IPv4/IPv6 目标，选择 11 个扫描引擎之一；
  只有引擎需要时才显示 probe，ICMP/ARP/NDP 扫描会隐藏端口。速率、超时和可选接口
  也在此设置。
- 服务端**预检**（`POST /api/preflight`）解析与 `job.start` 相同的请求，检查目标语法
  与数量、路由、源地址、网关、链路类型和 raw-IP 能力，并拒绝未知 scan/probe、TCP
  引擎只给 UDP 端口以及非法数值。预检不发包。
- **Start scan** 只有在预检通过、勾选授权、且预检后表单未改动时才可用。桥接层仍会
  拒绝 `params.authorized` 不为字面 `true` 的 `job.start`。
- **模块参数** 会显示当前扫描引擎和探测的开关与文本参数，作为 `scan_args`/
  `probe_args` 发送；留空即不发送。预检不校验参数名或取值，非法值会让 job 失败，
  并在 `stderr_tail`/日志中出现 worker 参数错误。
- **Live** 每 1.5 秒轮询 `job.status`，显示阶段、sent/targets、心跳、耗时、退出码、
  结果/日志路径和有界 stderr 尾部；queued/running 任务经确认可取消。
- **Results** 通过 `job.list` 列出任务，打开后显示清单状态、结果字节数与路径。
- **Interfaces** 显示采集网卡的 IPv4/IPv6、MAC、网关、默认标记、链路类型和 raw-IP
  能力；**Modules** 搜索模块目录；**Settings** 显示运行时、能力和安全状态。

输出路径由服务端管理。include_file、分块和配额等高级字段请直接使用 MCP server 或
JSON 控制 API；scan/probe 参数可在 Method 面板中编辑。

## 安全模型

- **仅环回。** 监听 `127.0.0.1`；`--gui-listen` 拒绝非环回主机。没有网络路径，
  因此也不提供 TLS。
- **会话 token。** 启动时生成 128 位随机 token。页面通过 `X-Xtate-GUI-Token`
  发送，服务端使用常数时间比较。
- **Host 校验。** 非环回 `Host` 请求会被拒绝，防止 DNS rebinding 页面访问 API。
- **方法白名单。** `/api/rpc` 仅转发 `job.list`、`job.status`、`job.cancel`、
  `job.result_manifest` 和 `job.start`；`/api/system`、`/api/interfaces`、
  `/api/modules` 和 `/api/preflight` 是服务端只读处理器，不能调用任意控制方法。
- **不经过 shell。** GUI 是进程内 C 代码；自动打开浏览器在 Windows 使用
  `ShellExecuteW`，在 Unix 使用 `xdg-open`。
- **token 处理。** 控制平面 token 只从环境读取并由服务端添加；页面 JavaScript
  不会拿到它。浏览器会话 token 会出现在页面源码中，因此应把浏览器配置视为可信
  本机状态。

GUI 不是扫描的安全边界。授权、目标数量、速率、路由预检和结果路径检查仍在控制平面
与 MCP server 中执行。

## 故障排查

| 现象 | 处理 |
|---|---|
| `cannot start a private control plane for --gui` | 子进程启动或绑定失败。确认二进制可运行、临时目录可写，或显式传入 `--control-connect`。 |
| `cannot bind GUI listener` | 端口被占用；使用 `--gui-listen=127.0.0.1:0` 或换端口。 |
| 页面显示 “control plane unavailable” | 所连接的控制面已停止；启动它，或省略 `--control-connect` 使用私有模式，并确认两个进程的 `XTATE_CONTROL_TOKEN` 一致。 |
| `GUI_TOKEN_REQUIRED` | 从当前打印的 URL 重新加载页面；token 必须匹配当前服务进程。 |
| `AUTHORIZATION_REQUIRED` | 在向导中勾选授权；API 也要求 `params.authorized=true`。 |
| `multiple default interfaces detected` | 运行 `xtate --explain-target=<target>`，把 `-if` 值填入接口字段。 |

## 测试

```bash
python tests/gui/test_gui.py
```

测试会启动真实控制平面和 GUI 桥接，检查页面、token、system/interfaces/modules/
preflight 端点，拒绝非环回 Host 和缺失 token，并启动一次 dry-run 任务轮询到终态。
无需浏览器。

## 相关文档

- [3.0 手册](manual/README.md)
- [控制平面](control-plane.md)
- [任务模型](job-model.md)
- [TUI 面板](tui.md)（3.0 中已弃用）
- [MCP server](mcp-server.md)
