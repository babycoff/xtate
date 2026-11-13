# 浏览器 GUI

Xtate 提供一个仅监听环回地址的浏览器控制平面控制台。它和 MCP、TUI 一样是客户端：
负责启动已授权扫描、实时观察、取消任务和打开结果；worker、超时、结果文件与真实扫描过程仍由
控制平面掌握。

GUI 面向本机分析工作站，不是公网 Web 服务，也不会通过 TCP 暴露控制平面。

## 前提

- 一个已连接的控制平面端点（Unix socket 或 Windows Named Pipe），或直接使用
  `xtate --gui` 自动启动的私有控制平面。
- 连接已有控制平面时，如果该控制平面设置了 `XTATE_CONTROL_TOKEN`，GUI 必须使用
  同一个值。
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

这种私有模式下启动的任务会随 GUI 退出而停止。如果环境中尚未设置
`XTATE_CONTROL_TOKEN`，GUI 会为私有控制平面生成一个临时的 128 位令牌并传给子进程，
因此本机其他账户无法直接连接该管道或 socket；令牌在 GUI 退出时清除，且不会打印。
若要连接已有控制面（用于长任务或其他客户端），显式传入端点：

```bash
export XTATE_CONTROL_TOKEN='change-me'
xtate --control-plane=/tmp/xtate-ctl.sock

# second terminal
xtate --gui --control-connect=/tmp/xtate-ctl.sock
```

Windows PowerShell：

```powershell
$env:XTATE_CONTROL_TOKEN = 'change-me'
.\bin\xtate.exe --control-plane=\\.\pipe\xtate-ctl

# second terminal
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

在 Windows 上，结果与日志写入 `xtate.exe` 同级、可见的 `xtate-state` 目录，
方便直接找到和删除。控制平面使用托管状态目录：Windows 上是
`xtate.exe` 同级的 `xtate-state`，Linux 上是 `$XDG_STATE_HOME/xtate`
（回退到 `$HOME/.local/state/xtate`）。设置 `XTATE_STATE_DIR` 可以覆盖它。
每次扫描在 `runs/<YYYYMMDD-HHMMSS>-<seq>/` 下拥有独立目录，包含 `scan.ndjson`、
`scan.ndjson.log`、manifest 和 index，多次扫描不会互相覆盖。请求文件位于
`requests/` 下，job 进入终态时会被删除。如果便携目录无法创建
（例如二进制位于只读安装目录），Windows 构建会依次回退到
`%LOCALAPPDATA%\xtate`、`%TEMP%\xtate-state`、当前目录下的 `xtate-state`；
选中的根目录下仍然包含 `requests` 和 `runs`。

## 控制台功能

GUI 以扫描为中心：默认页是 **New scan**，不是 job 表格。

- **New scan** 接受逗号、范围或 CIDR 形式的 IPv4/IPv6 目标，从 11 个扫描引擎中选择一个；
  只有引擎需要时才显示探测选项，ICMP/ARP/NDP 扫描会隐藏端口。速率、超时和可选接口
  也在此设置。
- 服务端**预检**（`POST /api/preflight`）解析与 `job.start` 相同的请求，校验目标语法
  与数量、路由、源地址、网关、链路类型和 raw-IP 能力，并拒绝未知扫描/探测、TCP
  引擎只给 UDP 端口以及非法数值。预检不发包。
- **Start scan** 只有在预检通过、勾选授权、且预检后表单未改动时才可用。桥接层仍会
  拒绝 `params.authorized` 不为字面 `true` 的 `job.start`。
- **全局参数** 提供 23 个安全的扫描级选项（seed、TTL、TCP window/MSS、缓冲区大小、
  去重等）。开关显示为复选框，带值选项显示为文本输入框，并附说明。预检会校验取值，
  通过后作为 `global_args` 发送；非法或不安全的选项会被拒绝。进程、文件、脚本、
  job/控制面以及目标/端口/速率/接口类选项不会出现在这里，因为它们会破坏 job 契约。
- **模块参数** 会显示当前扫描引擎和探测暴露的开关与文本参数，作为 `scan_args`/
  `probe_args` 发送；留空即不发送。全局参数由预检校验；模块参数由 worker 解析，
  非法模块值会让 job 失败，并在 `stderr_tail`/日志中出现 worker 参数错误。
- **Live** 以可配置的间隔轮询 `job.status`，页面顶部是一个大号状态标题（`Scanning`、
  `Scan complete`、`Scan failed` 等），下面显示 sent/targets、吞吐、已用时间、退出码、
  结果/日志路径和清理过的 worker 日志尾部。没有进度条。**Open log** 与 **Open result**
  会把服务端解析出的 job 文件交给操作系统的默认应用（Windows 上 `.log`/`.ndjson`
  没有文件关联时回退到文本编辑器）。取消前会要求确认。
- **Results** 用 `job.list` 列出 job；打开一个会切到 Live 并选中该 job。**Load records**
  通过 `GET /api/results?job_id=...&offset=...&limit=...`（每页 50 条）读取已完成的
  结果文件，**Load more** 继续翻页。只返回合法的 NDJSON 记录；损坏或不完整的行会被跳过。
- **Interfaces** 列出采集网卡及其 IPv4/IPv6 地址、MAC、网关、默认标志、链路类型和
  raw-IP 能力。**Modules** 把扫描模块、探测模块、输出模块和生成模块分组，支持搜索与
  类型标签页；点击模块会展开完整说明和参数表，包含参数描述与别名。**System** 有真实的
  外观控制（Paper/Graphite 主题、密度、实时刷新）、运行时计数、能力以及本地安全模型。
- **语言** 顶栏可在 English 与中文之间切换。模块与全局参数说明直接复用 CLI 的翻译
  目录，因此与 `--help` 和手册保持一致。选择会保存在浏览器中，也可用 `?lang=en` 或
  `?lang=zh` 强制指定。

输出路径由服务端管理。include 文件、分块和配额等设置请直接使用 MCP server 或
JSON 控制 API。scan/probe 参数可在 Method 面板中编辑。

## 安全模型

- **仅环回。** 监听 `127.0.0.1`；`--gui-listen` 拒绝非环回主机。没有网络路径，
  因此也不提供 TLS。
- **会话 token。** 启动时生成 128 位随机 token。页面通过 `X-Xtate-GUI-Token`
  发送，服务端使用常数时间比较。
- **Host 校验。** 非环回 `Host` 请求会被拒绝，防止 DNS rebinding 页面访问 API。
- **方法白名单。** `/api/rpc` 仅转发 `job.list`、`job.status`、`job.cancel`、
  `job.result_manifest` 和 `job.start`。`/api/system`、`/api/interfaces`、
  `/api/modules`、`/api/options`、`/api/preflight`、`/api/results` 和
  `/api/open` 是服务端处理器，不能调用任意控制方法。`/api/results` 只接受
  `job-<数字>`，读取该 job manifest
  报告的结果路径，绝不接受客户端任意路径。`/api/open` 只接受 `job_id` 加 `kind`
  （`log`、`result` 或 `manifest`）；服务端从 job status/manifest 解析路径，绝不打开
  客户端提供的路径。
- **不经过 shell。** GUI 是进程内 C 代码；自动打开浏览器在 Windows 使用
  `ShellExecuteW`/Explorer，在 Unix 使用 `xdg-open`。当 Xtate 以管理员权限运行时，
  Windows 通过已运行的 Explorer 打开 URL，避免把浏览器强制提升为管理员实例。
- **token 处理。** 连接已有控制平面时，其 control-plane token 只从环境读取并由服务端
  添加；页面 JavaScript 不会拿到它。私有模式下若环境没有 token，GUI 会生成临时 token
  并在退出时清除。浏览器会话 token 会出现在页面源码中，因此应把浏览器配置视为
  可信本机状态。

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
| Edge 提示现有实例以提升权限运行、是否重启 | 当前构建在 Xtate 以管理员权限运行时通过 Explorer 打开 URL，避免该提示。旧构建可加 `--gui-no-open`，把打印出的 URL 粘贴到普通权限启动的浏览器。 |

## 测试

```bash
python tests/gui/test_gui.py
```

测试会启动真实控制平面和 GUI 桥接，使用工作区 `XTATE_STATE_DIR`，检查页面、
语言切换标记、token、system/interfaces/modules/options/preflight 和 results 端点，
验证英文/中文模块与选项内容，拒绝非环回 Host 与缺失 token，在不启动任何应用的情况下
拒绝非法的 `/api/open` 请求，校验预检中的 `global_args`，检查每次扫描的独立结果目录，
并启动一个 dry-run job 轮询到终态。无需浏览器。

## 相关文档

- [3.0 手册](manual/README.md)
- [控制平面](control-plane.md)
- [任务模型](job-model.md)
- [TUI 面板](tui.md)（3.0 中已弃用）
- [MCP server](mcp-server.md)
