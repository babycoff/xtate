# 02 · GUI 控制台

[English](../../manual/02-gui-console.md) · **中文**

3.0 控制台是由 Xtate 二进制提供的本地网页。它和 TUI、MCP server 一样，是本地控制面的客户端：扫描在守护进程里运行，不在浏览器里；控制台列出并控制该守护进程拥有的 job。

页面只在回环上可用。它不是远程看板，不监听网络接口，也没有用户账户。扫描授权是一个独立的、显式的步骤。

## 启动控制台

### 私有控制面（一条命令）

```bash
sudo ./bin/xtate --gui
```

没有 `--control-connect` 时，二进制会为控制台启动一个私有控制面、提供页面，并在进程退出时把两者一起停掉。此模式下启动的 job 是控制台进程的子进程，不会在控制台退出后存活。

进程会打印：

```text
Xtate GUI listening on http://127.0.0.1:8787/
Control endpoint: <endpoint>
GUI session token: <32 hex characters>
This server is loopback-only. Press Ctrl-C to stop.
```

除非使用 `--gui-no-open`，否则会自动打开浏览器。

同一条命令在 Windows 上也能用（从提权的 shell 运行）：

```powershell
.\bin\xtate.exe --gui
```

### 接入已有控制面（守护进程比控制台活得久）

先启动守护进程，再让控制台接入它的端点：

```bash
sudo xtate --control-plane=/tmp/xtate-ctl.sock
xtate --control-connect=/tmp/xtate-ctl.sock --gui
```

此模式下控制台只是客户端。关闭它不会影响守护进程及其 job，另一个控制台、TUI 或 MCP 都可以接入同一个端点。Windows 上的端点是命名管道，例如 `\\.\pipe\xtate-control`。

### 选项

| 选项 | 作用 |
|:---|:---|
| `--gui` | 提供控制台（除非给了 `--control-connect`，否则启动私有控制面） |
| `--gui-listen=<addr>` | 绑定地址；只允许 `127.0.0.1` 或 `localhost`，可带端口。默认 `127.0.0.1:8787`；`:0` 让操作系统分配空闲端口 |
| `--gui-no-open` | 不启动浏览器 |
| `--control-connect=<endpoint>` | 接入已有守护进程，而不是启动私有的 |

## 页面导览

左侧导航有六项：**New scan**、**Live scan**、**Results**、**Interfaces**、**Modules** 和 **Settings**。顶栏显示与控制面的连接状态；页脚显示控制台版本和当前使用的端点。

### New scan

页面是一个四步表单加一块预检面板。

**01 Scope.** 目标文本框。目标语法与 CLI、scan-request schema 相同：单个地址、CIDR 块、区间和逗号列表。解析出的目标会以带计数的标签显示。**Use sample** 填入 `198.18.0.0/24, 203.0.113.10-40`，这是一个文档用范围——不是让你去扫互联网。

**02 Method.** 扫描卡片来自运行中守护进程的模块目录，因此卡片始终与该构建的 `--list-scan` 一致。端口默认 `80,443`，接受逗号列表和数字区间（`20-25`）。控制台发送的是纯端口号，因此这里不能用 CLI 的协议前缀，如 `U:`/`S:`；UDP/SCTP 专用端口集请用 CLI 或控制面请求。探测选择器只对接受探测的扫描引擎出现，并按引擎的探测类型过滤：

| 扫描引擎 | 探测类型 | 探测示例 |
|:---|:---|:---|
| `zbanner` | TCP | `http`、`echo`、`ssh` |
| `tcp-state` | state | `tls-state`、`http-state`、`smtp-state` |
| `udp` | UDP | `dns`、`snmp`、`ntp` |
| `quic-state`（可选，Linux） | state | `http3-state`（可选） |
| `tcp-syn`、`sctp-init`、`yarrp-udp` | 无 | — |

速率单位是包/秒（1–10000，默认 1000）。超时是总的墙钟时限，单位秒（1–86400，默认 300）。输出固定为带结果 manifest 的 NDJSON；控制台不选择输出模块。

**模块参数。** 方法卡片下方的 *Module parameters* 列出当前扫描引擎和探测暴露的开关与文本参数。开关是复选框，取值参数是文本框；留空即不发送。这些值会作为 `scan_args` 和 `probe_args` 随 `job.start` 发送，与 CLI 的 `--scan-arg`/`--probe-arg` 同名。切换扫描或探测时会重建列表。预检不校验参数名或取值；如果 worker 拒绝某个参数，job 会失败，`stderr_tail`/日志中会显示参数错误。

**03 Interface.** *Auto (from route)* 让预检为采样目标解析路由。TUN/VPN 网卡显示为 RAW 链路类型且没有 MAC，因此 banner 和有状态扫描可能无法通过它工作；请改选物理网卡。预检无法在路由之间决定时，会要求你显式选择接口。

**04 Authorization.** 复选框的文字是 *I own the targets or have written permission. The exact scope, rate, interface and time window above are what will be sent.* 它是开始扫描的必要条件，服务器还会再检查一次。它不能替代法律意义上的许可。

**Preflight panel.** 预检是服务端的只读检查，不发送报文。它会报告：

- 状态（idle、pending、passed 或 blocked）、尝试次数和摘要；
- 目标、端口、接口、源地址、网关和链路类型；
- 检查项列表，以及任何警告或错误。

预检在以下情况失败关闭：扫描模块未知、探测与引擎不匹配、端口与引擎协议不匹配、目标无法解析、速率/超时越界，或目标经多个接口解析且没有显式选择。ICMP 类扫描（`icmp-echo`）不需要端口，端口数为零。

任一被扫描字段变化都会使之前的结果失效；页面在最后一次变化后等待约 320 ms 再跑一次预检。**Start scan** 在预检通过且勾选授权之前保持禁用。按钮下方的提示会说明当前阻塞原因。

开始扫描会向本地控制面提交 `job.start` 请求，带上扫描、目标、端口、探测、速率、超时、可选接口和 `authorized: true`。成功后页面切换到返回的 job id 对应的 Live scan。

### Live scan

页头显示 job id 和状态：`queued`、`running`、`completed`、`failed`、`cancelled`、`timed_out` 或 `stalled`。页面约每 1.5 秒轮询一次 `job.status`，进入终态后停止轮询。

字段与面板：

- 进度条和已发送/目标计数；
- 阶段、心跳年龄、已用时间和退出码；
- 每秒包数，由已发送包数和已用时间推算；
- 结果 manifest：结果路径、manifest 路径、大小和完整性；
- worker 日志（stderr）的有界尾部；
- 已完成 job 的有界结果记录浏览器（每页 50 条）；
- 守护进程上报时的 result、log 和 error 字段。

**Cancel** 立即发送 `job.cancel`，并用 toast 报告结果。终态下该按钮禁用。离开页面不会停止扫描；守护进程继续运行，job 仍会出现在 Results 中。

### Results

用 `job.list`（最多 100 条）把 job 列成表格：扫描 id、状态、结果路径和返回 Live scan 的链接。选中一行会重新打开它的 Live scan 页面。空状态显示 *No scans yet.*。

在 Live scan 中，**加载记录** 通过 `GET /api/results?job_id=...&offset=...&limit=...` 读取已完成的结果文件，每次显示 50 条 JSON 记录。**加载更多** 推进 offset。该端点只接受 `job-<数字>`，从 job manifest 解析路径；损坏或不完整的 NDJSON 行会被跳过，不会渲染。

### Interfaces

显示服务器上报的网卡：索引、名称、描述、IPv4 与 IPv6 地址、MAC、网关、默认标志、状态和链路类型。回环与虚拟接口会列出，但不做探测。`state` 取值 `loopback`、`virtual`、`up` 或 `no-ipv4`；`raw_capable` 表示该链路类型是否支持原始扫描。同一份数据也驱动 CLI 的 `--list-if`。

### Modules

显示运行中守护进程的模块目录，按扫描引擎、探测、输出和生成模块分组。每张卡片显示模块名、简短描述（没有简短描述时显示完整描述）和参数名。过滤框可缩小列表。该目录与 `--list-modules-json` 及模块帮助背后的是同一份，因此控制台不会声称二进制没有的模块。

### Settings

显示版本、平台、控制端点和四个模块计数，以及服务器上报的 HTTP/3 与 QUIC 传输能力标志（例如带 ngtcp2 的 Linux 对比没有它的 Windows 构建）。页面还会重述控制台的安全模型。该页不修改守护进程配置；请用你需要的选项启动守护进程。

## 安全模型

控制台是为单个本地用户设计的：

- **仅回环。** `--gui-listen` 拒绝除 `127.0.0.1` 或 `localhost` 以外的任何值。服务器还会拒绝 `Host` 头不是回环的请求，从而阻断 DNS rebinding 攻击。
- **每会话 token。** 启动时生成一个 128 位随机 token，只打印一次，并嵌入页面。每个 `/api/*` 请求都必须把它放在 `X-Xtate-GUI-Token` 中；比较是常数时间的。绝不从请求体接受该 token。
- **方法白名单。** 浏览器桥只转发 `job.list`、`job.status`、`job.cancel`、`job.result_manifest` 和 `job.start`。`/api/results` 是独立的只读处理器，只接受 job id，并分页读取该 job manifest 指向的结果文件；两条路径都不能调用任意控制方法。
- **服务端授权。** 除非请求带有 `params.authorized: true`，否则 `job.start` 会被拒绝。浏览器复选框只是便利，不是强制点。
- **无 shell、无任意路径。** GUI 服务器不执行命令，也不读取任意文件。结果通过守护进程的 manifest 读取，页面只渲染服务器数据。
- **有界请求。** 头部上限 128 KiB，正文 64 KiB，桥接回复使用 64 KiB 缓冲；服务端直接构建的模块目录可能更大。socket 超时 8 秒。页面设置严格的 Content-Security-Policy、`X-Frame-Options: DENY` 和 `no-store`。
- **无 TLS。** 流量从不离开主机；回环上的明文 HTTP 就是设计。不要通过代理或隧道暴露该端口。

控制台不是扫描本身的安全边界：速率限制、目标限制、路由预检和结果路径规则由守护进程与 job worker 强制执行，MCP 还有自己的限制（见 [MCP server](../mcp-server.md)）。

## 控制台不做什么

控制台覆盖常见扫描流程，而不是全部 CLI 功能。以下内容刻意留给 CLI、控制面或 MCP：

- 目标文件（`include_file`）以及扫描/探测参数；
- 输出模块选择、结果分片和每 job 配额；
- 调度、周期扫描或扫描配置档；
- 远程访问、多用户，或会话 token 之外的认证；
- 有状态扫描的防火墙配置——在 Linux 上你必须自己安装规则，见 [01 · 安装与快速上手](./01-install-and-quickstart.md)。

这些场景请直接用 [03 · CLI 与 job](./03-cli-and-jobs.md) 或[控制面](../control-plane.md)。

## 故障排查

| 症状 | 可能原因与修复 |
|:---|:---|
| `cannot start a private control plane for --gui` | 私有守护进程无法创建。检查是否与已有端点冲突，或用 `--control-connect` 接入 |
| `cannot bind GUI listener` | 端口已被占用。换一个端口：`--gui-listen=127.0.0.1:0` 或 `:8790` |
| `control plane unavailable`（502） | 接入的守护进程消失了。重启它或接入新的 |
| `GUI_TOKEN_REQUIRED`（403） | 页面加载时没有 token，例如来自保存的 URL 或另一个浏览器配置。从启动时打印的 URL 重新加载 |
| `AUTHORIZATION_REQUIRED`（403） | job 启动请求没有包含 `params.authorized: true` |
| `multiple default interfaces detected` | 路由有歧义。显式选择接口，或先用 `--explain-target` / `--list-if` |
| Start 一直禁用 | 预检被阻塞或仍在运行、上次预检后字段有变化，或授权未确认 |

GUI 测试套件是 `python tests/gui/test_gui.py`；它覆盖页面/token 握手、API 端点、预检接受/拒绝用例、授权门、Host 检查、私有模式启动和一次 dry-run 托管 job。

## 相关文档

- [03 · CLI 与 job](./03-cli-and-jobs.md)
- [GUI 参考（job 看板）](../gui.md)
- [控制面](../control-plane.md)与 [job 模型](../job-model.md)
- [MCP server](../mcp-server.md)与 [Agent Skill](../agent-skill.md)
- [TUI](../tui.md)（2.44.x 界面，3.0 中已弃用）
- [故障排查](../troubleshooting.md)
