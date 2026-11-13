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

Linux/macOS：

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
| `--control-connect=...` | 必填，控制平面端点。 |

浏览器 URL 形如 `http://127.0.0.1:<port>/`。会话 token 只打印一次，同时注入页面；
没有匹配 `X-Xtate-GUI-Token` 请求头的调用会被拒绝。

## 面板功能

- 通过 `job.list` 列出任务，每三秒刷新状态。
- 展示选中任务的阶段、sent/targets 计数、心跳、耗时、退出码、结果与日志路径、
  错误和有界 stderr 尾部。
- 展示结果清单（`complete`、结果路径、清单路径与字节数）。
- 通过向导启动扫描：scan 模块、目标、可选端口、速率、超时、结果路径和可选接口。
  只有勾选明确授权复选框后才会启动；桥接层还会拒绝 `params.authorized` 不为
  字面 `true` 的 `job.start`。
- 选中 queued/running 任务后，经确认可取消。

向导刻意小于完整扫描请求 schema。probe 参数、scan 参数、include_file、分块和配额等
高级字段请直接使用 MCP server 或 JSON 控制 API。

## 安全模型

- **仅环回。** 监听 `127.0.0.1`；`--gui-listen` 拒绝非环回主机。没有网络路径，
  因此也不提供 TLS。
- **会话 token。** 启动时生成 128 位随机 token。页面通过 `X-Xtate-GUI-Token`
  发送，服务端使用常数时间比较。
- **Host 校验。** 非环回 `Host` 请求会被拒绝，防止 DNS rebinding 页面访问 API。
- **方法白名单。** 仅转发 `job.list`、`job.status`、`job.cancel`、
  `job.result_manifest` 和 `job.start`；GUI 不能调用 `ping`、`job.results`
  或任意控制方法。
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
| `--gui requires --control-connect` | 传入与 `--control-plane` 相同的 socket/pipe 路径。 |
| `cannot bind GUI listener` | 端口被占用；使用 `--gui-listen=127.0.0.1:0` 或换端口。 |
| 页面显示 “control plane unavailable” | 先启动守护进程，并确认两个进程的 `XTATE_CONTROL_TOKEN` 一致。 |
| `GUI_TOKEN_REQUIRED` | 从当前打印的 URL 重新加载页面；token 必须匹配当前服务进程。 |
| `AUTHORIZATION_REQUIRED` | 在向导中勾选授权；API 也要求 `params.authorized=true`。 |
| `multiple default interfaces detected` | 运行 `xtate --explain-target=<target>`，把 `-if` 值填入接口字段。 |

## 测试

```bash
python tests/gui/test_gui.py
```

测试会启动真实控制平面和 GUI 桥接，检查页面与 token，拒绝非环回 Host 和缺失
token，启动一次 dry-run 任务并轮询到终态。无需浏览器。

## 相关文档

- [控制平面](control-plane.md)
- [任务模型](job-model.md)
- [TUI 面板](tui.md)
- [MCP server](mcp-server.md)
