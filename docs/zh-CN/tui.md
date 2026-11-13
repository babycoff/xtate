# TUI 任务面板

TUI 是一个全屏的**控制平面客户端**。它不在进程内扫描，也不替代扫描器 CLI；
每个动作都会转成控制平面的 JSON-lines 请求，和 MCP 使用同一套 API。任务生命周期、
超时、结果文件、配额告警和取消仍由控制平面负责。

如果你需要同时观察多个受管任务、取消其中一个，或者不想手写 JSON 就启动一个小范围
的已授权扫描，可以使用 TUI。

## 前提

- 同一台主机上已经有一个控制平面：
  - Unix：`--control-plane=/tmp/xtate-ctl.sock`
  - Windows：`--control-plane=\\.\pipe\xtate-ctl`
- 如果设置了控制令牌，控制平面和 TUI 进程必须使用相同的
  `XTATE_CONTROL_TOKEN`。
- 终端支持 ANSI 转义序列。Windows 10/11 Terminal 和较新的 Windows 控制台可用；
  TUI 会主动开启虚拟终端处理。
- 非 ASCII 结果路径需要能显示 UTF-8 的终端。

## 启动

本机日常使用只需一条命令。省略 `--control-connect` 时，TUI 会在子进程中启动一个
私有控制面，等待其就绪，并在 TUI 退出时停止它：

```bash
xtate --tui
```

Windows PowerShell：

```powershell
.\bin\xtate.exe --tui
```

这种私有模式下启动的任务会随 TUI 退出而停止。若要连接已有控制面（用于长任务或其他
客户端），显式传入端点：

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --control-plane=/tmp/xtate-ctl.sock
# 另一个终端，使用同一个令牌：
xtate --tui --control-connect=/tmp/xtate-ctl.sock
```

Windows PowerShell：

```powershell
$env:XTATE_CONTROL_TOKEN = "change-me"
xtate --control-plane=\\.\pipe\xtate-ctl
# 另一个终端：
xtate --tui --control-connect=\\.\pipe\xtate-ctl
```

私有子进程会继承 TUI 进程的 `XTATE_CONTROL_TOKEN`，因此设置令牌时仍然会校验。

## 按键

| 按键 | 动作 |
|---|---|
| `↑` / `k` | 选择上一个任务 |
| `↓` / `j` | 选择下一个任务 |
| `r` | 立即刷新 |
| `s` | 启动扫描向导 |
| `c` | 取消选中任务（询问 `y/n`） |
| `Enter` | 详情：状态和结果 manifest |
| `q` | 退出并恢复终端 |

面板每两秒刷新一次。列表来自 `job.list`，显示 `job_id`、状态和结果路径；选中行还会
显示 `job.status` 里的阶段、已发送/目标数、心跳时长和已用时间。详情页会额外显示
`job.result_manifest` 的 manifest 路径、字节数和完成标记。

## 启动向导

向导依次询问：

1. 扫描模块，默认 `tcp-syn`；
2. 目标，逗号分隔（每一项作为一个目标字符串）；
3. 端口，逗号分隔的 `0..65535` 整数；留空表示使用扫描模块默认端口；
4. 可选的接口名；
5. 速率，默认 `1000` 包/秒；
6. 超时，默认 `300` 秒；
7. 结果路径，默认 `xtate-tui-<epoch>.ndjson`（相对路径相对于控制平面进程，而不是
   TUI 进程）；
8. 确认：必须原样输入 `YES`。

只有确认之后，TUI 才会发送 `authorized: true`。这是易用性保护，不是安全边界：
控制平面只在本机、且被信任；MCP 仍会自己校验 `authorized: true`，控制平面不接受
远程连接。

向导不支持 `include_file`、`probe_args`、`scan_args`、zstd 和配额设置；这些请用
MCP 的 `start_scan` 或扫描请求 JSON 文件。

### 接口选择

Xtate 扫描需要一个抓包接口。如果主机有多个默认接口，工作进程可能启动失败：

```text
multiple default interfaces detected (2); use -if to choose explicitly
```

先对同一目标运行预检，然后把输出里的 `Interface` 值粘贴到向导中：

```bash
xtate --explain-target=203.0.113.0/24
```

Windows 上接口通常形如 `\Device\NPF_{...}`；Linux 上是 `eth0`、`lo` 这样的设备名。
路由唯一时留空即可让 Xtate 自动选择。

## 脚本化快照

当 stdin 或 stdout 不是终端时，`--tui` 会打印一次纯文本快照并退出，适合冒烟测试和
状态检查：

```bash
xtate --tui --control-connect=/tmp/xtate-ctl.sock
```

输出包含端点、任务数量和同样的 id/state/result 表。它不读取按键，也不会进入向导。

## 职责与限制

- TUI 只是客户端，不能绕过控制平面的校验、结果路径、接口匹配或任务数量限制。
- 本地 Unix socket 和命名管道的控制令牌默认可选；共享机器上应设置
  `XTATE_CONTROL_TOKEN`。
- TUI 不读取结果记录，只显示 manifest；请用扫描器 CLI、MCP resource 或自己的
  NDJSON 读取器读取分块。
- 取消是尽力而为。已经退出的工作进程可能返回 `"cancelled": false`，刷新即可。
- TUI 按设计只支持本机（Unix socket 或命名管道），没有网络模式。
- 启动时注册了终端恢复；如果进程被 `SIGKILL` 或控制台被关闭，终端可能仍处于 raw
  模式。Unix 下可执行 `reset` 恢复。

## 相关文档

- [控制平面](./control-plane.md) — 请求/响应契约
- [任务模型](./job-model.md) — 状态、心跳、超时、结果分块
- [MCP 服务器](./mcp-server.md) — 通过 MCP 工具操作同一批任务
- [Agent Skill](./agent-skill.md) — 外部 agent 的操作手册
