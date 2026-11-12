# MCP server

Xtate 通过 stdio 提供 Model Context Protocol（MCP）服务。它是控制面的类型化客户端，
并提供本地只读发现工具：
不内嵌扫描结果、不启动 shell，也不接受命令字符串。

## 启动

控制面和 MCP 客户端使用同一个 token（未设置时以无认证的本地模式运行）：

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"

# 终端 1：控制面（Linux 为 Unix socket，Windows 为 Named Pipe）
xtate --control-plane=/tmp/xtate-ctl.sock

# 终端 2：MCP server
xtate --mcp --control-connect=/tmp/xtate-ctl.sock
```

Windows 的 endpoint 形如 `\\.\pipe\xtate-control`。`--control-connect` 只建立
本地连接，不会监听 TCP。

## 工具

| 工具 | 用途 |
|---|---|
| `list_modules` | 全部模块元数据：扫描、探测、输出、生成模块 |
| `describe_probe` | 查询单个扫描/探测模块的元数据 |
| `explain_target` | 目标集的路由分组、接口/源地址/网关和 Linux 防火墙状态 |
| `check` | 与 `explain_target` 相同的路由/防火墙检查 |
| `validate_config` | 校验封闭的扫描请求对象，不启动 job |
| `start_scan` | 启动托管扫描 job，返回 `job_id` |
| `job_list` | 分页列出 job |
| `job_status` | 状态、计数器、退出码、错误、日志路径和 stderr 尾部 |
| `job_result_manifest` | 结果/分片路径、大小和完整性 |
| `job_cancel` | 取消运行中的 job |

所有结果使用 MCP 的文本内容格式：

```json
{"content":[{"type":"text","text":"{\"ok\":true,...}"}],"isError":false}
```

`text` 字段是 JSON。请求被拒绝或控制面返回错误对象时 `isError` 为 true。扫描
结果数据从不内联返回：客户端先读 manifest，再读分片文件。

`start_scan` 要求 `authorized: true`，表示调用方确认目标已获授权。`targets`（JSON
数组）和 `include_file` 二选一，不能同时使用。大目标集必须使用 `include_file`，
因为 MCP 参数缓冲区只有 8 KiB。

## 面向模型的元数据

`initialize` 返回 `serverInfo` 和 `instructions`，说明 Xtate、支持的协议、授权要求、
Linux 防火墙前提以及 job/结果分离模型。`tools/list` 提供描述、输入 schema 和
只读/破坏性标注。

服务还提供三个 resource 和一个 prompt：

```text
xtate://docs/overview          docs/README.md
xtate://docs/firewall          docs/firewall.md
xtate://schemas/scan-request   schemas/scan-request.schema.json
plan-safe-scan                 规划已授权扫描的检查清单
```

两个文档以 `text/markdown` 返回，schema 以 `application/json` 返回。

### 资源查找与安全

Resource URI 与上面的编译期内置白名单精确匹配。目标都是固定的相对文件名；任何
URI、工具参数或 MCP 字段都不能选择任意路径。绝对路径、带盘符的路径以及包含 `..`
的路径在访问文件系统之前就会被拒绝。

对每个允许的文件，服务按顺序尝试：

1. `$XTATE_MCP_DOCS_DIR/<file>`
2. 当前工作目录
3. 可执行文件所在目录及其最多四级父目录

`XTATE_MCP_DOCS_DIR` 是本地运维配置，应指向包含 `docs/` 和 `schemas/` 的仓库或安装
根目录；它只从服务进程环境读取，远程 MCP 客户端无法设置。文档只作为数据读取并返回文本，不会被执行。

该查找让 resource 在仓库构建或正常安装中都能从任意工作目录使用。如果文档没有
安装，`resources/read` 返回 `-32002 resource not found`，不会退化为扫描文件系统。

## 路由感知规划

`explain_target` 和 `check` 接受目标集字符串（例如
`203.0.113.0/24,2001:db8::1`），返回结构化的 `targets`、`route_groups` 和
`groups`，包含接口、源地址、网关和样例。Linux 上还会报告防火墙前提是否满足。

`start_scan` 对内联 `targets` 执行同样的分组，并拒绝跨越多个路由的目标集；请拆分
为多个 job。使用 `include_file` 时，Windows 多网卡主机必须显式传 `interface`。从
include 文件发现路由尚未实现，服务不会声称已经校验。

## 限制与校验

- `scan` 必须是已注册的扫描模块；`probe` 必须是已注册的探测模块。
- 内联 `targets` 最多 20000 个数组元素；端口必须在 0-65535。
- `rate` 上限为 10000 包/秒。
- 启动前会探测 `result_path` 是否可写。
- 超过 MCP 参数缓冲区的超大请求会被干净拒绝。
- `start_scan` 会向 MCP 进程工作目录下的 `xtate-mcp-audit.log` 追加审计记录，
  包含 rate 和截断后的配置。

## 测试

`tests/mcp/test_mcp.py` 覆盖初始化与 instructions、工具 schema、resources 和
prompts、未知方法/工具、畸形参数和 URI、`list_modules`/`describe_probe`、路由分组、
拒绝规则、真实完成的 job、`log_path`/`stderr_tail`、Unicode 结果路径、缺失或错误
token、`job_list` 分页、分片 manifest，以及从任意工作目录读取 resource。

`tests/mcp/test_mcp_stability.py` 覆盖超时、取消、并发请求、畸形 JSON、超大配置、
控制面重启和第二个 MCP 客户端。两套测试在 Windows 和 Linux 上均通过。
