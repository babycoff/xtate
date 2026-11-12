# 输入与 Generate 模块

## 两种输入模型

Xtate 有两种提供目标的方式：

- **静态目标集**——扫描开始前解析：`-ip`、`-iL`/`--include-file`、`--exclude-file`。
- **Generate 模块**——扫描时生成目标：`--generate <module>`。

`include_file` 属于静态输入。`ip-stream`、`addr-stream`、`ip-list`、`addr-list`
在扫描过程中读取。`blackrock` 是默认 Generate 模块，用于把静态目标集随机化。

## Generate 模块

| 模块 | 一行输入的含义 | 主要参数 |
|---|---|---|
| `blackrock` | 内部随机化目标集 | 默认；不是逐行读取器 |
| `ip-stream` | IP/CIDR/范围 | `--ip-file`、`--default-port`、`--no-random`、`--rounds` |
| `addr-stream` | IP 范围 + 分隔符 + 端口范围 | `--address-file`、`--splitter`、`--default-port`、`--no-random` |
| `ip-list` | 单个 IP | `--ip-file`、`--default-port`、`--no-random` |
| `addr-list` | 单个 IP + 分隔符 + 单个端口 | `--address-file`、`--splitter` |

四个逐行读取模块：

- 每次读取一个物理行，并维护共享的 `line_number`；
- 超长行会被完整消费而不是拆成多个目标，并计为非法行；
- 错误格式为 `file:line: reason`；
- 默认跳过非法行并继续；
- 只支持一个 TX 线程；流阻塞时扫描速率只会被限制，不会被保证。

```bash
xtate --generate ip-stream \
  --gen-arg "--ip-file targets.txt --default-port 443" \
  -scan tcp-syn -if eth0 -wait 0 -o out.ndjson --no-status
```

## 错误策略

- 非法目标行：输出 `file:line`，`bad_lines` 加一，继续。
- 输入结束但没有任何有效目标：退出码 1。
- 读错误：失败。
- `--strict-errors`（别名 `--strict`）：遇到第一条非法行立即中止。
- `--max-errors N`（别名 `--max-bad`）：非法行达到 `N` 后中止；`0` 表示禁用
  （默认）。
- `--max-error-rate P`（别名 `--max-bad-rate`）：非法行超过已读行数的 `P%` 后
  中止；`P` 取值 0-100，`0` 表示禁用（默认）。

三者都是 `--gen-arg` 模块参数，例如：

```bash
--gen-arg "--ip-file targets.txt --strict-errors"
--gen-arg "--ip-file targets.txt --max-errors 100"
--gen-arg "--ip-file targets.txt --max-error-rate 5"
```

## 为什么 MCP 不暴露流式输入

MCP 的 stdin 是 JSON-RPC。流式生成器默认从 stdin 读取，无法在扫描前报告目标
数量，也无法在扫描前做路由分组。因此 MCP 只使用静态 `targets` 数组或
`include_file`，二者不能混用。大目标集应使用 `include_file`，而不是 Generate
模块。

## 已知问题

- 流式错误计数尚未反映到 `job_status`。
- 尚未实现从 `include_file` 发现路由；Windows 多网卡用户必须显式传 `interface`。
