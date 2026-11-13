# 输入/生成模块审查

[English](../input-modules-audit.md) · **中文**

状态：初步审计，2026-11-12。解决情况见下。

## 解决情况（2.42.0 之后）

已修复并有测试覆盖：

- 四个按行读取的生成模块统一使用 `src/generate-modules/stream-reader.h`：
  一行物理行就是一条记录；超长行会被消费并计数；错误会携带 `file:line`；
- `--strict-errors`、`--max-errors N` 与 `--max-error-rate P` 对四者都可用；
- 仅 IPv4 的网卡不再要求 IPv6（`init-nic`）；
- `ip-stream` 与 `addr-stream` 增加了计数/溢出检查；
- `addr-list` 不再每行泄漏一个 `RangeList`；
- 文件选项可打开 UTF-8/UTF-16 路径，并关闭上一个流；
- job worker 会得到 NUL stdin，因此未配置的流不会阻塞在 control/MCP 的 stdin 上；MCP 还会拒绝同时给出 `targets` 与 `include_file`；
- 流式生成模块会拒绝多于一个 TX 线程，而不是静默降级。

测试：`tests/input/test_generate.py`（覆盖四个模块、第 2 行无效、全部无效时退出码 1、strict 退出码 1）。尚缺的覆盖列在下面。

## 两种输入模型

1. 静态 `TargetSet`：`-ip`、`-iL/--include-file`、`--exclude-file`、`--list-ranges`。
2. 生成模块（`--generate`）：`blackrock`（默认）、`ip-stream`、
   `addr-stream`、`ip-list`、`addr-list`。它们在扫描运行时读取目标。

`--include-file` 不是生成模块。它把静态文件解析进 `TargetSet`；`--generate ip-stream` 则在扫描期间读取文件。

## 发现的问题

### 高危

- `ip-stream` 与 `addr-stream` 无条件设置 `init_ipv4 = init_ipv6 = true`。
  在仅 IPv4 的网卡上，`init_nic` 会以
  `failed to detect IPv6 address of interface` 失败。
- `--include-file` 会清空已有的 `TargetSet`；若同时提供 `targets` 与
  `include_file`，内联目标会被静默丢弃。
- `ip-stream`/`addr-stream` 按
  `(count_ipv4s + count_ipv6s.lo) * count_ports` 计算工作量。超过 2^64 的 IPv6
  计数会被截断，且乘法可能溢出 `uint64_t`。
- 流式/列表生成模块使用 256 字节的 `fgets` 缓冲区，且不检测超长行；长行会被拆成
  畸形片段。

### 中危

- 流式错误只记录行内容，不带 `file:line`；无效行会被跳过并继续扫描。静态
  include-file 会记录 `file:line` 并中止。
- `addr-list` 每行泄漏一个局部 `RangeList`。
- 文件参数使用 `fopen`；Windows 上 Unicode 路径会失败。
- 文件 setter 会泄漏上一个 `FILE*`，重新配置时不会关闭。
- `--gen-arg` 语法脆弱；缺失或无法解析的文件会回退到 stdin。
- 流式生成模块只支持 1 个 TX 线程；job 路径没有强制这一点。
- stdin 是默认输入，会与 MCP/job 的 stdin 冲突。
- `--list-ranges`/`--list-target` 只能看到静态 TargetSet。

## 已执行的测试

- `--include-file file --list-ranges`：PASS。
- 在仅 IPv4 的网卡上执行
  `--generate ip-stream --gen-arg "-ip-file file -default-port 1"`：FAIL，
  IPv6 网卡检测失败。
- `--gen-arg ip-file=file`：FAIL，未知参数。
- 畸形调用回退到 stdin，并一直挂起直到取消。

## 尚缺的测试覆盖

1. 四个生成模块的有效/无效/注释/空行。
2. 仅 IPv4 与仅 IPv6 的文件/网卡。
3. 超过 255 字节的行。
4. Unicode/带空格的文件路径。
5. 重复使用的文件选项。
6. job/MCP 模式下禁止 stdin。
7. include_file + targets 冲突。
8. 计数/溢出边界。
9. 单 TX 线程强制。
10. file:line/列错误。

## 设计方向

- `input_mode = static | stream`。
- 静态：targets 与 include_file 二选一，可计数、可路由。
- 流式：generate + input_file + 显式网卡，`targets_known=false`，
  不自动按路由分组。
- job/MCP 拒绝 stdin。
- 共享 UTF-8/UTF-16 打开器与共享的解析错误类型。
