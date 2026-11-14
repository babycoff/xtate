# Job 控制面

[English](../control-plane.md) · **中文**

MCP、GUI 共用的本地 JSON-lines 契约。一行一个 JSON 对象；服务端不执行
shell，也不是网络监听器。

## 传输

- Linux：Unix domain socket。
- Windows：Named Pipe，例如 `\\.\pipe\xtate-control`。

没有隐式 endpoint。服务端只使用传给 `--control-plane` 的路径，客户端只使用传给
`--control-connect` 的路径：

```bash
xtate --control-plane=/tmp/xtate-ctl.sock
xtate --control-connect=/tmp/xtate-ctl.sock --control-request='{"id":1,"method":"ping"}'
```

## 鉴权

服务端和客户端都从环境变量读取 `XTATE_CONTROL_TOKEN`。服务端设置了 token 时，
每个请求必须携带相同的 `"token"` 字段；缺失或错误返回 `UNAUTHORIZED`。

如果服务端没有设置 `XTATE_CONTROL_TOKEN`，它会接受所有本地客户端。在不能信任
其他本地用户或进程时务必设置 token。控制面只监听本地，不监听 TCP。

## 方法

| 方法 | 参数 | 结果 |
|---|---|---|
| `ping` | 无 | `{"pong":true}` |
| `job.start` | `params` 扫描请求对象，或旧式 `request_path` | `{"job_id":"..."}` |
| `job.list` | 可选 `offset`、`limit`（默认 100，最大 1000） | `jobs`、`total`、`next_offset`、`truncated` |
| `job.status` | `job_id` | 状态、计数器、结果/日志路径、stderr 尾部 |
| `job.result_manifest` | `job_id` | `result_path`、`manifest_path`、`result_bytes`、`complete` |
| `job.results` | `job_id` | 同上 manifest 元数据；`offset`/`limit` 保留但当前被忽略 |
| `job.cancel` | `job_id` | `cancelled` 布尔值 |

`job.start` 还会读取这些顶层选项：`result_path`、`timeout_sec`、`chunk_size`、
`compression`、`index`、`quota_bytes` 和 `interface`。扫描请求本身由 worker 校验；
非法请求会异步失败，并通过 `job.status` 查看。

省略 `result_path` 时，控制面会在状态根目录下创建每次运行独立的目录：
`<state>/runs/<YYYYMMDD-HHMMSS>-<seq>/scan.ndjson`，以及对应的
`scan.ndjson.log`、manifest 和 index。Windows 的状态根目录是
`%LOCALAPPDATA%\xtate`（含回退路径），Linux 上是 `$XDG_STATE_HOME/xtate` 或
`$HOME/.local/state/xtate`，可用 `XTATE_STATE_DIR` 覆盖。Windows 的 `--gui`
优先使用 `xtate.exe` 同级、可见的 `xtate-state`。请求文件位于
`<state>/requests`，job 进入终态时删除。

没有 `job.events` 方法，也没有服务端推送。客户端轮询 `job.status` / `job.list`。

## 状态

`job.status` 返回：

```text
job_id, state, phase, sent, targets, heartbeat_age_ms, heartbeat,
exit_code, result, log_path, error, stderr_tail, elapsed_ms
```

状态：`queued`、`running`、`completed`、`failed`、`cancelled`、`timed_out`、
`stalled`。

## 错误

错误码来自 `schemas/error-codes.json`，格式：

```json
{"id":1,"error":{"code":"JOB_NOT_FOUND","message":"...","retryable":false}}
```

## 数据面

控制响应有界，且从不携带结果字节。job 拥有自己的结果路径；客户端从文件系统读取
manifest 和分片。

- 结果大小和游标使用 `uint64_t` 和 64 位 seek。
- 完成结果可拆成 `<result>.<id>.ndjson` 分片和 `<result>.manifest.json`，并写
  可选 index。
- 压缩是可选 zstd，默认 `none`（不压缩）。
- `job.results` 当前返回 manifest 元数据，不返回字节区间；客户端不能依赖
  `offset`/`limit` 对结果内容分页。
- `quota_bytes` 在完成后检查并告警，扫描期间不强制。
- 完成 job 的 TTL 和最大保留数由 manager 执行。
- 心跳由 worker 更新、manager 读取；客户端看到 `heartbeat_age_ms` 和
  `heartbeat`。

## 结果存储

`--result-chunk-size=N --result-index` 会把完成结果拆成分片，并写
`<result>.manifest.json` 和可选 index。`job.result_manifest` 返回 manifest 路径；
控制消息不携带结果字节。

### 可选 zstd

`-DWITH_ZSTD=ON` 启用 zstd 检测。缺少 zstd 时定义 `NOT_FOUND_ZSTD`；
`--result-compress=zstd` 会退化为未压缩分片，`--list-capabilities` 显示 `zstd:false`。Windows 上请先用 vcpkg 安装
`zstd:x64-windows`（构建脚本会自动传入工具链）再重新构建。默认 `none`（关闭）。

## 每 job 结果配置

`job.start` 支持 `chunk_size`、`compression`、`index`、`quota_bytes`。
完成的 job 在下一次控制请求时自动完成分片和 manifest。`quota_bytes` 在完成后
检查并输出警告；扫描过程中的强制配额仍是后续工作。

## 批量 explain

`--explain-target` 接受目标集（CIDR、范围、逗号列表）。输出按接口/源地址/网关
分组并带目标计数；目标集跨多个路由时会警告。`check` 使用同一分组。MCP
`explain_target` 接受同样的目标集字符串。

### IPv4/IPv6 explain

单个地址不带 `/32` 或 `/128`。IPv6 目标也会分组；无路由目标进入 `(no route)`
组但仍计数。混合 IPv4/IPv6 目标集可能产生多个组和拆分警告。

## 规则

- 控制面单线程；manager 调用串行。
- daemon 拥有 worker；MCP/GUI 只是客户端。
- server 重启终止 job，不声称持久化或恢复。
- 本地 token 鉴权；不监听网络。
