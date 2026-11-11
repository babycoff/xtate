# Job 控制平面

[English](../control-plane.md) · **中文**

MCP、TUI、GUI 共用的 P0 契约。仅本地传输：Linux Unix domain socket，
Windows Named Pipe。一行一个 JSON 对象，不经过 shell。

## 端点

Linux: `$XDG_RUNTIME_DIR/xtate/control.sock`
Windows: `\\.\pipe\xtate-control`

本地 token 文件鉴权。

## 方法

- `ping`
- `job.start`（scan-request 对象）
- `job.list`
- `job.status`（`job_id`）
- `job.results`（`job_id`、`offset`、`limit`）
- `job.cancel`（`job_id`）
- `job.events`（`after`）

## 状态

`job_id`、`state`、`phase`、`sent`、`targets`、`success`、`failed`、
`elapsed_ms`、`result_path`、`heartbeat_age_ms`。

状态：`queued`、`running`、`completed`、`failed`、`cancelled`、`timed_out`、
`stalled`。

## 错误

错误码来自 `schemas/error-codes.json`，格式：
`{"id":1,"error":{"code":"JOB_NOT_FOUND","message":"...","retryable":false}}`。

## 数据面（互联网规模结果）

控制消息不携带无界结果数据。在 `start_scan` 之前增加 Result Store 工作流：

- `uint64_t` offset 和 64 位文件 seek，不使用 32 位 `long`/`fseek`；
- `job.results(offset, max_bytes)` 返回有界 chunk、`next_offset`、`truncated` 和
  chunk 元数据；
- 结果分片、可选 zstd 压缩和索引；
- 单 job 磁盘配额；ENOSPC 使用 `OUTPUT_WRITE_FAILED`；
- 完成 job 的 TTL 和最大保留数；
- heartbeat 约 1 秒一次，不做每次 fsync；
- 控制面与数据面分离：MCP/TUI/GUI 读 chunk，不读整文件。

## 规则

- 控制面单线程，manager 调用串行。
- 控制面不携带结果数据。`job.result_manifest` 返回路径、大小和完成状态；
  客户端直接读取结果分块。
- `job.start` 必须有明确目标与 timeout/stall 策略。
- daemon 拥有 worker；MCP/TUI/GUI 只是客户端。
- server 重启终止 job，不声称可恢复。
- 本地 token 鉴权，不监听网络。

## 结果存储

`--result-chunk-size=N --result-index` 会把完成的 CLI job 结果拆成
`<result>.<id>.ndjson` 分片，并写 `<result>.manifest.json` 和可选 index。
当前压缩仅 `none`。`job.result_manifest` 返回 manifest 路径；控制消息不携带结果字节。
