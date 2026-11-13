# Job control plane

**English** · [中文](zh-CN/control-plane.md)

Local JSON-lines contract shared by MCP, TUI and GUI. One JSON object per line;
the server never runs a shell. It is not a network listener.

## Transport

- Linux: Unix domain socket.
- Windows: Named Pipe, for example `\\.\pipe\xtate-control`.

There is no implicit endpoint. The server uses exactly the path passed to
`--control-plane`, and a client uses exactly the path passed to
`--control-connect`:

```bash
xtate --control-plane=/tmp/xtate-ctl.sock
xtate --control-connect=/tmp/xtate-ctl.sock --control-request='{"id":1,"method":"ping"}'
```

## Authentication

Both server and client read `XTATE_CONTROL_TOKEN` from their environment. When
the server has a token, every request must carry the same `"token"` field;
missing or wrong tokens return `UNAUTHORIZED`.

If `XTATE_CONTROL_TOKEN` is unset, the server accepts every local client. Always
set it when other local users or processes are not trusted. The control plane is
local-only and does not listen on TCP.

## Methods

| Method | Parameters | Result |
|---|---|---|
| `ping` | none | `{"pong":true}` |
| `job.start` | `params` scan-request object, or legacy `request_path` | `{"job_id":"..."}` |
| `job.list` | optional `offset`, `limit` (default 100, max 1000) | `jobs`, `total`, `next_offset`, `truncated` |
| `job.status` | `job_id` | state, counters, result/log paths, stderr tail |
| `job.result_manifest` | `job_id` | `result_path`, `manifest_path`, `result_bytes`, `complete` |
| `job.results` | `job_id` | same manifest metadata; `offset`/`limit` are reserved and currently ignored |
| `job.cancel` | `job_id` | `cancelled` boolean |

`job.start` also reads these top-level options when present: `result_path`,
`timeout_sec`, `chunk_size`, `compression`, `index`, `quota_bytes` and
`interface`. The scan request itself is validated by the worker; an invalid
request fails asynchronously and is visible through `job.status`.

There is no `job.events` method and no server-push channel. Clients poll
`job.status` / `job.list`.

## Status

`job.status` returns:

```text
job_id, state, phase, sent, targets, heartbeat_age_ms, heartbeat,
exit_code, result, log_path, error, stderr_tail, elapsed_ms
```

States: `queued`, `running`, `completed`, `failed`, `cancelled`, `timed_out`,
`stalled`.

## Errors

Stable codes come from `schemas/error-codes.json`; an error response looks like:

```json
{"id":1,"error":{"code":"JOB_NOT_FOUND","message":"...","retryable":false}}
```

## Data plane

Control responses are bounded and never carry result bytes. A job owns its
result path; clients read the manifest and the chunk files from the filesystem.

- Result sizes and cursors use `uint64_t` and 64-bit seeks.
- Completed results can be split into `<result>.<id>.ndjson` chunks plus
  `<result>.manifest.json`, with an optional index.
- Compression is optional zstd; the default is none.
- `job.results` currently returns manifest metadata rather than byte ranges, so
  clients must not expect `offset`/`limit` paging over result content.
- `quota_bytes` is checked after completion and reported as a warning; it is not
  enforced during the scan.
- Completed-job TTL and maximum retained jobs are enforced by the manager.
- Heartbeat is updated by the worker and read by the manager; clients see
  `heartbeat_age_ms` and `heartbeat`.

## Result store

`--result-chunk-size=N --result-index` splits a completed result into chunks and
writes `<result>.manifest.json` plus an optional index. `job.result_manifest`
returns the manifest path; control messages never carry result bytes.

### Optional zstd

The `WITH_ZSTD` CMake option (default `ON`) enables zstd detection. If zstd is missing, the build defines
`NOT_FOUND_ZSTD`; `--result-compress=zstd` then falls back to uncompressed
chunks and `--list-capabilities` reports `zstd:false`. On Windows, install
`zstd:x64-windows` with vcpkg (the build script passes the toolchain
automatically) and rebuild. Compression is opt-in per job; the default is
`none`.

## Per-job result config

`job.start` accepts `chunk_size`, `compression`, `index` and `quota_bytes`.
Completed jobs are finalized on the next control request: chunks and manifest
are written automatically. `quota_bytes` is checked after completion and
reported as a warning; enforcement during scanning is future work.

## Batch explain

`--explain-target` accepts a target set (CIDR, ranges, comma list). Output is
grouped by interface/source/gateway with target counts and a warning when the
set spans multiple routes. `check` uses the same grouping. MCP `explain_target`
accepts the same target-set string.

### IPv4/IPv6 explain

Single addresses are printed without `/32` or `/128`. IPv6 targets are grouped
too; targets with no route appear in a `(no route)` group and still count. Mixed
IPv4/IPv6 sets can produce multiple groups and a split warning.

## Rules

- One control-plane thread; manager calls are serialized.
- The daemon owns workers; MCP/TUI/GUI are clients.
- A server restart terminates jobs; there is no persistence or recovery claim.
- Local token authentication; no network listener.
