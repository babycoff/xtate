# Job control plane

**English** · [中文](zh-CN/control-plane.md)

P0 contract shared by MCP, TUI and GUI. Local transport only: Unix domain
socket on Linux, Named Pipe on Windows. One JSON object per line; no shell.

## Endpoints

Linux: `$XDG_RUNTIME_DIR/xtate/control.sock`
Windows: `\\.\pipe\xtate-control`

A local token file guards access.

## Methods

- `ping`
- `job.start` (scan-request object)
- `job.list`
- `job.status` (`job_id`)
- `job.results` (`job_id`, `offset`, `limit`)
- `job.cancel` (`job_id`)
- `job.events` (`after`)

## Status

`job_id`, `state`, `phase`, `sent`, `targets`, `success`, `failed`,
`elapsed_ms`, `result_path`, `heartbeat_age_ms`.

States: `queued`, `running`, `completed`, `failed`, `cancelled`,
`timed_out`, `stalled`.

## Errors

Stable codes from `schemas/error-codes.json`; error response:
`{"id":1,"error":{"code":"JOB_NOT_FOUND","message":"...","retryable":false}}`.

## Data plane (Internet-scale results)

Control messages never carry unbounded result data. Add a result store
workstream before `start_scan`:

- `uint64_t` offsets and 64-bit file seeks (no 32-bit `long`/`fseek`);
- `job.results(offset, max_bytes)` returns a bounded chunk plus `next_offset`,
  `truncated`, and chunk metadata;
- chunked result files, optional zstd compression and an index;
- per-job disk quota / ENOSPC failure with `OUTPUT_WRITE_FAILED`;
- completed-job TTL and max retained jobs;
- heartbeat throttled to ~1s, no fsync per update;
- control plane and data plane separated: MCP/TUI/GUI read chunks, not whole files.

## Rules

- One control-plane thread; manager calls serialized.
- Results are cursor-based; clients never read files directly.
- `job.start` requires explicit targets and a timeout/stall policy.
- Daemon owns workers; MCP/TUI/GUI are clients.
- Server restart terminates jobs; no false persistence claim.
- Local token authentication; no network listener.

## Result store

`--result-chunk-size=N --result-index` splits a completed CLI job result into
`<result>.<id>.ndjson` chunks and writes `<result>.manifest.json` plus an
optional index. Compression is currently `none`. `job.result_manifest` returns
the manifest path; control messages never carry result bytes.

### Optional zstd

`-DWITH_ZSTD=ON` enables zstd detection. If zstd is missing, the build defines
`NOT_FOUND_ZSTD`; `--result-compress=zstd` then falls back to uncompressed
chunks. Compression is opt-in; default is `none`.
