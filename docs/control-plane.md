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

## Rules

- One control-plane thread; manager calls serialized.
- Results are cursor-based; clients never read files directly.
- `job.start` requires explicit targets and a timeout/stall policy.
- Daemon owns workers; MCP/TUI/GUI are clients.
- Server restart terminates jobs; no false persistence claim.
- Local token authentication; no network listener.
