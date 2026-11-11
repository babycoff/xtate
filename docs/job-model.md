# Job model and timeout

**English** · [中文](zh-CN/job-model.md)

Long scans need a control-plane job, not a blocking tool call. The job manager
is the shared backend for MCP, TUI and (later) GUI.

## API

```c
JobManager *job_manager_create(unsigned max_jobs);
Job *job_start(JobManager *, char *const argv[], const char *result_path,
               const char *log_path, unsigned timeout_sec);
JobState job_poll(Job *);
bool job_cancel(Job *);
bool job_wait(Job *, unsigned timeout_ms);
```

Status: `queued`, `running`, `completed`, `failed`, `cancelled`,
`timed_out`, `stalled`.

`timeout_sec` is optional (0 = unlimited) and is read by `--job-run` when
`--job-timeout` is absent. `--job-stall-timeout` detects no output progress and
does not require predicting total scan duration.

## Platform mapping

| Concern | Linux | Windows |
|:---|:---|:---|
| process | `fork`/`execv` | `CreateProcessA` |
| group | `setsid` | `CREATE_NEW_PROCESS_GROUP` |
| kill | `SIGTERM`/process group | `TerminateProcess`/`TerminateJobObject` |
| parent death | `PR_SET_PDEATHSIG` | Job Object `KILL_ON_JOB_CLOSE` |
| clock | `CLOCK_MONOTONIC` | `GetTickCount64` |
| output | files via `dup2` | handles via `STARTF_USESTDHANDLES` |

No shell is used. `argv` is passed directly.

## Design rules

- Worker is the same `xtate` binary; no sidecar interpreter.
- One result file per job; partial results survive timeout/cancel.
- Timeout is total wall-clock time, not a per-connection timeout.
- A future local control API (`job.start/status/results/cancel`) reuses this
  manager; MCP/TUI/GUI are clients of that API.
- Job ids are stable strings; lifecycle errors are `SCAN_TIMEOUT`,
  `SCAN_CANCELLED`, `JOB_NOT_FOUND`, `JOB_LIMIT_REACHED`.
- Single-threaded control plane for now; callers serialize manager access.

## Current state

Core manager + Linux/Windows implementations + a Linux smoke test:
`tests/job/test_job.c` (timeout, cancel, complete). CLI/MCP wiring is next.

## CLI

```bash
xtate --job-run=request.json --job-result=out.ndjson --job-timeout=30
```

Starts the same binary as a managed worker, waits for completion and prints:

```json
{"job":{"id":"job-1","state":"completed","exit_code":0,"result":"out.ndjson"}}
```

Worker output is NDJSON (`--show all`, `--wait 1`). `--job-timeout` is the total
wall-clock limit.

## Tests

```bash
XTATE_BIN=bin/xtate bash tests/job/test_cli.sh
```

Covers a completed job, a result file, and a `timed_out` job.

## Heartbeat and stall detection

The worker writes `<result>.heartbeat` while the status loop runs:

```text
time=...
sent=...
targets=...
success=...
failed=...
info=...
```

The manager treats a stale heartbeat as a wedged worker. Scan progress is
`packets_sent`/`targets_done` movement, not result-file growth; a scan with no
live targets can still be healthy. Result-file growth is only auxiliary.
`--job-heartbeat-timeout` defaults to 30 seconds; `--job-stall-timeout` tracks
no progress while the heartbeat stays alive.
