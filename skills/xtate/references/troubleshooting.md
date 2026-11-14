# Troubleshooting

Diagnose from the error envelope and the job state; do not retry blindly. A
rejected request means nothing was scanned.

## Discovery and validation

| Symptom | Likely cause | Action |
|---|---|---|
| `unknown or missing scan` | `scan` absent or misspelled | `list_modules`; use the exact scan name |
| `unknown probe` | probe absent from this build, or wrong module type | `list_modules` and `describe_probe` |
| `targets or include_file required` | neither supplied | supply exactly one |
| `targets and include_file are mutually exclusive` | both supplied | choose one; use `include_file` for large sets |
| `target authorization required: set authorized=true` | missing attestation | confirm scope, then set `authorized: true` |
| `too many targets` | inline set over the 20000-entry limit | use `include_file`, split the job |
| `rate must be ...` | non-integer or out of range | integer 0-10000; prefer a lower authorized rate |
| `timeout_sec ...` | not an integer in 1-86400 | set an explicit bounded timeout |
| `result_path is not writable` | directory missing, read-only, or permission denied | choose a writable dedicated path |
| `include_file must be a regular file` | directory, device, FIFO, or `-` | point at a readable target list |
| `cannot determine route groups` | target has no route, or route lookup failed | check host networking; a no-route target is a stop condition |
| `route preflight failed; targets were not accepted by explain_target` | route/interface preflight failed | run `explain_target`, fix the route or split the set |
| `failed to detect MAC address of interface: "lo"` | target routes through Linux loopback, which has no Ethernet MAC | use an on-link gateway/host; do not force `lo` for raw scans |

## Control plane

`control request failed` means the MCP server could not reach the control plane,
or the request was rejected at the transport boundary.

Check, in order:

1. The control-plane process is running.
2. MCP uses the same endpoint as the server (`--control-connect`).
3. `XTATE_CONTROL_TOKEN` is set identically on both sides.
4. The endpoint is local and not a stale socket/pipe from a previous run.
5. No unrelated process is holding a Windows Named Pipe or the socket file.

`UNAUTHORIZED` is a token mismatch. Restart both sides with the same token; do
not disable authentication to work around it.

## Jobs

| State / code | Meaning | Action |
|---|---|---|
| `JOB_NOT_FOUND` | wrong job id, or a different control-plane instance | re-list jobs; do not reuse ids across restarts |
| `JOB_LIMIT_REACHED` | concurrent-job limit | wait for a job to finish or ask the operator |
| `failed` | worker exited nonzero; inspect `error`, `stderr_tail`, `log_path` | fix the reported cause, then revalidate |
| `timed_out` / `SCAN_TIMEOUT` | `timeout_sec` elapsed | report partial progress; re-authorize before retrying |
| `cancelled` / `SCAN_CANCELLED` | `job_cancel` succeeded | results may be partial; do not resume automatically |
| `stalled` | heartbeat stopped | inspect host load, control connection and worker log |
| `queued` for a long time | worker could not start, or limit reached | check `job_status` error and job list |

A completed job with `total_records: 0` is a valid result: the targets may be
down, filtered, or outside the scanned ports. It is not proof that the scan
failed. Check `sent`, `targets`, and the probe's own counters before concluding.

## Result files

- `job_result_manifest` returns paths and sizes, not records. If `complete` is
  false, wait for a terminal state before reading the manifest.
- Do not parse `<result>.manifest.json` or a chunk while the job is running;
  partial writes can produce invalid JSON.
- If `compression` is `zstd`, decompress each chunk before parsing NDJSON.
- A chunk path with spaces, Chinese characters or backslashes is valid; the
  manifest is JSON-escaped. Do not hand-edit paths.
- `quota_bytes` is checked after completion and produces a warning; it does not
  stop the scan. Enforce a time/target budget before starting.

## Platform notes

- Linux: raw sockets need root or `CAP_NET_RAW`; stateful scans need the
  firewall rules from the `xtate://docs/firewall` resource. Never disable the
  firewall to make a scan work.
- Windows: raw capture needs Npcap and administrator rights; the control
  endpoint is a Named Pipe, not a TCP port. UTF-8 paths are supported.
- Multi-NIC hosts: confirm the interface with `explain_target` before starting.
  For `include_file`, the server does not discover routes; an explicit
  `interface` skips that check, so verify it yourself.

## When to stop

Stop and ask the operator when the target set is ambiguous, a route is
unexpected, authorization cannot be confirmed, the scope would expand, or a
retry would exceed the authorized time window. Do not “try it and see” with
packets.
