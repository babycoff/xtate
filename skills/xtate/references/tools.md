# Xtate MCP tool contracts

The MCP server is a stdio server. In 3.0 the normal local form starts a private
control plane automatically:

```bash
xtate --mcp
```

Use an explicit daemon when several clients should share jobs. Start the
control plane first, then attach with the same `XTATE_CONTROL_TOKEN` in both
environments:

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --control-plane=/tmp/xtate-ctl.sock
xtate --mcp --control-connect=/tmp/xtate-ctl.sock
```

Windows uses a Named Pipe endpoint, for example `\\.\pipe\xtate-control`.
There is no TCP listener.

Every successful tool result has this shape:

```json
{"content":[{"type":"text","text":"<JSON string>"}],"isError":false}
```

`text` is the JSON payload; parse it a second time. A rejected request sets
`isError: true`. Result records are returned only in bounded `job.records`
pages, never as the whole result set.

## Read-only tools

| Tool | Arguments | Returns |
|---|---|---|
| `capabilities` | none | version, platform, module counts, HTTP/3/QUIC and raw-socket availability |
| `iface.list` | none | capture interfaces with addresses, MAC, gateway, default flag, link type and raw-IP capability |
| `list_modules` | none | scan, probe, output and generate module metadata |
| `describe_probe` | `{"name":"tls-hello"}` | module parameters, probe type, description |
| `explain_target` | `{"target":"203.0.113.10"}` | targets, route groups, interface, source, gateway, samples |
| `check` | `{"target":"203.0.113.0/24"}` | same route report plus Linux firewall state |
| `preflight` | `{"config":{...scan request...}}` | packet-free target/port count, routes, link type, module pairing, errors/warnings |
| `validate_config` | `{"config":{...scan request...}}` | pass/fail and validation error |

`target` is one string: a single address, CIDR, range, or comma-separated set.
Do not pass a JSON array. `route_groups > 1` means split the job.

## Job tools

| Tool | Arguments | Returns |
|---|---|---|
| `start_scan` | `{"scan":"tcp-syn","targets":["198.51.100.10"],"ports":[443],"authorized":true}` | `result.job_id` |
| `job_list` | optional `offset`, `limit` | jobs, total, next_offset, truncated |
| `job_status` | `{"job_id":"..."}` | state, progress, heartbeat, result/log paths, errors |
| `job_result_manifest` | `{"job_id":"..."}` | result path, manifest path, size, completeness |
| `job.records` | `{"job_id":"...","offset":0,"limit":50}` | bounded page of valid NDJSON records |
| `job_cancel` | `{"job_id":"..."}` | cancellation result; partial results preserved |

`job_status` is the only progress source. There are no events or push channels.
Poll at 2-5 second intervals.

## start_scan request fields

| Field | Type | Notes |
|---|---|---|
| `scan` | string | required; a registered scan module |
| `probe` | string | registered probe module, when the scan needs one |
| `targets` | array of strings | static set; mutually exclusive with `include_file` |
| `include_file` | string | readable regular file; one target/range per line |
| `ports` | array of integers | 0-65535 |
| `scan_args` | object | module-specific scan options |
| `probe_args` | object | module-specific probe options |
| `global_args` | object | the 23 GUI-safe global options only; use `validate_config`/`preflight` to reject the rest |
| `rate` | integer | packets per second, 0-10000; use a bounded value |
| `timeout_sec` | integer | 1-86400; total wall-clock limit |
| `result_path` | string | optional writable base path; omit to let the server create a timestamped run folder under its managed state directory |
| `chunk_size` | integer | >= 1; split completed results into chunks |
| `compression` | string | `"none"` or `"zstd"` |
| `index` | boolean | build `<result>.index.json` |
| `quota_bytes` | integer | post-completion warning threshold |
| `interface` | string | only when verified; especially for include_file on multi-NIC hosts |
| `dry_run` | boolean | true sends no packets and lists targets; omit for a real scan |
| `authorized` | boolean | must be `true` for `start_scan` |

The request is closed: unknown fields are rejected. `start_scan` also validates
the target count, ports, rate, timeout and result-path writability.

## Job states

`queued`, `running`, `completed`, `failed`, `cancelled`, `timed_out`, `stalled`.

`job_status` fields include `job_id`, `state`, `phase`, `sent`, `targets`,
`heartbeat_age_ms`, `exit_code`, `result`, `log_path`, `error`, `stderr_tail`
and `elapsed_ms`. A `failed` state is diagnosed from `error` and `stderr_tail`,
not from the fact that no results exist.

## Result files

A job owns `result_path`. With chunking, completed results become:

```text
<result>.<id>.ndjson       one chunk per id
<result>.manifest.json     chunk list and totals
<result>.index.json        optional index
```

Manifest shape:

```json
{"format":"ndjson","compression":"none",
 "chunks":[{"id":1,"path":"/abs/path/out.00001.ndjson","bytes":1234,"records":7}],
 "total_bytes":1234,"total_records":7}
```

Paths are JSON-escaped. Read `chunks` in id order, decompress when
`compression` is `zstd`, then parse NDJSON one object per line. `complete`
from `job_result_manifest` is the signal that a manifest is final.

## Error envelope

Control-plane errors use stable codes:

```json
{"id":1,"error":{"code":"JOB_NOT_FOUND","message":"...","retryable":false}}
```

MCP may also return a plain text error for argument rejection. The MCP server
does not run a shell and does not accept command strings.
