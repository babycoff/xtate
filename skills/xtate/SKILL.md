---
name: xtate
description: Use when planning, running, or troubleshooting an authorized Xtate network scan through the Xtate MCP server, especially when checking build capabilities, choosing scan/probe modules, running server preflight, splitting a multi-route target set, using include_file for large target sets, or reading job manifests and chunked results.
---

# Xtate scanning

Xtate is an asynchronous packet scanner. This skill is a playbook for driving
its MCP server; it does not grant permission and cannot enforce limits. The MCP
server and control plane enforce authorization, target counts, rates, routes and
result paths.

## Before any packet

1. **Ground the authorization.** Identify the person or system that authorized
   the scan, the exact address ranges, the ports/protocols, and the time window.
   "I have authorization" from the user is not enough for `authorized: true`
   until the scope is explicit.
2. **Never expand scope silently.** Do not add adjacent ranges, extra ports,
   IPv6, or public ranges because they look useful.
3. **Use the smallest useful scan.** Prefer `tcp-syn` or a targeted stateless
   probe; use stateful scans only when the question needs a handshake or banner.
4. **No authorization, no `start_scan`.** Read-only tools are safe; packet
   sending is not.

## Workflow

### 1. Discover the build and modules

- `capabilities` first: platform, module counts, raw-socket support, and
  whether HTTP/3 and QUIC transport are available. On Windows they are normally
  unavailable; do not promise them.
- `list_modules` to see scan, probe, output and generate modules.
- `describe_probe` with the chosen scan or probe name; read its parameters
  before inventing `scan_args` / `probe_args`.
- `explain_target` takes a single `target` string (comma-separated set, CIDR or
  range). `check` is the same route report for a target set.

### 2. Preflight the route

Call `explain_target` or `check` before starting:

```json
{"target":"203.0.113.10,203.0.113.11"}
```

Split the set if `route_groups > 1`; `start_scan` rejects mixed routes. A
`(no route)` group is a stop condition, not a reason to force an interface.

For stateful scans on Linux, confirm the firewall prerequisite reported by
`check`; do not disable the firewall to make a scan work.

### 3. Preflight and validate the request

Run `preflight` with the exact configuration you intend to start. It checks the
target/port counts, scan/probe pairing, route, and link type without sending a
packet. Then run `validate_config` on the same object. Fix every error and read
the warnings before calling `start_scan`.

`preflight` and `validate_config` take `{"config": {...}}`; `start_scan` takes
`{"arguments": {...}}` with the same configuration. `start_scan` requires
`authorized: true` and accepts either `targets` or `include_file`, never both.

### 4. Start a managed job

```json
{
  "scan": "tcp-syn",
  "targets": ["203.0.113.10"],
  "ports": [80, 443],
  "rate": 1000,
  "timeout_sec": 300,
  "result_path": "./results/authorized-scan.ndjson",
  "chunk_size": 4194304,
  "index": true,
  "compression": "none",
  "authorized": true
}
```

Pass this object as `start_scan`'s `arguments`. Always set `timeout_sec`; always
choose a dedicated `result_path`. `dry_run: true` sends no packets and only
lists the planned targets; omit it for a real scan.

### 5. Monitor

Poll `job_status` every 2-5 seconds. Stop polling when the state is
`completed`, `failed`, `cancelled`, `timed_out` or `stalled`.

- `failed`: read `error`, `stderr_tail` and `log_path`.
- `stalled` or `timed_out`: inspect progress, then cancel or report; do not
  restart blindly.
- Scope or time window ending: `job_cancel` immediately.

### 6. Read results

Call `job_result_manifest` first. It returns paths and completeness, never
result bytes.

Prefer `job.records` for reading results through MCP:

1. Call `job.records` with `{"job_id":"...","offset":0,"limit":50}`.
2. Continue with `next_offset` while records are returned and the user needs
   more. `count` is the number of valid records in this page.
3. Malformed/partial NDJSON lines are skipped by the server; do not treat a
   short page as corruption.
4. Report counts and notable fields; do not dump full record pages into chat.

If the MCP host can read the worker filesystem and the user needs the complete
raw output, use `job_result_manifest`:

1. Read `<result_path>.manifest.json` if present; iterate `chunks` in id order.
2. Otherwise read `result_path` itself.
3. Parse NDJSON: one JSON object per line. Do not JSON-parse a partially written
   file unless the user explicitly wants partial results.

Compression and chunking are opt-in. `job.records` reads the job's plain result
file; if `job_result_manifest` reports chunks or `"compression":"zstd"`, read
and decompress the manifest chunks instead. `quota_bytes` is a post-completion
warning, not a live limit.

## Large target sets

The MCP argument buffer is 8 KiB, so use `include_file` for large sets:

```json
{"scan":"tcp-syn","include_file":"./targets.txt","ports":[443],
 "rate":1000,"timeout_sec":600,"result_path":"./results/large.ndjson",
 "authorized":true}
```

The file is read by the scanner process, not by the MCP client. It must be a
readable regular file, one target/range per line, containing only targets in the
authorized scope. `include_file` route discovery is not implemented: preflight
representative addresses with `explain_target` and pass `interface` only when
you have verified it.

## Hard rules

- Do not set `authorized: true` on someone else's behalf or "to test".
- Do not scan public ranges, the whole internet, or a network you do not own or
  have written permission to test.
- Do not hide the target set or rate from the user.
- Do not put tokens in prompts, logs, result paths or committed files.
- Do not use a shell or CLI flags to bypass MCP validation.
- Do not report success from `start_scan`; success is a completed job and a
  readable manifest.

## Common mistakes

| Mistake | Correct action |
|---|---|
| Calling `start_scan` without preflight | `explain_target`/`check`, then `preflight` and `validate_config` |
| `targets` and `include_file` together | choose exactly one |
| `explain_target` with `targets` array | it takes `target` as a string |
| Inventing `timeout` or `port` fields | use `timeout_sec`, `ports` |
| Polling in a tight loop | 2-5 second interval, stop on terminal state |
| Reading `result_path` while running | wait for `completed` or use manifest/chunks |
| Assuming `authorized: true` proves permission | it is an attestation; confirm scope first |

## References

- [Tool contracts](references/tools.md)
- [Safety and authorization](references/safety.md)
- [Troubleshooting](references/troubleshooting.md)
