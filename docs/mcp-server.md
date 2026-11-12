# MCP server (read-only first)

```bash
xtate --mcp --control-connect=<endpoint>
```

MCP stdio JSON-RPC. Current tools:

```text
list_modules
describe_probe
explain_target
check
validate_config
start_scan
job_list
job_status
job_result_manifest
job_cancel
```

Tool results are text JSON from the control plane. The MCP server does not carry
result data; clients fetch chunks via the result manifest.

Still planned: `list_modules`, `describe_probe`, `explain_target`, `check`,
`validate_config`, and controlled `start_scan`.

## Model-facing metadata

`initialize` returns `serverInfo` plus an `instructions` string describing
Xtate, supported protocols, authorization, firewall prerequisites and the job
model. `tools/list` includes descriptions, JSON input schemas and read-only /
destructive annotations. Resources expose overview, firewall and scan-request
schema; a `plan-safe-scan` prompt is provided. `list_modules` returns full
module metadata.

## Tool behavior

- `describe_probe` filters module metadata by name.
- `validate_config` checks scan/targets presence.
- `start_scan` requires `authorized:true`; rejects more than 20000 quoted fields and rate > 10000; writes `xtate-mcp-audit.log`.
- `explain_target` / `check` return interface, source IPv4, gateway and Linux firewall status from the default interface. Per-target route selection is not yet mirrored from CLI.

## Route-aware tools

`explain_target` and `check` accept a target set and return structured
`targets`, `route_groups` and `groups` (interface/source/gateway/samples).
`start_scan` runs the same route grouping and refuses targets that span more
than one route; split those into separate jobs.

## Tests

`tests/mcp/test_mcp.py` covers initialize/instructions, tools/list schemas,
resources/list, describe_probe, structured explain_target, validate/start
guards, start_scan -> job_status/job_result_manifest/job_list, and mixed-route
rejection when the target set actually spans routes.

## P0 test coverage

`tests/mcp/test_mcp.py` additionally asserts unknown RPC methods, unknown
tools, malformed/absent tool arguments, malformed resource URIs, unknown job
ids, unwritable result paths, real `completed` jobs, and presence of
`log_path`/`stderr_tail`.

## P1 test coverage

Unicode and space-containing result paths, missing token, concurrent jobs,
`job_list` pagination, mixed-route rejection, and chunk manifest checks are
covered when the worker completes.

## P2 stability coverage

`tests/mcp/test_mcp_stability.py` covers timeout, cancellation, concurrent
requests, oversized configuration rejection, malformed JSON, control-plane
restart (Windows) and a second MCP client. Oversized requests above the 8 KiB
MCP argument buffer are rejected cleanly; large target sets need a future
file/stream input path.
