# MCP server

Xtate exposes a Model Context Protocol (MCP) server over stdio. It is a typed
client of the control plane with local read-only discovery tools: it never
embeds scan results, never spawns a shell, and never accepts a command string.
Discovery runs the same executable with a fixed argument vector.

## Starting it

Start a control plane and an MCP client with the same token (when one is set):

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"

# Terminal 1: control plane (Unix socket on Linux, Named Pipe on Windows)
xtate --control-plane=/tmp/xtate-ctl.sock

# Terminal 2: MCP server
xtate --mcp --control-connect=/tmp/xtate-ctl.sock
```

On Windows the endpoint is a Named Pipe such as
`\\.\pipe\xtate-control`. `--control-connect` only establishes a local
connection; it does not listen on TCP.

## Tools

| Tool | Purpose |
|---|---|
| `list_modules` | Full module metadata: scan, probe, output and generate modules |
| `describe_probe` | Metadata for one named scan/probe module |
| `explain_target` | Route groups, interface/source/gateway and Linux firewall state for a target set |
| `check` | Same route/firewall report as `explain_target` |
| `validate_config` | Validate a closed scan-request object without starting a job |
| `start_scan` | Start a managed scan job and return its `job_id` |
| `job_list` | Paginated job list |
| `job_status` | State, counters, exit code, error, log path and stderr tail |
| `job_result_manifest` | Result/chunk paths, sizes and completeness |
| `job_cancel` | Cancel a running job |

Every result has the MCP text-content shape:

```json
{"content":[{"type":"text","text":"{\"ok\":true,...}"}],"isError":false}
```

The `text` field is JSON. `isError` is true when the tool rejected the request
or the control plane returned an error object. Scan result data is never
returned inline: clients read the manifest and then the chunk files.

`start_scan` requires `authorized: true`, which records the caller's assertion
that the targets are authorized. It accepts either `targets` (a JSON array) or
`include_file`, never both. `include_file` is the path for large target sets;
the MCP argument buffer is 8 KiB.

## Model-facing metadata

`initialize` returns `serverInfo` and an `instructions` string that describes
Xtate, the supported protocols, authorization requirements, Linux firewall
prerequisites and the job/result split. `tools/list` provides descriptions,
input schemas and read-only/destructive annotations.

The server also exposes three resources and one prompt:

```text
xtate://docs/overview          docs/README.md
xtate://docs/firewall          docs/firewall.md
xtate://schemas/scan-request   schemas/scan-request.schema.json
plan-safe-scan                 a checklist for planning an authorized scan
```

The two documents are returned as `text/markdown`; the schema is returned as
`application/json`.

### Resource lookup and security

Resource URIs are matched exactly against the compiled-in allowlist above.
Targets are relative, fixed filenames; no URI, tool argument or MCP field can
select an arbitrary path. Absolute paths, drive-qualified paths, and any path
containing `..` are rejected before the filesystem is touched.

For each allowlisted file the server tries, in order:

1. `$XTATE_MCP_DOCS_DIR/<file>`
2. the current working directory
3. the executable's directory and up to four parent directories

`XTATE_MCP_DOCS_DIR` is local operator configuration; point it at the
repository or install root that contains `docs/` and `schemas/`. It is read from
the server process environment only; a remote MCP client cannot set it. Documents
are read as data and returned as text, never executed.

This lookup makes resources work from an arbitrary working directory in a
repository build or a normal installation. If the documentation files are not
installed, `resources/read` returns `-32002 resource not found`; it does not
fall back to scanning the filesystem.

## Route-aware planning

`explain_target` and `check` accept a target-set string (for example
`203.0.113.0/24,2001:db8::1`) and return structured `targets`, `route_groups`
and `groups` with interface, source address, gateway and samples. Linux also
reports whether the firewall prerequisite is satisfied.

`start_scan` performs the same grouping for inline `targets` and refuses a set
that spans more than one route; split it into separate jobs. With
`include_file`, pass `interface` explicitly on multi-NIC Windows hosts. Route
discovery from an include file is not implemented, so the server does not claim
to verify it.

## Limits and validation

- `scan` must name a registered scan module; `probe` must name a registered probe.
- Inline `targets` are limited to 20000 array entries; port values must be 0-65535.
- `rate` is capped at 10000 packets per second.
- `result_path` is probed for writability before the job starts.
- Large inline arguments above the MCP buffer are rejected cleanly.
- `start_scan` appends an audit record to `xtate-mcp-audit.log` in the MCP
  process working directory; the record contains rate and the truncation-bounded
  config.

## Tests

`tests/mcp/test_mcp.py` covers initialization and instructions, tool schemas,
resources and prompts, unknown methods/tools, malformed arguments and URIs,
`list_modules`/`describe_probe`, route grouping, rejection guards, a real
completed job, `log_path`/`stderr_tail`, Unicode result paths, missing or wrong
tokens, `job_list` pagination, chunk manifests and resource reads from an
arbitrary working directory.

`tests/mcp/test_mcp_stability.py` covers timeouts, cancellation, concurrent
requests, malformed JSON, oversized configuration, control-plane restart and a
second MCP client. Both suites pass on Windows and Linux.
