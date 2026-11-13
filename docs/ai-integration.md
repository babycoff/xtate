# AI integration (MCP / Agent / Skill)

Xtate is callable by AI agents through a typed, auditable interface instead of an
unrestricted shell. The CLI remains the source of truth; the control plane owns
jobs, and the MCP server is a thin client of that control plane.

## Current state

Implemented in 2.42.0:

- managed scan jobs with timeout, stall detection, heartbeat and cancellation;
- a local control plane over a Unix socket or Windows Named Pipe with optional
  shared-token authentication through `XTATE_CONTROL_TOKEN` (set it in
  production);
- a stdio MCP server exposing module metadata, route planning, validation, job
  start and job queries;
- chunked result files with a manifest; results are never returned inline;
- JSON contracts for scan requests and error codes.

Delivered for 2.42.1:

- a reviewed Agent Skill (documentation and policy, not a privileged binary) at
  [`skills/xtate/`](../skills/xtate/SKILL.md).

Delivered for 2.43.0:

- a full-screen TUI control-plane client (`xtate --tui`) that shares the same
  job/control API; it does not add another scanning path.

Delivered for 2.44.0:

- a loopback-only browser GUI (`xtate --gui`) that is another control-plane
  client: dashboard, start wizard, cancel, status and result manifest. It binds
  loopback, uses a per-run session token and a Host check, and forwards only an
  allowlist of job methods.

Delivered for 2.44.1:

- one-command local TUI/GUI startup: when `--control-connect` is omitted, the UI
  starts a private control plane in a child process, waits for readiness, and
  stops it on exit. `--control-connect` still attaches to an existing daemon.

Delivered for 2.44.2:

- corrected RAW link-type handling for TUN/VPN adapters and added link-type
  preflight output in `--explain-target`; scan startup rejects unsupported link
  types with an actionable message.
- scan startup and meta output include the effective `Rate:` (default or
  `--rate`).

Delivered for 3.0.0-rc.3 (candidate):

- one-command `xtate --mcp` with a token-protected private control plane;
- `capabilities` and `iface.list` MCP tools, plus `--list-capabilities` JSON;
- server-authoritative `preflight` and bounded `job.records` paging through
  MCP, including chunked and zstd-compressed results;
- redesigned scan-first GUI preflight and live view as a reference front end.

Still pending:

- final 3.0.0 after RC trial feedback;
- an agent evaluation suite and packaging;
- exposing generate/stream input through MCP (MCP is static `targets` or
  `include_file` only).

## Three layers

### 1. Stable JSON contracts

Machine-readable boundaries exist for:

```text
schemas/scan-request.schema.json
schemas/module.schema.json
schemas/result.schema.json
schemas/error.schema.json and schemas/error-codes.json
NDJSON result lines
```

MCP tools return JSON text, so an agent never parses colored CLI output. The MCP
server validates a closed subset itself (scan/probe names, target syntax, port
range, rate, mutual exclusion) and the control plane validates the job request.

### 2. Agent skill

The skill teaches an agent to:

```text
confirm target authorization and the exact scope
run explain_target / check first
open only the required Linux firewall rules for stateful scans
choose a scan/probe pair and a bounded rate
start a bounded job with a dedicated result_path
read the manifest and chunks, not the whole result file
cancel or let the job time out
```

It is installed from [`skills/xtate/`](../skills/xtate/SKILL.md); see
[Agent Skill for Xtate](./agent-skill.md). A skill is policy and documentation.
It cannot enforce tool boundaries; the MCP server does that.

### 3. MCP server

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --control-plane=/tmp/xtate-ctl.sock
xtate --mcp --control-connect=/tmp/xtate-ctl.sock
```

Tools:

```text
capabilities
iface.list
list_modules
describe_probe
explain_target
check
preflight
validate_config
start_scan
job_list
job_status
job_result_manifest
job.records
job_cancel
```

`start_scan` accepts a closed object, not a shell string:

```json
{
  "scan": "tcp-state",
  "probe": "doh-h2",
  "targets": ["203.0.113.10"],
  "ports": [443],
  "probe_args": {"dns_name": "example.com", "authority": "dns.example"},
  "rate": 100,
  "timeout_sec": 30,
  "result_path": "results/doh.ndjson",
  "authorized": true
}
```

It returns a `job_id` immediately. Status and results are read later; there is no
unbounded blocking tool call and no inline result payload.

## Safety requirements

Implemented:

```text
no arbitrary shell execution
no target expansion beyond user input
scan/probe names restricted to registered modules
target and rate limits
job timeout, cancellation and audit log
explicit authorized:true assertion for start_scan
resource paths restricted to a fixed allowlist
control plane local-only; `XTATE_CONTROL_TOKEN` authentication when configured
```

Still to verify or add:

```text
capability-scoped tokens and per-client quotas
configurable audit destination and rotation
agent evaluation for prompt-injection and target-scope violations
```

## Testing

- MCP protocol conformance, schemas, resources and prompts;
- read-only tools without network access;
- scan job lifecycle: start, status, manifest, cancel and timeout;
- rejection tests: unknown modules, malformed targets, mixed routes, bad tokens,
  oversized arguments;
- Windows and Linux regression runs.

See [MCP server](./mcp-server.md), [control plane](./control-plane.md) and
[job model](./job-model.md).

## Phases

```text
2.42.0  jobs + control plane + MCP server (done)
2.42.1  Agent Skill (done, released)
2.43.0  TUI control-plane dashboard (done, released)
2.44.0  browser GUI for the control plane (done, released)
2.44.1  one-command local TUI/GUI startup (done, released)
2.44.2  RAW/TUN link preflight + startup rate display (done)
next    evaluation suite and packaging
later   MCP generate/stream input
```
