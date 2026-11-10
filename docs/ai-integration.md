# AI integration design (MCP / Agent / Skill)

**English** · [中文](zh-CN/ai-integration.md)

Xtate should be callable by AI agents through typed, auditable interfaces — not
through an unrestricted shell. The CLI remains the source of truth; MCP and
skills are wrappers around it.

## Three layers

### 1. Stable JSON contracts

Required before any agent integration:

```text
module metadata schema
scan/probe configuration schema
result schema (NDJSON already exists)
error schema with stable codes
```

Add `--json`/`--json-schema` where the CLI currently prints human text. Never
make an agent parse colored text.

### 2. Agent skill

A reviewed `SKILL.md` that tells an agent how to:

```text
ask for target authorization
run --check / --explain-target first
install Linux firewall rules only for stateful scans
choose a scanner/probe and rate
start a bounded job
read NDJSON results
clean up firewall rules
```

The skill is documentation plus policy, not a privileged binary.

### 3. MCP server

Proposed command:

```text
xtate mcp --stdio
```

Transport: stdio JSON-RPC (MCP). Tools are small and typed.

Read-only first:

```text
list_modules
describe_probe
explain_target
check
validate_config
get_scan_status
get_results
```

Controlled scan tools after the read-only phase:

```text
start_scan
stop_scan
```

`start_scan` accepts a closed config object, not a shell string:

```json
{
  "scan": "tcp-state",
  "probe": "doh-h2",
  "targets": ["203.0.113.10"],
  "ports": [443],
  "probe_args": {"dns_name": "example.com", "authority": "dns.example"},
  "rate": 100,
  "timeout_sec": 30
}
```

It returns a job id; results are read later. No unbounded blocking call.

## Safety requirements

```text
no arbitrary shell execution
no target expansion beyond user input
allowlist scan/probe/parameter names
rate and concurrency limits
job timeout and cancellation
audit log: who/what/targets/args/result path
dry-run by default for write-like actions
explicit confirmation for scans and firewall changes
no credentials or secret storage
```

## Why not just a skill?

A skill alone cannot enforce tool boundaries or validate arguments. MCP gives a
typed boundary; the skill teaches workflow. Both are needed.

## Testing

- MCP protocol conformance and schema validation;
- tool tests: read-only tools work without network;
- scan job lifecycle: start/status/stop/results;
- rejection tests: shell metacharacters, unknown args, unbounded targets;
- agent evaluation tasks: plan a safe scan, run it, summarize results.

## Phases

```text
2.42.0  JSON contracts + skill
2.43.0  read-only MCP server
2.44.0  controlled scan jobs
2.45.0  evaluation suite and packaging
```
