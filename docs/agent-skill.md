# Agent Skill for Xtate

The Xtate Agent Skill is a Markdown playbook that teaches an external agent how
to use the Xtate MCP server safely and correctly. It is not an Xtate agent, not
a separate binary, and not a privilege boundary.

The skill lives in the repository at
[`skills/xtate/`](../skills/xtate/SKILL.md). It is guidance: the MCP server and
control plane still enforce authorization, target counts, rates, routes and
result paths.

## Scope: MCP only

This skill teaches an external agent to use **the Xtate MCP server**, not the
Xtate command line. It contains no CLI command syntax and deliberately tells the
agent not to bypass MCP validation with a shell. For direct CLI use, follow the
[manual](./manual/README.md) and `--help` instead. The same Xtate engine and
safety model apply, but the CLI is the expert-facing interface and has no MCP
tool-call wrapper.

## What it contains

| File | Purpose |
|---|---|
| `SKILL.md` | trigger description and the end-to-end scan workflow |
| `references/tools.md` | MCP tool contracts, `start_scan` fields, job states, result files |
| `references/safety.md` | authorization checklist, stop conditions, host prerequisites, token hygiene |
| `references/troubleshooting.md` | error-to-action table and platform notes |

The main workflow is:

```text
confirm authorization and exact scope
→ list_modules / describe_probe
→ explain_target and check (split multi-route sets)
→ validate_config
→ start_scan with flat fields and authorized:true; result_path is optional
→ poll job_status
→ job_result_manifest, then read chunks in id order
```

## Install

Copy or symlink the skill directory into the location your agent host scans for
skills. Common layouts are:

```bash
# repository checkout
skills/xtate/

# per-user installs used by some hosts
~/.claude/skills/xtate/
~/.agents/skills/xtate/
```

For example:

```bash
cp -r skills/xtate ~/.claude/skills/xtate
```

Use the path documented by your host. The skill does not need to be next to the
Xtate binary; it only needs to be discoverable by the agent.

## Use

Start the control plane and MCP server as described in the
[MCP server guide](./mcp-server.md):

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --control-plane=/tmp/xtate-ctl.sock
xtate --mcp --control-connect=/tmp/xtate-ctl.sock
```

Then give the agent a scoped request, for example:

> Scan 203.0.113.10 and 203.0.113.11 on TCP 80 and 443 with tcp-syn, at most
> 500 packets per second, for at most 5 minutes. I own this test network.

The skill directs the agent to preflight the route, validate the request, start a
bounded job, and report the manifest and counts instead of dumping raw results.
The agent still has to confirm the scope; the skill does not turn a vague request
into an authorization.

## Security boundary

- `authorized: true` is an attestation, not proof. The skill tells the agent to
  confirm who authorized the scan and the exact ranges, ports and window first.
- The MCP server rejects missing authorization, unknown modules, mixed target
  sources, invalid rates/timeouts, mixed routes and unwritable result paths.
  The skill cannot weaken those checks.
- The skill contains no executable code and no credentials. It must never be
  given a control token in its files.
- A skill is not an agent evaluation. Prompt injection, scope expansion and
  retry behavior still need host-level review.

## Large target sets

The MCP argument buffer is 8 KiB. For larger sets the skill directs the agent to
`include_file`, with one target or range per line, and to preflight
representative targets with `explain_target`. Route discovery from an
`include_file` is not implemented; passing an explicit `interface` skips that
server-side preflight, so the operator must verify it.

## Maintenance

Update the skill when MCP tools, `scan-request.schema.json`, the error envelope,
or the job/result model changes. Keep examples in `skills/xtate/` consistent with
the [MCP server guide](./mcp-server.md) and the
[scan request schema](../schemas/scan-request.schema.json).

Before changing the skill, run a no-skill baseline on a scoped scan scenario and
record the failure. After changing it, run the same scenario and check that the
agent passes `target` (a single string) to `explain_target`/`check` and `targets`
(an array) to `start_scan`, uses flat `start_scan` fields (no nested `arguments`),
`timeout_sec`, an explicit scope confirmation, and a dedicated `result_path` when
one is supplied (otherwise the managed run directory is used).

## Related

- [MCP server](./mcp-server.md) — tools, resources, limits
- [Control plane](./control-plane.md) — job API shared by MCP and GUI
- [Job model](./job-model.md) — lifecycle, heartbeat, cancellation
- [AI integration design](./ai-integration.md) — how the skill fits the layers
