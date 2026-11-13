# TUI dashboard

The TUI is a full-screen **control-plane client**. It does not scan in-process
and it does not replace the scanner CLI. Every action becomes a JSON-lines
request to a running control plane, the same API used by MCP and the planned
GUI. The control plane keeps ownership of job lifetime, timeouts, result files,
quota warnings and cancellation.

Use the TUI when you want to watch several managed jobs, cancel one, or start a
small authorized scan without composing JSON by hand.

## Requirements

- A running control plane on the same host:
  - Unix: `--control-plane=/tmp/xtate-ctl.sock`
  - Windows: `--control-plane=\\.\pipe\xtate-ctl`
- The same `XTATE_CONTROL_TOKEN` value in the control-plane process and in the
  TUI process when a token is configured.
- A terminal that supports ANSI escape sequences. Windows 10/11 Terminal and
  current Windows consoles work; the TUI enables virtual-terminal processing.
- A UTF-8 capable terminal for non-ASCII result paths.

## Start

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --control-plane=/tmp/xtate-ctl.sock
# in another terminal, with the same token:
xtate --tui --control-connect=/tmp/xtate-ctl.sock
```

Windows PowerShell:

```powershell
$env:XTATE_CONTROL_TOKEN = "change-me"
xtate --control-plane=\\.\pipe\xtate-ctl
# in another terminal:
xtate --tui --control-connect=\\.\pipe\xtate-ctl
```

If `--control-connect` is missing, `--tui` exits with an error. The TUI never
starts a control plane for you.

## Keys

| Key | Action |
|---|---|
| `↑` / `k` | select previous job |
| `↓` / `j` | select next job |
| `r` | refresh now |
| `s` | start-scan wizard |
| `c` | cancel selected job (asks `y/n`) |
| `Enter` | details: status plus result manifest |
| `q` | quit and restore the terminal |

The dashboard refreshes every two seconds. It lists `job_id`, state and result
path from `job.list`; the selected row also shows phase, sent/targets,
heartbeat age and elapsed time from `job.status`. The details screen adds the
manifest path, byte count and completion flag from `job.result_manifest`.

## Start wizard

The wizard asks for:

1. scan module, default `tcp-syn`;
2. targets, comma-separated (each item is passed as one target string);
3. ports, comma-separated integers `0..65535`; blank lets the scan module use
   its default;
4. optional interface name;
5. rate, default `1000` packets/second;
6. timeout, default `300` seconds;
7. result path, default `xtate-tui-<epoch>.ndjson` (relative paths are relative
   to the control-plane process, not the TUI);
8. confirmation: type exactly `YES`.

The TUI only sends `authorized: true` after that confirmation. This is a
usability guard, not the security boundary: the control plane is local and
trusted. MCP still enforces `authorized: true` itself; the control plane does
not accept remote connections.

The wizard does not support `include_file`, `probe_args`, `scan_args`, zstd or
quota settings. Use the MCP `start_scan` tool or a scan-request JSON file for
those.

### Interface selection

Xtate needs one capture interface for a scan. If the host has several default
interfaces, worker startup can fail with:

```text
multiple default interfaces detected (2); use -if to choose explicitly
```

Run the normal preflight on the same target, then paste its `Interface` value
into the wizard:

```bash
xtate --explain-target=203.0.113.0/24
```

On Windows an interface usually looks like
`\Device\NPF_{...}`. On Linux it is a device name such as `eth0` or `lo`.
Leaving the field blank lets Xtate choose automatically when the route is
unambiguous.

## Scripted snapshot

When stdin or stdout is not a terminal, `--tui` prints a plain-text snapshot and
exits. This is useful for smoke tests and status checks:

```bash
xtate --tui --control-connect=/tmp/xtate-ctl.sock
```

It prints the endpoint, job count and the same id/state/result table. It does
not read keys and does not start the wizard.

## Responsibilities and limits

- The TUI is a client. It cannot bypass control-plane validation, result paths,
  interface matching or job limits.
- The control-plane token is optional for local Unix sockets and Named Pipes;
  set `XTATE_CONTROL_TOKEN` for shared machines.
- The TUI does not read result records. It shows the manifest; read chunks with
  the scanner CLI, MCP resources or your own NDJSON reader.
- Cancellation is best-effort. A worker that already exited may report
  `"cancelled": false`; refresh the row.
- The TUI is local-only by design (the control transport is a Unix socket or a
  Named Pipe). There is no network mode.
- Terminal restoration is registered at startup; if the process is killed with
  `SIGKILL` or the console is closed, the terminal may remain in raw mode. Run
  `reset` on Unix if that happens.

## Related

- [Control plane](./control-plane.md) — request/response contract
- [Job model](./job-model.md) — states, heartbeat, timeout, result chunks
- [MCP server](./mcp-server.md) — the same jobs through MCP tools
- [Agent Skill](./agent-skill.md) — playbook for external agents
