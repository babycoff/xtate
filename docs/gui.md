# Browser GUI

Xtate ships a loopback-only browser dashboard for the control plane. It is a
client, like MCP and the TUI: it renders jobs, starts authorized scans and
cancels work, but the control plane still owns workers, timeouts, result files
and the actual scan process.

The GUI is intended for a local analyst workstation. It is not a remote web
service and does not expose the control plane over TCP.

## Requirements

- An attached control-plane endpoint (Unix socket or Windows Named Pipe), or
  the default private control plane started by `xtate --gui`.
- For an attached daemon, the same `XTATE_CONTROL_TOKEN` as that daemon, if one
  is configured.
- A modern browser with `fetch` and `<dialog>` support.

See [control-plane.md](control-plane.md) for starting the daemon.

## Start

The usual local case is one command. If `--control-connect` is omitted, the GUI
starts a private control plane in a child process, waits for it, and stops it
when the GUI exits:

```bash
xtate --gui
```

Windows PowerShell:

```powershell
.\bin\xtate.exe --gui
```

Jobs started in this private mode stop when the GUI exits. If
`XTATE_CONTROL_TOKEN` is not already set, the GUI generates an ephemeral
128-bit token for the private control plane and passes it to the child, so
other local accounts cannot drive the pipe or socket. The token is removed
when the GUI exits and is never printed. To attach to an already-running
control plane instead (for long-lived jobs or another client), pass its
endpoint explicitly:

```bash
export XTATE_CONTROL_TOKEN='change-me'
xtate --control-plane=/tmp/xtate-ctl.sock

# second terminal
xtate --gui --control-connect=/tmp/xtate-ctl.sock
```

Windows PowerShell:

```powershell
$env:XTATE_CONTROL_TOKEN = 'change-me'
.\bin\xtate.exe --control-plane=\\.\pipe\xtate-ctl

# second terminal
.\bin\xtate.exe --gui --control-connect=\\.\pipe\xtate-ctl
```

By default the GUI listens on `127.0.0.1:8787`, prints a random session token
and opens the page in the default browser. Options:

| Option | Meaning |
|---|---|
| `--gui-listen=127.0.0.1:PORT` | Listen port; only loopback hosts are accepted. `:0` picks a free port. |
| `--gui-no-open` | Print the URL and token but do not open a browser. |
| `--control-connect=...` | Optional endpoint. Use it to attach to an existing control plane; omitted starts a private one. |

The browser URL is printed as `http://127.0.0.1:<port>/`. The session token is
printed once and is also injected into the page; requests without the matching
`X-Xtate-GUI-Token` header are rejected.

Result and log files are not written beside the binary. The control plane uses a
managed state directory: `%LOCALAPPDATA%\xtate\results` on Windows, or
`$XDG_STATE_HOME/xtate/results` (falling back to
`$HOME/.local/state/xtate/results`) on Linux. Set `XTATE_STATE_DIR` to override
it. Request files live under the same state directory and are removed when the
job reaches a terminal state.

## What the console does

The GUI is scan-first: the default page is **New scan**, not a job table.

- **New scan** accepts IPv4/IPv6 targets in comma, range or CIDR form, picks one
  of the 11 scan engines, shows probe choices only when the engine needs one,
  and hides ports for ICMP/ARP/NDP scans. Rate, timeout and an optional interface
  are set here.
- The server-side **preflight** (`POST /api/preflight`) parses the same request
  as `job.start`, verifies target syntax and counts, resolves route, source,
  gateway, link type and raw-IP capability, and rejects unknown scans/probes,
  UDP-only ports for a TCP engine, and invalid numeric values. Nothing is sent.
- **Start scan** stays disabled until the preflight is ready, the authorization
  checkbox is ticked, and the form has not changed since the preflight. The
  bridge also rejects `job.start` unless `params.authorized` is literally `true`.
- **Module parameters** exposes the selected scan engine and probe flags and text
  arguments. Values are sent as `scan_args`/`probe_args`; empty fields are omitted.
  Preflight does not validate argument names or values, so a bad value fails the
  job with the worker argument error in `stderr_tail`/the log.
- **Live** polls `job.status` at a configurable interval and leads with a large
  status headline (`Scanning`, `Scan complete`, `Scan failed`, and so on) plus
  sent/targets, throughput, elapsed time, exit code, result/log path and a
  cleaned worker-log tail. There is no progress bar. **Open log** and **Open
  result** hand the server-resolved job files to the operating system's default
  application (with a text-editor fallback on Windows when `.log`/`.ndjson` has
  no file association). Cancelling asks for confirmation.
- **Results** lists jobs from `job.list`; opening one moves to Live with that job
  selected. **Load records** reads the completed result file through
  `GET /api/results?job_id=...&offset=...&limit=...` (50 records per page) and
  **Load more** pages through it. Only valid NDJSON records are returned;
  malformed or partial lines are skipped.
- **Interfaces** lists capture adapters with IPv4/IPv6, MAC, gateway, default
  flag, link type and raw-IP capability. **Modules** groups scan engines,
  protocol probes, output writers and generators, with search and type tabs.
  **System** has real appearance controls (Paper/Graphite theme, density, live
  refresh), runtime counts, capabilities and the local security model.

The output path is managed by the server. For include files, chunking or quota
settings, use the MCP server or the JSON control API directly. Scan and probe
arguments are editable in the Method panel.

## Security model

- **Loopback only.** The listener binds `127.0.0.1`; `--gui-listen` rejects
  non-loopback hosts. There is no TLS because there is no network path.
- **Session token.** A random 128-bit token is generated at startup. The page
  sends it in `X-Xtate-GUI-Token`; the server compares it in constant time.
- **Host validation.** Requests with a non-loopback `Host` header are rejected,
  which prevents DNS-rebinding pages from reaching the API.
- **Method allowlist.** Only `job.list`, `job.status`, `job.cancel`,
  `job.result_manifest` and `job.start` are forwarded through `/api/rpc`.
  `/api/system`, `/api/interfaces`, `/api/modules`, `/api/preflight`,
  `/api/results` and `/api/open` are server-side handlers; they cannot call
  arbitrary control methods. `/api/results` accepts only `job-<digits>` and
  reads the result path reported by that job's manifest, never an arbitrary
  client path. `/api/open` accepts only `job_id` plus `kind` (`log`, `result`
  or `manifest`); the server resolves the path from the job status/manifest and
  never opens a client-supplied path.
- **No shell.** The GUI is in-process C; the optional browser launch uses
  `ShellExecuteW`/Explorer on Windows and `xdg-open` on Unix. When Xtate is
  elevated, Windows opens the URL through the running Explorer shell so the
  browser is not forced into an elevated instance.
- **Token handling.** An attached daemon's control-plane token is read from the
  environment and added by the server; page JavaScript never receives it. In
  private mode the GUI creates an ephemeral token when the environment has none
  and removes it on exit. The browser session token is visible in the page
  source, so treat the browser profile as trusted local state.

The GUI is not a security boundary for scanning. Authorization, target limits,
rate limits, route preflight and result-path checks remain in the control plane
and MCP server.

## Troubleshooting

| Symptom | Action |
|---|---|
| `cannot start a private control plane for --gui` | The child process failed to start or bind. Check that the binary is runnable and the temp directory is writable, or pass `--control-connect` explicitly. |
| `cannot bind GUI listener` | Another process owns the port; use `--gui-listen=127.0.0.1:0` or another port. |
| Page says "control plane unavailable" | The attached daemon is down; start it or omit `--control-connect` to use private mode, and verify `XTATE_CONTROL_TOKEN` matches in both processes. |
| `GUI_TOKEN_REQUIRED` | Reload the page from the printed URL; the token must match the current server process. |
| `AUTHORIZATION_REQUIRED` | Tick the authorization checkbox in the wizard; the API also requires `params.authorized=true`. |
| `multiple default interfaces detected` | Run `xtate --explain-target=<target>`, then paste the `-if` value into the interface field. |
| Edge asks to restart because the existing instance is elevated | Current builds open the URL through Explorer when Xtate runs as Administrator, avoiding the prompt. On an older build, use `--gui-no-open` and paste the printed URL into a normally started browser. |

## Tests

```bash
python tests/gui/test_gui.py
```

The test starts a real control plane and GUI bridge with a workspace
`XTATE_STATE_DIR`, checks the page, token, system/interfaces/modules/preflight
and results endpoints, rejects a non-loopback Host and a missing token, rejects
invalid `/api/open` requests without launching an application, and starts a
dry-run job and polls it to a terminal state. It does not require a browser.

## Related

- [3.0 manual](manual/README.md)
- [Control plane](control-plane.md)
- [Job model](job-model.md)
- [TUI dashboard](tui.md) (deprecated in 3.0)
- [MCP server](mcp-server.md)
