# Browser GUI

Xtate ships a loopback-only browser dashboard for the control plane. It is a
client, like MCP and the TUI: it renders jobs, starts authorized scans and
cancels work, but the control plane still owns workers, timeouts, result files
and the actual scan process.

The GUI is intended for a local analyst workstation. It is not a remote web
service and does not expose the control plane over TCP.

## Requirements

- A control plane endpoint (Unix socket or Windows Named Pipe).
- The same `XTATE_CONTROL_TOKEN` as the control plane, if one is configured.
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

Jobs started in this private mode stop when the GUI exits. To attach to an
already-running control plane instead (for long-lived jobs or another client),
pass its endpoint explicitly:

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
- **Live** polls `job.status` every 1.5 seconds, shows phase, sent/targets,
  heartbeat, elapsed time, exit code, result/log path and the bounded stderr
  tail, and cancels a queued or running job after confirmation.
- **Results** lists jobs from `job.list`; opening one shows the manifest state,
  result bytes and paths.
- **Interfaces** lists capture adapters with IPv4/IPv6, MAC, gateway, default
  flag, link type and raw-IP capability. **Modules** searches the module catalog;
  **Settings** shows runtime, capability and security state.

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
  `/api/system`, `/api/interfaces`, `/api/modules` and `/api/preflight` are
  server-side read-only handlers; they cannot call arbitrary control methods.
- **No shell.** The GUI is in-process C; the optional browser launch uses
  `ShellExecuteW` on Windows and `xdg-open` on Unix.
- **Token handling.** The control-plane token is read from the environment and
  added by the server; page JavaScript never receives it. The browser session
  token is visible in the page source, so treat the browser profile as trusted
  local state.

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

## Tests

```bash
python tests/gui/test_gui.py
```

The test starts a real control plane and GUI bridge, checks the page, token,
system/interfaces/modules/preflight endpoints, rejects a non-loopback Host and
a missing token, and starts a dry-run job and polls it to a terminal state. It
does not require a browser.

## Related

- [3.0 manual](manual/README.md)
- [Control plane](control-plane.md)
- [Job model](job-model.md)
- [TUI dashboard](tui.md) (deprecated in 3.0)
- [MCP server](mcp-server.md)
