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

## What the dashboard does

- Lists jobs from `job.list`, newest state refreshed every three seconds.
- Shows the selected job's phase, sent/targets counters, heartbeat, elapsed
  time, exit code, result and log path, error and bounded stderr tail.
- Shows the result manifest (`complete`, result path, manifest path and bytes).
- Starts a scan through a small wizard: scan module, targets, optional ports,
  rate, timeout, result path and an optional interface. The scan starts only
  after the operator ticks the explicit authorization checkbox; the bridge also
  rejects `job.start` unless `params.authorized` is literally `true`.
- Cancels a selected queued or running job after confirmation.

The wizard is intentionally smaller than the full scan-request schema. For
probe arguments, scan arguments, include files, chunking or quota settings, use
the MCP server or the JSON control API directly.

## Security model

- **Loopback only.** The listener binds `127.0.0.1`; `--gui-listen` rejects
  non-loopback hosts. There is no TLS because there is no network path.
- **Session token.** A random 128-bit token is generated at startup. The page
  sends it in `X-Xtate-GUI-Token`; the server compares it in constant time.
- **Host validation.** Requests with a non-loopback `Host` header are rejected,
  which prevents DNS-rebinding pages from reaching the API.
- **Method allowlist.** Only `job.list`, `job.status`, `job.cancel`,
  `job.result_manifest` and `job.start` are forwarded. The GUI cannot call
  `ping`, `job.results` or arbitrary control methods.
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

The test starts a real control plane and GUI bridge, checks the page and token,
rejects a non-loopback Host and a missing token, starts a dry-run job and polls
it to a terminal state. It does not require a browser.

## Related

- [Control plane](control-plane.md)
- [Job model](job-model.md)
- [TUI dashboard](tui.md)
- [MCP server](mcp-server.md)
