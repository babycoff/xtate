# Browser GUI

Xtate ships a browser console that binds loopback by default. It is a
client, like MCP: it starts authorized scans, observes them live,
cancels work and opens results, but the control plane still owns workers,
timeouts, result files and the actual scan process.

The GUI is intended for a local analyst workstation. It is not a remote web
service and does not expose the control plane over TCP. The listener is
loopback-only unless you explicitly opt in to a non-loopback bind (see
[Security model](#security-model)); the documented container path sets
`XTATE_GUI_ALLOW_REMOTE=1`, publishes the port and still relies on the session
token.

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
and the URL, and does **not** launch a browser. Open the printed address
yourself. Options:

| Option | Meaning |
|---|---|
| `--gui-listen=HOST:PORT` | `HOST` must be `127.0.0.1`, `localhost` or (with `XTATE_GUI_ALLOW_REMOTE`) `0.0.0.0`; the port is mandatory and `:0` picks a free one. |
| `--control-connect=...` | Optional endpoint. Use it to attach to an existing control plane; omitted starts a private one. |

The browser URL is printed as `http://127.0.0.1:<port>/`. The session token is
printed once and is also injected into the page; requests without the matching
`X-Xtate-GUI-Token` header are rejected.

On Windows, results and logs are written to the visible `xtate-state` folder
beside `xtate.exe`, so they are easy to find and delete. On Linux the managed
state directory is `$XDG_STATE_HOME/xtate` (falling back to
`$HOME/.local/state/xtate`). Set `XTATE_STATE_DIR` to override it. Each scan gets
its own folder under `runs/<YYYYMMDD-HHMMSS>-<seq>/` containing `scan.ndjson`,
`scan.ndjson.log`, the manifest and the index, so runs never overwrite one
another. Request files live under `requests/` and are removed when the job
reaches a terminal state. If the portable location cannot be created (for
example the executable is in a read-only install directory), the Windows build
falls back to `%LOCALAPPDATA%\xtate`, then `%TEMP%\xtate-state`, then
`xtate-state` in the current directory; the selected root still contains
`requests` and `runs`.

## What the console does

The GUI is scan-first: the default page is **New scan**, not a job table.

- **New scan** accepts IPv4/IPv6 targets in comma, range or CIDR form, picks one
  of the available scan engines (11 on a Windows or reduced-dependency build, 12
  with `quic-state` on a full Linux build), shows probe choices only when the
  engine needs one, and hides ports for ICMP/ARP/NDP scans. Probe lists follow
  the engine's `probe_type`; `tls-state` is not offered for `quic-state`, and
  `http3-state` is not offered for `tcp-state`. Rate, timeout and an
  optional interface are set here.
- The server-side **preflight** (`POST /api/preflight`) parses the same request
  as `job.start`, verifies target syntax and counts, resolves route, source,
  gateway, link type and raw-IP capability, and rejects unknown scans/probes,
  UDP-only ports for a TCP engine, and invalid numeric values. Nothing is sent.
- **Start scan** stays disabled until the preflight is ready, the authorization
  checkbox is ticked, and the form has not changed since the preflight. The
  bridge also rejects `job.start` unless `params.authorized` is literally `true`.
- **Global parameters** exposes the 23 safe scan-wide options (seed, TTL, TCP
  window/MSS, buffer sizing, dedup and similar). Flags are checkboxes and value
  options are text fields with their descriptions. Values are validated by
  preflight and sent as `global_args`; invalid or unsafe options are rejected.
  Process, file, script, job/control and target/port/rate/interface options are
  deliberately not available here because they would break the job contract.
- **Module parameters** exposes the selected scan engine and probe flags and text
  arguments. Values are sent as `scan_args`/`probe_args`; empty fields are omitted.
  When the selected probe supports a nested probe (`tls-state` does), a
  **Subprobe** selector appears with that probe's own arguments below it. Only
  state probes are offered; TCP/UDP probes, `tls-state` itself and QUIC-only
  `http3-state` are excluded. It starts empty, so a plain TLS scan is unchanged;
  choose a subprobe only when
  the scan should continue inside TLS. The GUI sends the chosen name as
  `probe_args.subprobe` and the nested arguments as a
  single-quoted `probe_args.subprobe-arg` command-line string; MCP and
  control-plane clients can set the same fields directly.
  Global options are preflight-validated; module argument names and values are
  passed to the worker, so a bad module value fails the job with the worker
  argument error in `stderr_tail`/the log.
- **Live** polls `job.status` at a configurable interval and leads with a large
  status headline (`Scanning`, `Scan complete`, `Scan failed`, and so on) plus
  sent/targets, throughput, elapsed time, exit code, result/log path and a
  cleaned worker-log tail. There is no progress bar. **Open log** and **Open
  result** hand the server-resolved job files to the operating system's default
  application (with a text-editor fallback on Windows when `.log`/`.ndjson` has
  no file association). Cancelling asks for confirmation.
- **Results** lists jobs from `job.list`; opening one moves to Live with that job
  selected. **Load records** reads the job's result file through
  `GET /api/results?job_id=...&offset=...&limit=...` (50 records per page) and
  **Load more** pages through it; records already written by a running job can be
  read too. Only valid NDJSON records are returned;
  malformed or partial lines are skipped.
- **Interfaces** lists capture adapters with IPv4/IPv6, MAC, gateway, default
  flag, link type and raw-IP capability. **Modules** groups scan modules, probe
  modules, output modules and generate modules, with search and type tabs.
  Clicking a module expands its full description and parameter table, including
  descriptions and aliases. **System** has real appearance controls
  (Paper/Graphite theme, density, live refresh), runtime counts, capabilities
  and the local security model.
- **Language** switches the console between English and Chinese from the top
  bar. Module and global-option descriptions come from the same translated help
  catalog as the CLI, so they stay consistent with `--help` and the manuals.
  The choice is stored in the browser and can be forced with `?lang=en` or
  `?lang=zh`.

The output path is managed by the server. For include files, chunking or quota
settings, use the MCP server or the JSON control API directly. Scan and probe
arguments are editable in the Method panel.

## Security model

- **Loopback by default.** The listener binds `127.0.0.1`; `--gui-listen`
  requires an explicit `host:port` and accepts `127.0.0.1` or `localhost`. A
  non-loopback bind (`0.0.0.0`) is rejected unless `XTATE_GUI_ALLOW_REMOTE` is
  set to `1`, `true` or `yes`; that is an explicit opt-in for containers and
  reverse proxies and removes the loopback protection, so keep the token and
  publish the port deliberately (see [docker-build.md](docker-build.md)). There
  is no TLS because the default deployment has no network path.
- **Session token.** A random 128-bit token is generated at startup. The page
  sends it in `X-Xtate-GUI-Token`; the server compares it in constant time.
- **Host validation.** Requests with a non-loopback `Host` header are rejected,
  which prevents DNS-rebinding pages from reaching the API.
- **Method allowlist.** Only `job.list`, `job.status`, `job.cancel`,
  `job.result_manifest` and `job.start` are forwarded through `/api/rpc`.
  `/api/info`, `/api/system`, `/api/interfaces`, `/api/modules`, `/api/options`,
  `/api/preflight`, `/api/results` and `/api/open` are server-side handlers;
  they cannot call arbitrary control methods. `/api/info` returns only the
  attached control endpoint and the GUI version. `/api/results` accepts only
  `job-<digits>` and
  reads the result path reported by that job's manifest, never an arbitrary
  client path. `/api/open` accepts only `job_id` plus `kind` (`log`, `result`
  or `manifest`); the server resolves the path from the job status/manifest and
  never opens a client-supplied path.
- **No browser hand-off, no shell.** The GUI never launches or controls a
  browser: it prints the URL and exits only when you press Ctrl-C. Open-log and
  open-result use direct process creation on Windows (Notepad) and `xdg-open`
  on Unix; no shell, DDE or explorer.exe hand-off is involved.
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
| Open log/result feels slow on Windows | Current builds start Notepad directly with the resolved path and do not wait for DDE/Explorer. If an old build still shows delay, close any modal dialog and retry; the server never opens a browser. |

## Tests

```bash
python tests/gui/test_gui.py
```

The test starts a real control plane and GUI bridge with a workspace
`XTATE_STATE_DIR`, checks the page, language switch markers, token,
system/interfaces/modules/options/preflight and results endpoints, verifies
English and Chinese module/option payloads, rejects a non-loopback Host and a
missing token, rejects invalid `/api/open` requests without launching an
application, validates `global_args` in preflight, checks the per-run result
folder, and starts a dry-run job and polls it to a terminal state. It does not
require a browser.

## Related

- [3.0 manual](manual/README.md)
- [Control plane](control-plane.md)
- [Job model](job-model.md)
- [TUI dashboard](tui.md) (deprecated in 3.0)
- [MCP server](mcp-server.md)
