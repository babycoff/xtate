# 02 · GUI console

The 3.0 console is a local web page served by the Xtate binary. It is a client
of the local control plane, exactly like the TUI and the MCP server: scans run
in the daemon, not in the browser, and the console lists and controls the jobs
that daemon owns.

The page is available only on loopback. It is not a remote dashboard, it does
not listen on a network interface, and it has no user accounts. Authorization
to scan is a separate, explicit step.

## Starting the console

### Private control plane (one command)

```bash
sudo ./bin/xtate --gui
```

Without `--control-connect`, the binary starts a private control plane for the
console, serves the page, and stops both when the process exits. Jobs started in
this mode are children of the console process and do not survive it.

The process prints:

```text
Xtate GUI listening on http://127.0.0.1:8787/
Control endpoint: <endpoint>
GUI session token: <32 hex characters>
This server is loopback-only. Press Ctrl-C to stop.
```

The browser is opened automatically unless `--gui-no-open` is used.

The same command works on Windows from an elevated shell:

```powershell
.\bin\xtate.exe --gui
```

### Attached control plane (daemon outlives the console)

Start a daemon first, then attach the console to its endpoint:

```bash
sudo xtate --control-plane=/tmp/xtate-ctl.sock
xtate --control-connect=/tmp/xtate-ctl.sock --gui
```

In this mode the console is only a client. Closing it leaves the daemon and its
jobs running, and another console, the TUI or MCP can attach to the same
endpoint. On Windows the endpoint is a named pipe such as
`\\.\pipe\xtate-control`.

### Options

| Option | Effect |
|:---|:---|
| `--gui` | Serve the console (starts a private control plane unless `--control-connect` is given) |
| `--gui-listen=<addr>` | Bind address; only `127.0.0.1` or `localhost`, optionally with a port. Default `127.0.0.1:8787`; `:0` asks the OS for a free port |
| `--gui-no-open` | Do not launch a browser |
| `--control-connect=<endpoint>` | Attach to an existing daemon instead of starting a private one |

## Page tour

The left navigation has six entries: **New scan**, **Live scan**, **Results**,
**Interfaces**, **Modules** and **System**. The top bar shows the connection
state to the control plane; the footer shows the console version and the
endpoint currently in use.

### New scan

The page is a four-step form plus a preflight panel.

**01 Scope.** Target textarea. Targets are the same syntax as the CLI and the
scan-request schema: single addresses, CIDR blocks, ranges and comma lists.
Parsed targets appear as chips with a count. **Use sample** fills
`198.18.0.0/24, 203.0.113.10-40`, a documentation range — it is not a
suggestion to scan the internet.

**02 Method.** Scan cards come from the running daemon's module catalog, so the
cards always match `--list-scan` for that build. Ports default to `80,443` and
accept comma lists and numeric ranges (`20-25`). The console sends plain port
numbers, so CLI protocol prefixes such as `U:`/`S:` are not available here; use
the CLI or a control-plane request for UDP/SCTP-specific port sets. The probe
selector appears only for scan engines that take a probe, and it is filtered by
the engine's probe type:

| Scan engine | Probe type | Example probe |
|:---|:---|:---|
| `zbanner` | TCP | `http`, `echo`, `ssh` |
| `tcp-state` | state | `tls-state`, `http-state`, `smtp-state` |
| `udp` | UDP | `dns`, `snmp`, `ntp` |
| `quic-state` (optional, Linux) | state | `http3-state` (optional) |
| `tcp-syn`, `sctp-init`, `yarrp-udp` | none | — |

Rate is in packets per second (1–10000, default 1000). Timeout is the total
wall-clock limit in seconds (1–86400, default 300). Output is fixed to NDJSON
with a result manifest; the console does not choose output modules.

**Module parameters.** Below the method cards, *Module parameters* lists the
flags and text arguments exposed by the selected scan engine and probe. Flags
are checkboxes and value arguments are text fields; empty fields are omitted.
Values are sent as `scan_args` and `probe_args` with `job.start`, the same names
the CLI uses for `--scan-arg` and `--probe-arg`. The list is rebuilt when the
scan or probe changes. Preflight does not validate parameter names or values;
if the worker rejects one, the job fails and its `stderr_tail`/log shows the
argument error.

**03 Interface.** *Auto (from route)* lets preflight resolve the route for the
sampled targets. A TUN/VPN adapter appears as a RAW link type and has no MAC, so
banner and stateful scans may not work through it; pick the physical adapter
instead. When preflight cannot decide between routes it asks you to select an
interface explicitly.

**04 Authorization.** The checkbox states *I own the targets or have written
permission. The exact scope, rate, interface and time window above are what will
be sent.* It is required for Start and it is checked again by the server. It is
not a legal substitute for permission.

**Preflight panel.** Preflight is a server-side, read-only check. It does not
send packets. It reports:

- status (idle, pending, passed or blocked), attempt count and a summary;
- target, port, interface, source address, gateway and link type;
- a list of checks, and any warnings or errors.

Preflight fails closed when, for example, the scan module is unknown, the probe
does not match the engine, the ports do not match the engine's protocol, a
target cannot be parsed, rate/timeout are out of range, or the targets resolve
through more than one interface without an explicit choice. ICMP-style scans
(`icmp-echo`) need no ports and report zero ports.

Any change to a scanned field invalidates the previous result; the page waits
about 320 ms after the last change and runs preflight again. **Start scan**
stays disabled until preflight passes and the authorization box is ticked. The
hint under the button explains the current blocker.

Start submits a `job.start` request to the local control plane with the scan,
targets, ports, probe, rate, timeout, optional interface and
`authorized: true`. On success the page switches to Live scan for the returned
job id.

### Live scan

The page leads with a large status headline — `Scanning`, `Scan complete`,
`Scan failed`, `Scan cancelled`, `Scan timed out` or `Scan stalled` — and a
one-line explanation. There is no progress bar; the counters and terminal state
are the authoritative status. The page polls `job.status` every 1.5 seconds by
default and stops polling in a terminal state.

Fields and panels:

- sent/targets, throughput, elapsed time, phase, heartbeat age and exit code;
- result manifest: result path, manifest path, size and completeness;
- a cleaned tail of the worker log (terminal escape fragments are removed but
  `[HIN]`, `[ERR]` and similar log prefixes are preserved);
- **Open log** and **Open result** buttons that ask the server to open the
  job's resolved log or result file with the operating system's default
  application (Windows falls back to the text editor when the extension has no
  association);
- a bounded result-record browser for the completed job (50 records per page);
- result, log and error fields when the daemon reports them.

**Cancel** sends `job.cancel` immediately and reports the outcome in a toast. It
is disabled in terminal states. Leaving the page does not stop the scan; the
daemon continues and the job stays visible on Results.

Result files are written to the visible `xtate-state` folder beside `xtate.exe`
on Windows (easy to find and delete), or to the managed state directory:
`$XDG_STATE_HOME/xtate/results`/`$HOME/.local/state/xtate/results` on Linux.
Set `XTATE_STATE_DIR` to override it. Request files are removed when the job
ends. If the portable directory cannot be created, the Windows build falls
back to `%LOCALAPPDATA%\xtate`, then `%TEMP%\xtate-state`, then
`xtate-state` in the current directory.

### Results

Lists jobs from `job.list` (up to 100) in a table: scan id, state,
result path and a link back to Live scan. Selecting a row reopens its Live scan
page. The empty state is *No scans yet.*

In Live scan, **Load records** reads the completed result file through
`GET /api/results?job_id=...&offset=...&limit=...` and shows 50 JSON records at
a time. **Load more** advances the offset. The endpoint accepts only
`job-<digits>`, resolves the path from the job manifest, and returns malformed
or partial NDJSON lines as skipped rather than rendering them.

### Interfaces

Shows adapters reported by the server: index, name, description, IPv4 and IPv6
addresses, MAC, gateway, default flag, state and link type. Loopback and virtual
interfaces are listed but are not probed. `state` is `loopback`, `virtual`, `up`
or `no-ipv4`; `raw_capable` says whether the link type supports raw scans. The
same data drives the CLI's `--list-if`.

### Modules

Shows the module catalog of the running daemon grouped by role — **Scan
engines**, **Protocol probes**, **Output writers** and **Target generators** —
with a count for each group. Each card shows the module name, its short
description and the number/first few parameter names. The search box and the
type tabs narrow the list. The catalog is the same one behind
`--list-modules-json` and the per-module help, so the console cannot claim a
module that the binary does not have.

### System

**System & preferences** is a real preferences page, not a read-only status
dump. Appearance offers a warm **Paper** theme or a **Graphite** dark theme,
comfortable or compact density, and a 1.5 s/3 s live-refresh interval; the
choice is saved in this browser's local storage. Runtime shows version,
platform, endpoint and module counts. Capabilities shows raw sockets, HTTP/3,
QUIC transport and zstd result capability. Security model restates loopback,
Host validation, session token, control-token handling and the allowlist.

## Security model

The console is designed for a single local user:

- **Loopback only.** `--gui-listen` rejects anything that is not `127.0.0.1` or
  `localhost`. The server also rejects requests whose `Host` header is not
  loopback, which blocks DNS-rebinding attacks.
- **Per-session token.** A 128-bit random token is generated at startup, printed
  once, and embedded in the page. Every `/api/*` request must send it as
  `X-Xtate-GUI-Token`; comparison is constant-time. The token is never accepted
  from a request body.
- **Private-mode control token.** If the GUI starts its own control plane and
  `XTATE_CONTROL_TOKEN` is not already set, it generates an ephemeral 128-bit
  token for that child, so another local account cannot connect to the pipe or
  socket. It is removed when the GUI exits and is not printed.
- **Method allowlist.** The browser bridge forwards only `job.list`,
  `job.status`, `job.cancel`, `job.result_manifest` and `job.start`.
  `/api/results` is a separate read-only handler that accepts only a job id and
  pages through that job's manifest result file; neither path can call arbitrary
  control methods. `/api/open` accepts only a job id and `kind`
  (`log`/`result`/`manifest`), resolves the path from the job status/manifest,
  and never opens a client-supplied path.
- **Server-side authorization.** `job.start` is refused unless the request
  carries `params.authorized: true`. The browser checkboxes are convenience,
  not the enforcement point.
- **No shell, no arbitrary paths.** The GUI server does not execute commands and
  does not read arbitrary files. Results are read from the daemon's manifest,
  and the pages render server data.
- **Bounded requests.** Headers are capped at 128 KiB, bodies at 64 KiB and
  bridge replies use a 64 KiB buffer; the server-built module catalog may be
  larger because it is generated directly. Sockets time out after 8 seconds.
  The page sets a strict Content-Security-Policy, `X-Frame-Options: DENY` and
  `no-store`.
- **No TLS.** Traffic never leaves the host; plain HTTP on loopback is the
  design. Do not expose the port through a proxy or tunnel.

The console is not a security boundary for scanning itself: rate limits, target
limits, route preflight and result-path rules are enforced by the daemon and the
job worker, and MCP applies its own restrictions (see
[MCP server](../mcp-server.md)).

## What the console does not do

The console covers the common scan workflow, not every CLI feature. These are
deliberately left to the CLI, the control plane or MCP:

- target files (`include_file`) and arbitrary scan/probe argument combinations
  beyond the parameters exposed in the Method panel;
- output-module selection, result chunking and per-job quotas;
- scheduling, recurring scans or scan profiles;
- remote access, multiple users or authentication beyond the session token;
- stateful-scan firewall setup — on Linux you must install the rules yourself,
  see [01 · Install and quick start](./01-install-and-quickstart.md).

For these, use [03 · CLI and jobs](./03-cli-and-jobs.md) or the
[control plane](../control-plane.md) directly.

## Troubleshooting

| Symptom | Likely cause and fix |
|:---|:---|
| `cannot start a private control plane for --gui` | The private daemon could not be created. Check for an existing endpoint conflict, or attach with `--control-connect` |
| `cannot bind GUI listener` | Port already in use. Pick another port: `--gui-listen=127.0.0.1:0` or `:8790` |
| `control plane unavailable` (502) | The attached daemon went away. Restart it or attach a new one |
| `GUI_TOKEN_REQUIRED` (403) | The page was loaded without the token, for example from a saved URL or a different browser profile. Reload from the URL printed at startup |
| `AUTHORIZATION_REQUIRED` (403) | The job start did not include `params.authorized: true` |
| `multiple default interfaces detected` | Routes are ambiguous. Choose an interface explicitly, or use `--explain-target` / `--list-if` first |
| Start stays disabled | Preflight is blocked or still running, a field changed after the last preflight, or authorization is not confirmed |

The GUI test suite is `python tests/gui/test_gui.py`; it covers the page/token
handshake, the API endpoints, preflight accept/reject cases, the authorization
gate, Host checking, private-mode startup and a dry-run managed job.

## Related documentation

- [03 · CLI and jobs](./03-cli-and-jobs.md)
- [GUI reference (job dashboard)](../gui.md)
- [Control plane](../control-plane.md) and [job model](../job-model.md)
- [MCP server](../mcp-server.md) and [Agent Skill](../agent-skill.md)
- [TUI](../tui.md) (2.44.x interface, deprecated in 3.0)
- [Troubleshooting](../troubleshooting.md)
