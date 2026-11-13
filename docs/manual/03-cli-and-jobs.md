# 03 · CLI and jobs

The CLI is the reference interface: the GUI, the TUI and MCP all drive the same
scan engine and the same job manager. This chapter covers scan commands,
output, the local control plane and managed jobs.

In the examples below `xtate` means `./bin/xtate` on Linux/macOS and
`.\bin\xtate.exe` on Windows. Raw-socket scans need `sudo` or an elevated shell.

## Command-line basics

A scan command combines a target set, a port set, a scan engine, an optional
probe and a rate:

```bash
xtate -ip <targets> -p <ports> -scan <engine> [-probe <probe>] -rate <pps>
```

| Option | Meaning |
|:---|:---|
| `-ip`, `--target-ip` | Targets: single IP, CIDR, explicit range, or a comma list |
| `-p`, `--port` | Ports or ranges; `U:` prefix for UDP, `S:` for SCTP, `O:` for non-port slots |
| `-scan`, `--scan-module` | Scan engine, for example `tcp-syn`, `zbanner`, `udp`, `tcp-state` |
| `-probe`, `--probe-module` | Probe for engines that take one, for example `http`, `dns`, `tls-state` |
| `-rate` | Total packets per second across transmit threads |
| `-if`, `--adapter` | Pin the network interface by index or unique description |
| `-show`, `--show-output` | Extra result levels: `failed`, `info`, `all` |
| `-scan-arg`, `-probe-arg` | Quoted module-specific arguments |
| `-output-module`, `-o` | Output module and output file |
| `--wait` | Seconds to keep receiving after transmission ends (default 10) |
| `--no-status` | Disable the live status bar on stderr |

Built-in help:

```bash
xtate --usage                 # one-screen synopsis with examples
xtate --help                  # every global parameter
xtate --intro                 # workflow overview
xtate --list-scan             # scan engines
xtate --list-probe            # probes and their types
xtate --list-out              # output modules
xtate --list-gen              # target generators
xtate --list-modules-json     # machine-readable catalog
xtate --help-scan zbanner     # per-module parameters
xtate --help-probe http
```

Module names, parameter names and result values stay in English. Human-facing
help can be switched to Chinese with `--lang zh` or `XTATE_LANG=zh`.

## Targets and ports

Targets accept `192.168.1.10`, `10.0.0.0/8`, `10.0.0.1-10.0.0.100`, `2001:db8::/64`
and comma lists. `--exclude` removes ranges from the set; excludes win over
includes. Target files and generators are covered in
[Targets and ports](../targets-and-ports.md).

Ports accept `80`, `20-25`, `80,20-25`, `U:161`, `U:1024-1100` and
`S:36412`. For port-scoped engines (`tcp-syn`, `zbanner`, `tcp-state`, `udp`,
`sctp-init`, `yarrp-udp`) always pass `-p`: without it Xtate warns and
substitutes a fake `o:0` endpoint. Most engines ignore it; YARRP topology scans
use the port field as a TTL, so `o:0` does build a TTL-0 packet — pass a real
TTL for those scans.

## Scan and probe pairings

| Engine | Probe | Typical use |
|:---|:---|:---|
| `tcp-syn` | none | Fast stateless port discovery |
| `zbanner` | TCP probe (`http`, `echo`, `ssh`, `ftp`, …) | Banner and protocol greeting |
| `tcp-state` | state probe (`tls-state`, `http-state`, `smtp-state`, …) | Complete handshake, then probe |
| `udp` | UDP probe (`dns`, `snmp`, `ntp`, `echo`, …) | Stateless UDP request/reply |
| `icmp-echo` | none | Host discovery, no ports |
| `arp-req`, `ndp-ns` | none | Local LAN discovery (`-lan` for ARP) |
| `yarrp-echo`, `yarrp-udp` | none / UDP | TTL-limited measurement |
| `quic-state` | `http3-state` | Optional, Linux with ngtcp2 only |

Picking a probe whose type does not match the engine is a validation error; the
GUI preflight and the job worker both reject it.

## Example scans

### Stateless SYN scan

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

Results stream to stdout, one line per reply:

```text
[+] host: 192.168.1.10 port: 80 in tcp is "open" because "syn-ack"
```

Only `success` results are shown by default; closed ports are `failed`:

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn \
  -rate 1000 -show failed
```

The status bar is drawn on stderr. Redirecting stdout to a file therefore keeps
the file clean, and `--no-status` removes the bar entirely.

### UDP probe

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p U:53 -scan udp -probe dns \
  -rate 500 -show info
```

### Host discovery without ports

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -scan icmp-echo -rate 500
```

### Banner grab and stateful probes (Linux)

Stateful engines need outgoing RSTs suppressed for the duration of the scan.
These rules are host-wide; remove them immediately afterwards:

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe http \
  -scan-arg "-banner" -rate 1000 -show info
sudo ./bin/xtate -ip 192.168.1.0/24 -p 443 -scan tcp-state -probe tls-state \
  -rate 200 -show info
./firewall/rm_rules.sh
```

`-scan-arg` and `-probe-arg` receive the module's own options as one quoted
string, for example `-scan-arg "-banner -ttl"`. The per-module help
(`--help-scan`, `--help-probe`) lists them. On Windows there is no bundled
firewall script; read the Windows notes in
[Getting started](../getting-started.md) before running stateful scans.

### Interfaces and routes

```bash
./bin/xtate --list-if
./bin/xtate --explain-target 192.168.1.0/24
./bin/xtate --check --explain-target 192.168.1.0/24
sudo ./bin/xtate -ip 192.168.1.0/24 -p 443 -scan tcp-syn -if 3
```

`--explain-target` is read-only, groups targets by interface/source/gateway and
warns when a set spans multiple routes. `--check` adds the preflight check and
exits non-zero on failure. If `-if` is omitted and routes are ambiguous, Xtate
fails closed rather than guessing.

## Output

By default results are text lines on stdout, with a live status bar on stderr.
To write structured output, select an output module:

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan tcp-syn \
  -output-module ndjson -o results.ndjson
```

`-o` is the output file for the selected module; `--output-screen` also prints
results while a module writes the file. `bson`, `csv`, `list` and `mongodb` are
the other output modules; their options come from `--help-out <module>`.
Post-processing (JARM aggregation, event aggregation, BSON parsing) is covered
in [Output](../output.md) and [Aggregation](../aggregation.md).

Stopping: `Ctrl-C` stops transmission and drains replies for `--wait` seconds
(default 10). A second `Ctrl-C` aborts. Exit status is zero on a normal scan and
non-zero for startup/validation failures, `--selftest` failures and failed
`--check` preflights.

## Managed jobs

A long scan should be a job: a child process owned by a local daemon, with
timeouts, cancellation and result files. The same job manager backs MCP, the
TUI and the GUI.

### Run one job and wait

```bash
./bin/xtate --job-run=request.json --job-result=out.ndjson --job-timeout=30
```

`request.json` is a scan request:

```json
{
  "scan": "tcp-syn",
  "targets": ["192.168.1.0/24"],
  "ports": [80, 443],
  "rate": 1000,
  "timeout_sec": 300
}
```

The worker runs with `--show all` and writes NDJSON to the result file. The
command waits for completion and prints a single JSON line:

```json
{"job":{"id":"job-1","state":"completed","exit_code":0,"result":"out.ndjson"}}
```

Only `--job-run` workers write a heartbeat file (`<result>.heartbeat`). A normal
CLI scan does not create one and does not change its behavior.
`--job-heartbeat-timeout` (default 30 s) fails a job whose worker stops
updating its heartbeat; `--job-stall-timeout` fails a job that makes no output
progress while the heartbeat is still alive.

### The local control plane

The daemon speaks one JSON object per line over a local endpoint: a Unix socket
on Linux, a named pipe on Windows. It never listens on TCP and never runs a
shell.

Start a server:

```bash
xtate --control-plane=/tmp/xtate-ctl.sock
```

Send a request from another process (or another terminal):

```bash
xtate --control-connect=/tmp/xtate-ctl.sock \
  --control-request='{"id":1,"method":"ping"}'
```

If `XTATE_CONTROL_TOKEN` is set for the server, every request must carry the
same `"token"` field; missing or wrong tokens return `UNAUTHORIZED`. Without a
token, any local process that can reach the endpoint is accepted, so set one on
shared machines.

Methods:

| Method | Parameters | Result |
|:---|:---|:---|
| `ping` | none | `{"pong":true}` |
| `job.start` | `params` scan request, or `request_path` | `{"job_id":"…"}` |
| `job.list` | `offset`, `limit` (default 100, max 1000) | `jobs`, `total`, `next_offset`, `truncated` |
| `job.status` | `job_id` | state, counters, paths, stderr tail |
| `job.result_manifest` | `job_id` | result path, manifest path, bytes, complete |
| `job.results` | `job_id` | manifest metadata; `offset`/`limit` are reserved and ignored |
| `job.cancel` | `job_id` | `cancelled` boolean |

Start a job:

```bash
xtate --control-connect=/tmp/xtate-ctl.sock --control-request='{
  "id":2,"method":"job.start",
  "params":{"scan":"tcp-syn","targets":["192.168.1.0/24"],
            "ports":[80,443],"rate":1000,"timeout_sec":300}
}'
```

`job.start` also accepts top-level `result_path`, `timeout_sec`, `chunk_size`,
`compression`, `index`, `quota_bytes` and `interface`. The request is validated
by the worker, so an invalid request fails asynchronously and shows up in
`job.status`.

Poll and cancel:

```bash
xtate --control-connect=/tmp/xtate-ctl.sock \
  --control-request='{"id":3,"method":"job.status","job_id":"job-1"}'
xtate --control-connect=/tmp/xtate-ctl.sock \
  --control-request='{"id":4,"method":"job.cancel","job_id":"job-1"}'
```

States are `queued`, `running`, `completed`, `failed`, `cancelled`,
`timed_out` and `stalled`. There is no `job.events` method and no server push:
clients poll. There is no persistence; a daemon restart terminates its jobs.

### Result files and chunks

A job owns its result path; control responses never carry result bytes. For
large results, ask for chunked, optionally compressed output in the job start
request:

```json
{
  "id": 2,
  "method": "job.start",
  "params": {"scan": "tcp-syn", "targets": ["192.168.1.0/24"],
             "ports": [80, 443], "rate": 1000, "timeout_sec": 300},
  "chunk_size": 67108864,
  "index": true,
  "compression": "none"
}
```

Completed results become `<result>.<id>.ndjson` chunks plus
`<result>.manifest.json` and an optional index; `job.result_manifest` returns
the manifest path. Compression is `none` by default; `--result-compress=zstd`
works when the build includes zstd (otherwise it falls back to uncompressed).
`--result-quota` is enforced while the scan runs; when the result file reaches the quota, the scan stops and the job reports a quota error; it does
not stop a running scan. Completed-job retention and pruning are enforced by
the job manager.

### Attach other clients

Any client can attach to a running daemon. For the console:

```bash
xtate --control-connect=/tmp/xtate-ctl.sock --gui
```

The TUI uses the same endpoint model (`--tui`; see [TUI](../tui.md)). MCP is the
automation interface and exposes the same job lifecycle as tools; see
[MCP server](../mcp-server.md) and [Agent Skill](../agent-skill.md). Because
all clients share one daemon, a job started by the GUI can be cancelled by a
control-plane request and listed by MCP.

## Troubleshooting

| Symptom | Likely cause and fix |
|:---|:---|
| `no ports` warning and no packets | Port-scoped engine without `-p`. Pass ports, or use `icmp-echo` |
| `open` but no banner or TLS evidence | Kernel RST; install Linux firewall rules for stateful scans |
| Ambiguous-interface error | Multiple default routes. Use `--list-if` / `--explain-target`, then `-if` |
| `JOB_NOT_FOUND` | Wrong job id, or the daemon restarted (jobs are not persisted) |
| `JOB_LIMIT_REACHED` | The manager's job limit is full; wait for jobs to finish or prune completed ones |
| `SCAN_TIMEOUT` / `SCAN_STALLED` | The job exceeded its total timeout or stopped making progress |
| `UNAUTHORIZED` on the control plane | Set the same `XTATE_CONTROL_TOKEN` for client and server, or add its value as `"token"` |
| `AUTHORIZATION_REQUIRED` | `job.start` from MCP or the GUI needs `authorized: true` |

Exit codes are non-zero for invalid arguments, failed preflight (`--check`),
failing `--selftest` and refused job starts. The exact code is not part of the
contract; check stderr and the JSON error object instead.

## Related documentation

- [02 · GUI console](./02-gui-console.md)
- [Control plane](../control-plane.md) and [job model](../job-model.md)
- [Output](../output.md), [aggregation](../aggregation.md),
  [JSON contracts](../json-contracts.md), [error codes](../error-codes.md)
- [Scanning modes](../scanning-modes.md), [modules](../modules.md),
  [targets and ports](../targets-and-ports.md)
- [MCP server](../mcp-server.md), [TUI](../tui.md)
- [Troubleshooting](../troubleshooting.md)
