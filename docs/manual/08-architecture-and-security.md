# 08 · Architecture and security

This chapter describes how a running Xtate is put together and where the
security boundaries are. It is the map you need before changing a scanner
deployment, exposing the console to another person, or trusting an automation
client with scan control.

Two ideas organize everything else:

1. **One pipeline, implemented by module structs.** Targets become packets,
   packets become replies, replies become records. Each stage is a pluggable
   module type; nothing is loaded at runtime.
2. **A privileged local daemon with thin local clients.** The scan engine, job
   manager and control plane run in one process. GUI, TUI and MCP are clients
   of that process, not alternative scanners.

## The pipeline

A scan moves in one direction:

1. **Generate** produces the next target — a tuple of target/source IP, port
   and protocol, flattened from the target set and shuffled.
2. **Scan** builds the packet for that target and hands it to the raw socket
   layer.
3. **Probe** contributes the application-layer payload and interprets
   responses.
4. **Output** formats each result as an `OutItem` and writes it where you asked.

The four module types are registered as static structs in NULL-terminated C
arrays. A build without an optional library compiles the corresponding modules
out instead of failing at runtime; that is why a module can be missing from
`--list-*` while the binary still starts. There is no plugin ABI and no dynamic
discovery.

| Type | Owns | Called from |
|:---|:---|:---|
| Generate | Target sequence and permutation state | tx threads |
| Scan | Packet construction and scan-level state machine | tx (`transmit`), rx (`validate`), handle (`handle`, `poll`) |
| Probe | Payload bytes, response parsing, optional per-connection session | tx or handle (`make_payload`), rx (`get_payload_length`), handle (`handle_response`, state callbacks) |
| Output | Result formatting and delivery | handle threads, serialised by one lock |

A scan module sees each reply up to three times: in `validate` (is this packet
mine, should it be deduplicated), in `handle` (run the state machine, emit
results), and in `poll` (service timeouts every loop). A probe is either
stateless (payload in, bytes out) or stateful (a session with
`conn_init`/`make_hello`/`parse_response`/`conn_close`, always called on the
handler thread that owns the connection).

## Threads and ownership

A running scan uses **N + M + 3** threads: one main, N transmitters, one
receiver, one dispatcher and M handlers. The defaults
(`--tx-thread-count 1`, `--rx-handler-count 1`) give five threads.

| Thread | Count | Responsibility |
|:---|:---:|:---|
| main | 1 | Control plane: parse config, initialise modules, poll status, handle signals, drain and shut down. Not on the packet path. |
| tx | N | Pull targets, build packets, send them, flush follow-up packets queued by handlers |
| rx | 1 | Receive, preprocess and validate every reply; optional pcap; optional deduplication; dispatch |
| dispatch | 1 | Hash the source IP and enqueue the packet onto one of the M handler queues |
| handle | M | Run the scan/probe state machine, format results, queue follow-up packets |

The split follows the workload: the transmit side is rate-shaped and CPU-bound
on packet construction, the receive side is I/O-bound and must not be delayed
by per-connection work, and the handlers are where the expensive per-target
logic runs. Handlers are the pool to scale when a stateful scan needs more CPU.

**Dispatch affinity.** The dispatcher computes `hash(src_ip) & (M - 1)` and
enqueues onto `handle_q[0..M-1]`. Because the hash uses only the source IP,
every packet from a given host lands on the same handler thread in arrival
order. That is what makes stateful scanning possible without locks: a handler
owns its connections exclusively, so a TCB only ever has one writer. `M` must
be a power of two and at most 256; larger values are rejected at startup
because the hash is only 8 bits wide.

**Per-handler connection tables.** A stateful scan such as `tcp-state`
allocates one user-space TCP connection table per handler, not one global
table. The affinity rule means the fast path needs no mutex. The price is that
connection state is bound to a thread: resizing `M` changes the distribution of
connections.

**NetStack queues.** Handlers do not send directly. Follow-up packets (ACKs,
RSTs, next probes) are written into a shared ring, `transmit_queue`, and a tx
thread flushes that ring at the top of its loop before generating new targets.
A matching pool of fixed-size 2048-byte packet buffers is shared the same way.
This is the mechanism that lets a stateless receive path drive a real TCP
conversation: the receiver stays pure, and stateful decisions are expressed as
packets queued for transmission. Dispatch and handler rings are sized at
startup (16384 slots by default, power of two). When a ring is full the
producer sleeps and retries — backpressure instead of silent loss.

CPU affinity is assigned in a fixed order — tx threads, then rx, then handlers
— and disabled with `--no-cpu-bind`.

## Packet construction, targets and results

Packets are not built from scratch per target. At startup the template layer
pre-bakes a small set of templates (SYN, generic TCP with data, RST, and the
UDP/ICMP/ARP/NDP/SCTP equivalents). Per-target transmission patches addresses,
ports, sequence numbers and the IP ID into a copy, then recomputes the
transport and IP checksums. Template assumptions explain the tuning knobs: the
SYN template advertises MSS 1460 and a 64240-byte window, the non-SYN TCP
template carries no options and a 1024-byte window, and the RST template
advertises a zero window.

The target set is flattened into one index space of `ip × port` and walked in
a permuted order. The default generator is **BlackRock**, a stateless DES-like
permutation: given a seed and an index it computes the shuffled index without
storing the list, so memory stays flat at Internet scale. The space is limited
to 63 bits, and a request for more than a billion addresses without an explicit
`--exclude` is refused as a guard against accidentally scanning the whole
Internet. `--shard` and `--resume-index` split one logical scan across
processes and restart points on top of the same permutation.

Source addresses and ports can be randomised inside their ranges. The source
port range matters: ZBanner and HLTCP encode the probe slot in the source port
(`first + index`), which is how a reply is matched to the probe that produced
it. `--source-port` must therefore be at least as wide as the probe's slot
count, or slot replies are filtered out.

Every result is an `OutItem`: a target tuple, a level (`info`, `failure` or
`success`), a classification and reason string, plus three typed key-value
chains — scan fields, probe fields, output fields. The output module is chosen
once and receives results from whichever handler produced them; a single mutex
serialises that call. A slow sink (a synchronous database insert, for example)
therefore slows handling — a deliberate simplicity trade-off and the reason
throughput-sensitive runs should prefer local formats.

## Two engines, one pipeline

| | ZBanner | HLTCP |
|:---|:---|:---|
| State | none per target | a TCB after the SYN-ACK |
| Sends | SYN, then an ACK carrying the probe | a full TCP conversation |
| Returns | open/closed and first banner(s) | TLS handshakes, certificates, HTTP inside TLS |
| Module | `-scan zbanner` | `-scan tcp-state` |

Both rely on the same invariants: follow-up packets travel through the NetStack
queue rather than being sent inline, and the host kernel must be prevented from
resetting connections it does not know about. See chapter 05 and the deep
documents [ZBanner](../zbanner.md) and [HLTCP](../hltcp.md).

The design deliberately gives up some things: one receiver thread (which caps
receive-side throughput), no output queue, thread-affine connection state, and
compile-time static modules. Each buys simplicity in the other column; they are
not bugs.

## The daemon and the control plane

The same executable can run as a scan command, or as a daemon hosting a local
control plane. The control plane is a **local JSON-lines contract** shared by
MCP, the TUI and the GUI:

- One JSON object per line; one response per request.
- The server never runs a shell.
- It is **not a network listener**.

Transport is a Unix domain socket on Linux and a Named Pipe on Windows (for
example `\\.\pipe\xtate-control`). There is no implicit endpoint: the server
uses exactly the `--control-plane` path and the client exactly
`--control-connect`:

```bash
# terminal 1: daemon
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --control-plane=/tmp/xtate-ctl.sock

# terminal 2: one-shot client
xtate --control-connect=/tmp/xtate-ctl.sock \
      --control-request='{"id":1,"method":"ping"}'
```

Control methods are deliberately small:

| Method | Purpose |
|:---|:---|
| `ping` | Liveness (`{"pong":true}`) |
| `job.start` | Validate and start a scan job; returns a `job_id` |
| `job.list` | Paginated job list (offset/limit, limit default 100, max 1000) |
| `job.status` | State, counters, exit code, result/log paths, stderr tail |
| `job.result_manifest` | Result path, manifest path, size, completeness |
| `job.results` | Manifest metadata for a completed job (currently reserved/ignored paging) |
| `job.cancel` | Request cancellation; returns whether it was cancelled |

A job moves through `queued`, `running`, `completed`, `failed`, `cancelled`,
`timed_out` or `stalled`. Errors use stable codes from
`schemas/error-codes.json` and the shape
`{"id":1,"error":{"code":"JOB_NOT_FOUND","message":"...","retryable":false}}`.
`job.start` also accepts top-level `result_path`, `timeout_sec`, `chunk_size`,
`compression`, `index`, `quota_bytes` and `interface`; the scan request is
validated asynchronously and invalid requests become visible through
`job.status`.

The **data plane is the filesystem**, not the control channel. Control
responses are bounded and never carry result bytes; a job owns its result path
and clients read the manifest and chunk files. Completed results can be split
into `<result>.<id>.ndjson` chunks plus `<result>.manifest.json` (and an
optional index) with `--result-chunk-size`/`--result-index`. Compression is
opt-in zstd (default none); a build without zstd falls back to uncompressed
chunks rather than failing the job. `quota_bytes` is enforced during the run:
when the result file reaches the quota, the scan stops and the job reports a
quota error — it is a hard mid-scan limit.

The operational consequences: one control-plane thread, serialized manager
calls; the daemon owns the workers; a daemon restart terminates its jobs (there
is no persistence or recovery); and clients poll `job.status`/`job.list`
because there is no server-push event stream.

## GUI: loopback console

The GUI is a local scan console served by the same process. The browser page,
its assets and the API are local by default: the server binds `127.0.0.1` and
`--gui-listen` must be `host:port`. Binding a non-loopback address requires the
explicit `XTATE_GUI_ALLOW_REMOTE=1` opt-in (for Docker host publishing), and
Host-header validation still rejects non-loopback names. The page is served from
the binary and exposes a small JSON API — `/api/info`, `/api/system`, `/api/interfaces`, `/api/modules`,
`/api/preflight`, `/api/results` and `/api/rpc` for the job allowlist. The GUI never shells out
and never forwards an arbitrary method to the control plane.

The security contract for the loopback API is the important part:

- **Loopback bind and Host validation** — the listener binds loopback by default
  (remote binding requires `XTATE_GUI_ALLOW_REMOTE=1`), and every request must
  carry a loopback `Host` (`127.0.0.1:PORT` or
  `localhost:PORT`); anything else is rejected, which blocks DNS-rebinding
  attacks.
- **Per-run token** — `/api/*` requests must carry `X-Xtate-GUI-Token`, a
  random token generated at startup and injected into the served page. A
  request without it gets `403 GUI_TOKEN_REQUIRED`, and the token value is
  never displayed in Settings; only its presence/absence is shown.
- **The browser cannot supply the control-plane token.** A `/api/rpc` body
  containing a `token` member is rejected with `400 TOKEN_NOT_ALLOWED`; when
  forwarding to the control plane the GUI injects the server process's own
  `XTATE_CONTROL_TOKEN`. Page JavaScript therefore cannot choose or leak an
  arbitrary control token.
- **Bounded bodies and responses** — request bodies are capped at 64 KiB
  (`413` beyond that), and forwarded control responses are capped at the same
  size.
- **No arbitrary file reads** — the browser cannot ask the server to read a
  file; result access goes through the job methods and their manifests.
- **Explicit authorization** — `job.start` requires `params.authorized=true`
  at the server; a checkbox in the page is a UI convenience, not the
  enforcement point.
- **Method allowlist** — only the documented job/read methods are accepted.

The same design rule applies to rendering: scan records, interface names and
route strings are escaped before display, because they contain data from
untrusted peers.

## MCP: typed automation client

The MCP server is a stdio process (start it with `--mcp`) that speaks the Model
Context Protocol to a local agent and acts as a typed client of the control
plane plus read-only discovery tools. It never embeds scan results, never
spawns a shell, and never accepts a command string; discovery runs the same
executable with a fixed argv.

Its tool surface is intentionally small and structured: `capabilities`,
`iface.list`, `list_modules`, `describe_probe`, `explain_target`, `check`,
`preflight`, `validate_config`, `start_scan`, `job_list`, `job_status`,
`job_result_manifest`, `job.records` and `job_cancel` — build/interface/module discovery,
route/firewall explanation, packet-free preflight, config validation, job
start/list/status/cancel, bounded `job.records` pages and result-manifest
metadata. Whole result sets are not inlined: use `job.records` for pages or
read the manifest and chunks directly when the host can access them.

MCP adds its own boundaries:

- **`authorized: true` is required** by `start_scan` — the agent must assert
  that its targets are authorized.
- **Inline targets are capped** (20000 entries) and rates capped (10000 pps);
  ports are validated; `result_path` is probed for writability before the job
  starts.
- **Large inputs use `include_file`**, and a target set spanning multiple
  routes is refused rather than silently split.
- **Resources are allowlisted** — three fixed URIs (`docs/overview`,
  `docs/firewall`, `schemas/scan-request`), resolved relative to fixed
  filenames, then `$XTATE_MCP_DOCS_DIR`, executable directories, and finally
  the working directory. Absolute paths, drive-qualified paths and `..` are
  rejected before the filesystem is touched.
- **No arbitrary filesystem reads** from a URI or tool argument; missing
  resources return `-32002 resource not found` without scanning the disk.
- **Argument and buffer limits** — an oversized inline argument is rejected,
  and the MCP argument buffer is 8 KiB.
- **Audit trail** — `start_scan` appends a record (rate plus a
  truncation-bounded config) to `xtate-mcp-audit.log` in the MCP process's
  working directory. That path is relative, so the directory must be trusted;
  it is not a tamper-proof audit store.

The Agent Skill is documentation/playbook, not an enforcement mechanism. It
tells an agent how to plan an authorized scan; validation in the MCP server and
job manager is what actually blocks unsafe requests.

## Security model and boundaries

The deployment model is a **single privileged local scanner** with local
clients. That yields a short list of boundaries and a short list of things that
are explicitly out of scope.

### What isolates the daemon

- **No network listener.** Control plane = Unix socket/Named Pipe; GUI =
  loopback HTTP; MCP = stdio. None of these is a remote service, and none
  should be exposed through a TCP proxy and described as supported.
- **Local authentication.** When `XTATE_CONTROL_TOKEN` is set, every control
  request must carry the same token, and a missing or wrong token returns
  `UNAUTHORIZED`. When it is unset, the server accepts every local client —
  acceptable on a single-user host, not acceptable where other local users or
  processes are untrusted.
- **GUI token + Host validation** block cross-site and DNS-rebinding access to
  the loopback HTTP API; the token is per run and injected into the served
  page.
- **Fail-closed validation** at startup and job start: module/probe type
  mismatch, unsupported link type, invalid targets/ports, unwritable result
  paths, missing authorization and multi-route inline target sets are rejected
  rather than "best-effort" executed.

### What the privilege buys, and costs

Raw sockets require root on Linux or Administrator plus Npcap on Windows. The
scan needs that privilege to build packets and complete handshakes; the same
privilege means the firewall rules and adapter selection affect the whole host.

The firewall rules used by stateful scans are **host-wide**: they drop all
outgoing TCP RSTs (IPv4 and IPv6) and ICMP port-unreachable during the scan.
Install them before a stateful scan, remove them immediately afterwards, and
never leave them installed on a shared or long-running host — they change
unrelated connections' behavior. On Windows there is no equivalent script:
handshake-based banner/state scans depend on the Windows stack not resetting
those connections, and raw scans additionally need Npcap.

### Non-goals

Xtate does not embed an LLM, cloud account, telemetry or a hosted scanning
service, and the GUI/MCP do not execute shells. It is also **not** a hardened
multi-tenant service: if a host is shared with untrusted users, the local
control plane and token model are your responsibility, and the audit log is a
local file rather than a security control.

## Deployment shape

A normal deployment is:

```text
                +--------------------------------------+
                | scanner host (root/Administrator)    |
                |                                      |
  GUI browser --loopback HTTP-->  xtate daemon        |
  MCP agent  --stdio-------->     + control plane      |
  TUI/CLI    --socket/pipe-->     + job manager        |
                |                 + scan engine        |
                |                                      |
                |   results <-- filesystem manifest    |
                +--------------------------------------+
```

The clients do not scan; they submit validated requests and read results. That
is why a scan started in the GUI can be listed or cancelled from MCP, and why
the job manager — not the client — owns the result files.

See also:

- [03 · CLI and jobs](./03-cli-and-jobs.md) for the command and job workflow
- [Control plane](../control-plane.md), [job model](../job-model.md),
  [JSON contracts](../json-contracts.md), [error codes](../error-codes.md)
- [MCP server](../mcp-server.md), [Agent Skill](../agent-skill.md),
  [GUI design brief](../gui-3.0-design.md)
- [Firewall setup](../firewall.md) and [known limitations](../known-limitations.md)
- [09 · Troubleshooting](./09-troubleshooting.md)
