# Roadmap

**English** · [中文](zh-CN/roadmap.md)

This page records the planned work after Xtate 2.33.0, updated for the 3.0 line.
It is not a promise of dates; it is a priority and acceptance-criteria list.
Completed work is noted so the next change does not silently regress it.

## Done in 2.33.0

- Optional `quic-state`: raw-UDP QUIC handshake with ngtcp2/GnuTLS, certificate/ALPN
  output and a state sub-probe; HTTP/3 is still a later application probe.
- Optional `http3-state`: HTTP/3 request over `quic-state`; methods/headers/body,
  Huffman QPACK strings, full static table and structured response headers;
  dynamic QPACK remains intentionally disabled and reported explicitly.

- QUIC capability probe (`quic`): valid QUIC v1 Initial, Version
  Negotiation/Retry/Initial/Handshake classification, local aioquic lab.
- Module count at the 2.33.0 release: 27 probes (59 on Windows and 60 on a full
  Linux build in the current 3.0 line).
- Salesforce JARM 1.0 comparison on a local target; fixed TLS 1.3 extension
  offset in `jarm`.
- `jarm --first-probe N` rotation and standard-slot-preserving aggregation.
- STARTTLS for SMTP/IMAP/POP3/FTP in `tls-state`, with certificate details and
  subprobes after the upgrade.
- Structured X.509 details (`--dump-cert-details`).
- Parameter parser regression suite, strict value parsing, 200-case fuzz and
  error propagation.
- Expanded English/Chinese help and documentation.
- Generic `ProbeSlotPlan` with `ProbeSlot_Always` and
  `ProbeSlot_AfterFirstReply`.
- Legacy `MultiMode`/`multi_num` semantics removed.
- TCP and UDP independent slot execution.
- Built-in `slot-test` and `slot-test-udp` runtime examples.
- JARM per-slot parts and output-side aggregation.
- Offline JARM/TCP/UDP lab.
- Module development guide for all four module types.
- Compile-checked module templates for probe/state/output/generate.

## Priority reset (current direction)

As of 3.0.0, the QUIC probe, Linux-only `quic-state`/`http3-state`
transport, the scan console GUI, the MCP surface, and the nine-chapter English
and Chinese manuals are delivered. 3.0.0 is released; what shipped is recorded
in the [Xtate 3.0 roadmap](./roadmap-3.0.md). The current priorities are:

1. **Agent evaluation suite and packaging** — exercise the MCP/Skill path with
   real agent hosts and publish reproducible packages.
2. **MCP generate/stream input** — only static `targets` and `include_file` are
   supported today.
3. **Per-job disk quota enforcement during scanning** — quota is currently
   checked after completion and reported as a warning.
4. **HTTP/3 depth** — dynamic QPACK and DoQ inside the Linux-only transport;
   keep the transport scanner and the application probe separate.
5. **Protocol coverage expansion** — use the zgrab2 matrix in
   [Protocol coverage plan](./protocol-coverage.md); Batches A–C are largely
   delivered, so continue with the remaining rows.
6. **Xtate-native YAML templates and traffic randomization research** — both
   remain opt-in, lab-only workstreams; do not copy Nuclei.

The older backlog below remains valid but is lower priority unless a concrete
measurement requirement changes it.

## Module examples (completed)

- [`examples/modules/`](../examples/modules/) has one compile-checked template
  per module type.
- `tests/module-examples/test.sh` is part of Linux CI.
- Runtime slot examples remain `slot-test` and `slot-test-udp`.

## Parameter parser coverage (completed in 2.31.0/2.33.0)

- `tests/config/test.sh` covers flags, argument forms, unknown/missing options,
  long names, bare `--`, positional tokens and nested `-probe-arg`.
- Strict bool/int/size/time parsing with checked APIs and setter error
  propagation.
- `tests/config/fuzz.py` runs 200 deterministic cases in CI.
- Interactive malformed-recovery coverage exists.

HTTP/1 probe work is intentionally frozen at the current structured response
parser/pass; no further HTTP rewrite is planned unless requirements change.

## JARM correctness

The fuzzy hash was corrected to Salesforce JARM 1.0 semantics:

- cipher → index in JARM's ordered cipher table (two hex characters);
- TLS version → one version nibble (`a`–`f`);
- ALPN + extensions → first 32 hex characters of SHA-256.

The test fixture now asserts an exact 62-character reference vector. Remaining
work:

1. JARM is compared with the vendored Salesforce implementation on the same
   local TLS target; the parser extension offset was corrected to match.
2. Add scanner-level lab assertions for a known local TLS configuration:
   complete, alert/non-TLS, and missing slots.
3. Keep `targets_with_parts` semantics explicit: zero-part targets are not
   inferable from JARM rows. Do not add scanner-side group state.
4. Keep `jarm_sha256` documented as an auxiliary raw-parts hash, not the
   standard JARM fingerprint.
5. If retry usability needs improvement, use an external target manifest; do
   not silently claim a zero-part target was scanned.

Acceptance:

- exact reference vector passes;
- official JARM and Xtate agree on a local target;
- complete/incomplete/retry fixtures pass;
- docs explain the `targets_with_parts` limitation.

## Protocol probes

Status: the JARM hash/reference work, SSH banner/KEX, cleartext `h2c` and the
`h2` state probe (TLS/ALPN h2 via HLTCP) are implemented. `h2` decodes the HPACK
static table, literal fields and Huffman string literals; dynamic-table
insertions and a full stream state machine are the remaining HPACK work.
STARTTLS now covers SMTP, IMAP, POP3, FTP and ManageSieve, and the Linux-only
QUIC/HTTP/3 transport is implemented; TLS-variant fingerprints remain. TLS
certificate/subject details exist in `tls-state`; HTTP state behavior exists in
`http-state`.

Add protocol-specific detail probes without creating scanner-side per-target
state. Each probe reuses single-slot or `ProbeSlot_Always` where it makes sense.

Planned order:

1. TLS certificate/details probe is implemented in `tls-state` via
   `--dump-cert-details` (subject, issuer, SAN, validity, key type/bits,
   signature algorithm, ALPN, version/cipher).
2. SSH banner probe is implemented (`ssh`), including coalesced KEX/host-key
   algorithm lists. Full KEX packet exchange remains future work.
3. HTTP/1 work is frozen after the structured response parser pass; no further
   HTTP rewrite is planned.
4. STARTTLS adapters for SMTP, IMAP, POP3, FTP and ManageSieve are implemented
   in `tls-state --starttls`, including certificate details after the upgrade.
5. HTTP/2 (`h2`) decodes the HPACK static table, literals and Huffman string
   literals; dynamic-table insertions and full stream management remain. The
   Linux-only HTTP/3/QUIC transport (`quic-state`/`http3-state`) is shipped;
   dynamic QPACK and DoQ remain.
6. TLS variant fingerprint research: ClientHello variants, extension order,
   GREASE, ALPN ordering.
7. QUIC was delivered as a two-layer feature: the stateless `quic` capability
   probe and the optional `quic-state` transport (Linux, ngtcp2/GnuTLS). Do not
   call a UDP datagram an HTTP/3 probe without a QUIC handshake.

Constraints:

- one connection/flow per slot; no target group in the scanner;
- bounded payloads and output fields;
- deterministic tests in `tests/lab/` where a real service is required;
- optional dependencies stay optional.

For Advanced directions feasibility, see [Advanced directions feasibility](./feasibility.md).

## HTTP probe audit/rewrite (frozen)

The first response-parser pass is implemented. Per current direction, HTTP/1
work stops here; shared request-builder extraction and cross-segment chunked
state are deferred. See [HTTP probe audit](./http-probes-audit.md).

## Scan control

- Limited target-aware probe selection based on port/banner/TLS evidence.
- Adaptive packet-rate discovery for unknown networks, with explicit
  min/max rate and reproducible feedback.
- Cross-layer fingerprints combining IP/TCP/TLS/application evidence.
- Two-stage stateless → stateful handoff.

## Templates and traffic

- Xtate-native YAML templates, inspired by Nuclei but not compatible with it.
- Scanner-traffic fingerprint randomization and research controls.

## Deferred

- UDP `ProbeSlot_AfterFirstReply`: response attribution is not precise enough
  for now; UDP uses `ProbeSlot_Always`.
- HLTCP slot work: see the planned split in
  [Module development](./module-development.md#hltcp-and-slot-plans-planned).
  Connection-local `AfterFirstReply` comes first; parallel independent
  connections later.

## Recommended next order

1. YAML template schema and read-only matcher (10A).
2. Extend HTTP/3 with dynamic QPACK and DoQ; keep the transport scanner and
   application probe separate.
3. Protocol coverage Batch A: Redis, Memcached, MQTT, Telnet, SOCKS5, NTP.
4. Traffic randomization research as an opt-in, fixed-seed lab feature (10B).
5. JARM failure modes and external retry manifest.
6. SSH deep KEX/host-key, full HTTP/2 HPACK/streams.
7. HLTCP slot planning (connection-local AfterFirstReply, then parallel flows).
8. TLS variant fingerprints.
9. External two-pass target selection and opt-in adaptive rate.
10. HLTCP stateless -> stateful handoff.

## ZBanner audit and simplification

ZBanner is the largest and most complex stateless path. The audit and
acceptance criteria are in [ZBanner audit](./zbanner-audit.md). Priority:
after the current protocol work, before new ZBanner features.

- [x] one-shot guard for `AfterFirstReply`;
- [x] consolidate all-banner limit/floor/RST/truncated policy;
- [x] clarify `banner idx` versus `banner seqno` in output/docs;
- [x] narrow generic `AfterFirstReply` response semantics to banner/data;
- [x] add payload-length mismatch regression coverage;
- [x] extract response classification without adding per-target state;
- [x] add pcap/lab boundary coverage for all-banner.

## Windows quic-state TODO

- [ ] Add an ngtcp2 OpenSSL backend for the Windows MSVC build.
- [ ] Detect `vcpkg install ngtcp2[openssl]:x64-windows` in CMake (no pkg-config
      assumption).
- [ ] Port `quic-state` certificate/TLS metadata and `http3-state` to OpenSSL.
- [ ] Add MSVC build + local HTTP/3 lab coverage before calling it supported.
- [ ] Keep GnuTLS as the Linux backend until the OpenSSL path is proven.

## Release policy

Functional changes take a minor version (`2.44.x` → `3.0.0`); fixes take a
patch version. A release is not complete until the tag is pushed, the GitHub
release exists, and the build/test evidence is recorded.

## Input/output module audit

A dedicated review of every input (target/generate/pcap) and output module is
planned before the next protocol batch:

- bounds and overflow review for file/stream/BSON/NDJSON/pcap inputs;
- error handling and partial-write behavior for text/NDJSON/CSV/BSON/Mongo outputs;
- output escaping and machine-readable JSON validity;
- path/permission and cleanup behavior;
- unit tests for malformed input and failure paths;
- regression tests for existing pcap and target-file matrices.

This is a code-review workstream, not a new feature; it should land as a
separate audit report plus fixes.

## AI integration (MCP / Agent / Skill)

Goal: make Xtate usable by AI agents without giving them an unstructured shell.
The CLI remains the source of truth; the control plane owns jobs and MCP is a
typed client.

Delivered in 2.42.0:

1. JSON schemas for scan requests, module metadata, results and error codes.
2. Managed scan jobs with timeout, stall detection, heartbeat and cancellation.
3. A local control plane over a Unix socket or Windows Named Pipe, protected by
   `XTATE_CONTROL_TOKEN`.
4. An MCP stdio server with read-only tools and controlled `start_scan`:
   `list_modules`, `describe_probe`, `explain_target`, `check`,
   `validate_config`, `start_scan`, `job_list`, `job_status`,
   `job_result_manifest`, `job_cancel`.
5. Route-aware planning and rejection of target sets that span multiple routes.
6. Safety boundaries: no shell, registered module names only, target/rate limits,
   explicit `authorized:true`, audit log and local-only control transport.

Delivered in 2.42.1:

- Agent Skill at `skills/xtate/`, with English/Chinese docs and a schema-aligned
  `dry_run` contract;
- full-tree audit fixes for memory safety, Windows UTF-8 paths, control-plane
  framing/validation and result-store JSON escaping.

Delivered in 2.43.0:

- a full-screen TUI control-plane client (`xtate --tui`) for job listing, start,
  cancellation and manifest details, plus docs EN/ZH.

Delivered in 2.44.0:

- a loopback-only browser GUI (`xtate --gui`) as another control-plane client:
  dashboard, start wizard, cancel, status and result manifest, with a per-run
  session token, Host validation and a job-method allowlist.

Delivered in 2.44.1:

- one-command local TUI/GUI startup with a private control plane for the UI
  lifetime; `--control-connect` still attaches to an existing daemon.

Delivered in 2.44.2:

- corrected `PCAP_DLT_RAW` handling (`DLT_RAW` 12) so TUN/VPN adapters, including
  fake-IP tunnels, are no longer rejected as unknown link types.
- `--explain-target` reports the adapter link type and flags unsupported links;
  scan startup rejects unsupported link types with an actionable hint and the
  multiple-default-interface error points at `--explain-target`/`--list-if`.
- scan startup and the meta file show the effective `Rate:` (default or `--rate`).

Delivered in 3.0.0:

- redesigned scan-first browser console: readable Paper/Graphite themes,
  English/Chinese switch, Xtate module taxonomy with expandable descriptions and
  parameter tables, 23 validated global parameters, real System preferences,
  large live-status headline, result-record paging and open-in-default-app job
  files;
- per-run timestamped result folders and managed state directories, with
  request/heartbeat files cleaned up after jobs;
- server-side preflight and validation of `global_args` before a worker starts;
- one-command `xtate --gui` and `xtate --mcp` private control-plane startup;
- `--list-capabilities`, plus MCP `capabilities`, `iface.list`,
  `preflight`, `job.records` and token-protected private control planes;
- explicit Linux-only HTTP/3 + QUIC capability reporting, with Windows
  reporting the feature as unavailable;
- the GUI prints its URL instead of launching a browser; Open log/result starts
  Notepad directly on Windows; module details show the full help and probe
  transport type; README refreshed;
- hardened MCP/Agent Skill contract: flat `start_scan`, unknown-field rejection,
  array/string preflight, clear 8 KiB limit, token JSON escaping, and independent
  contract suites;
- the Ubuntu 24.04 full-feature Docker image is implemented: all optional
  dependencies, mainland APT mirrors, host GUI access and tested capabilities;
- bilingual 10-chapter manual under `docs/manual/` and
  `docs/zh-CN/manual/`.

Remaining after 3.0.0:

- agent evaluation suite and packaging;
- MCP generate/stream input (static `targets` and `include_file` only for now);
- per-job disk quota enforcement during scanning (currently reported after
  completion).

Release history:

```text
2.42.0  JSON contracts + jobs + control plane + MCP server (done)
2.42.1  Agent Skill + full-tree audit hardening (done)
2.43.0  TUI control-plane dashboard (done, released)
2.44.0  browser GUI for the control plane (done, released)
2.44.1  one-command local TUI/GUI startup (done, released)
2.44.2  RAW/TUN link preflight + startup rate display (done)
3.0.0  final: redesigned GUI + AI/MCP tools + capability reporting
future  evaluation suite, packaging and MCP generate/stream input
```

See [AI integration design](./ai-integration.md) and [MCP server](./mcp-server.md).

## Internet-scale job data plane

Status for the result path used by MCP/TUI/GUI:

- [x] 64-bit result sizes and cursors (`uint64_t`, `fseeko`/`_fseeki64`);
- [x] bounded control responses; clients read the manifest and chunks instead of
  asking the control plane for the whole result;
- [x] chunked NDJSON, optional zstd and optional index;
- [x] completed-job TTL and maximum retained jobs;
- [x] heartbeat and stall detection;
- [x] control/data plane separation for MCP/TUI/GUI;
- [ ] per-job disk quota enforced during scanning (quota is currently checked
  after completion and reported as a warning).

See [control plane](./control-plane.md).
