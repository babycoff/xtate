# Roadmap

**English** · [中文](zh-CN/roadmap.md)

This page records the planned work after Xtate 2.33.0. It is not a promise of
dates; it is a priority and acceptance-criteria list. Completed work is noted so
the next change does not silently regress it.

## Done in 2.33.0

- Optional `quic-state`: raw-UDP QUIC handshake with ngtcp2/GnuTLS, certificate/ALPN
  output and a state sub-probe; HTTP/3 is still a later application probe.
- Optional `http3-state`: minimal HTTP/3 GET over `quic-state`; status/header/body
  output, static QPACK/literal names, partial QPACK decoding reported explicitly.

- QUIC capability probe (`quic`): valid QUIC v1 Initial, Version
  Negotiation/Retry/Initial/Handshake classification, local aioquic lab.
- Module count: 27 probes.
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

The current priorities are:

1. **QUIC/HTTP3 next step** — the capability probe and the optional
   `quic-state` handshake transport are done; HTTP/3/QPACK and DoQ application
   probes are the next layer. See
   [QUIC state](./quic-state.md).
2. **Xtate-native YAML templates** — read-only matcher/schema first; do not
   copy Nuclei.
3. **Protocol coverage expansion** — use the zgrab2 matrix in
   [Protocol coverage plan](./protocol-coverage.md); start with Batch A.
4. **Traffic randomization research** — opt-in, fixed seed, lab-only; keep it
   separate from the default scanner.

The older backlog below remains valid but is lower priority unless a concrete
measurement requirement changes it.

## P1 — module examples (completed)

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

## P2 — JARM correctness

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

## P2 — protocol probes

Status: the JARM hash/reference work, SSH banner/KEX, cleartext `h2c` and the
`h2` state probe (TLS/ALPN h2 via HLTCP) are implemented. `h2` has a minimal
static/literal HPACK request and frame/HEADERS/DATA parsing; Huffman/dynamic
HPACK, full stream management, STARTTLS, HTTP/3/QUIC and TLS-variant
fingerprints remain. TLS certificate/subject details already exist in
`tls-state`; HTTP state behavior already exists in `http-state`.

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
4. STARTTLS adapters for SMTP, IMAP, POP3 and FTP are implemented in
   `tls-state --starttls`, including certificate details after the upgrade.
5. HTTP/2 remains minimal (`h2`): static/literal HPACK, no Huffman/dynamic
   table, no full stream management. HTTP/3/QUIC remain separate research.
6. TLS variant fingerprint research: ClientHello variants, extension order,
   GREASE, ALPN ordering.
7. QUIC probe and HTTP/3 exploration: a separate UDP/QUIC transport path,
   ALPN `h3`, QUIC Initial/Handshake packets and optional QUIC library
   evaluation. Do not call a UDP datagram an HTTP/3 probe without a QUIC
   handshake.

Constraints:

- one connection/flow per slot; no target group in the scanner;
- bounded payloads and output fields;
- deterministic tests in `tests/lab/` where a real service is required;
- optional dependencies stay optional.

For P3/P4 feasibility, see [P3/P4 feasibility](./feasibility.md).

## HTTP probe audit/rewrite (frozen)

The first response-parser pass is implemented. Per current direction, HTTP/1
work stops here; shared request-builder extraction and cross-segment chunked
state are deferred. See [HTTP probe audit](./http-probes-audit.md).

## P3 — scan control

- Limited target-aware probe selection based on port/banner/TLS evidence.
- Adaptive packet-rate discovery for unknown networks, with explicit
  min/max rate and reproducible feedback.
- Cross-layer fingerprints combining IP/TCP/TLS/application evidence.
- Two-stage stateless → stateful handoff.

## P3 — templates and traffic

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
2. Extend HTTP/3 beyond the minimal GET: dynamic QPACK/Huffman, more header
   handling and DoQ; keep the transport scanner and application probe separate.
3. Protocol coverage Batch A: Redis, Memcached, MQTT, Telnet, SOCKS5, NTP.
4. Traffic randomization research as an opt-in, fixed-seed lab feature (10B).
5. JARM failure modes and external retry manifest.
6. SSH deep KEX/host-key, full HTTP/2 HPACK/streams.
7. HLTCP slot planning (connection-local AfterFirstReply, then parallel flows).
8. TLS variant fingerprints.
9. P3 external two-pass target selection, opt-in adaptive rate.
10. HLTCP stateless -> stateful handoff.

## Release policy

Functional changes take a minor version (`2.29.x` → `2.33.0`); fixes take a
patch version. A release is not complete until the tag is pushed, the GitHub
release exists, and the build/test evidence is recorded.
