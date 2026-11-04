# Roadmap

**English** · [中文](zh-CN/roadmap.md)

This page records the planned work after Xtate 2.30.0. It is not a promise of
dates; it is a priority and acceptance-criteria list. Completed work is noted so
the next change does not silently regress it.

## Done in 2.30.0

- Generic `ProbeSlotPlan` with `ProbeSlot_Always` and
  `ProbeSlot_AfterFirstReply`.
- Legacy `MultiMode`/`multi_num` semantics removed.
- TCP and UDP independent slot execution.
- Built-in `slot-test` and `slot-test-udp` runtime examples.
- JARM per-slot parts and output-side aggregation.
- Offline JARM/TCP/UDP lab.
- Module development guide for all four module types.
- Compile-checked module templates for probe/state/output/generate.

## P1 — module examples (completed)

- [`examples/modules/`](../examples/modules/) has one compile-checked template
  per module type.
- `tests/module-examples/test.sh` is part of Linux CI.
- Runtime slot examples remain `slot-test` and `slot-test-udp`.

## Parameter parser coverage (planned)

The CLI/parameter parser has not had a dedicated regression suite. Add one
before relying on more nested/subprobe options:

- `ConfParam` flag/argument/unknown-option/duplicate-option cases;
- quoted strings, spaces, backslashes and nested `-subprobe-arg`;
- integer/range/hex/size boundaries and invalid values;
- `-scan-arg`, `-probe-arg`, `-output-arg`, `-gen-arg` nesting;
- interactive `set` and recovered config files;
- exact nonzero exit and stderr for invalid input.

Acceptance: a `tests/config/` suite runs on Linux CI, covers the parser and a
representative module from each registry, and does not depend on the network.

## P2 — JARM correctness

The fuzzy hash was corrected to Salesforce JARM 1.0 semantics:

- cipher → index in JARM's ordered cipher table (two hex characters);
- TLS version → one version nibble (`a`–`f`);
- ALPN + extensions → first 32 hex characters of SHA-256.

The test fixture now asserts an exact 62-character reference vector. Remaining
work:

1. Compare Xtate's output with the official JARM implementation on the same
   local TLS target, not only with the hash fixture.
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

1. TLS certificate/details probe: subject, issuer, SAN, validity, key type,
   signature algorithm, ALPN, negotiated version/cipher.
2. SSH banner probe is implemented (`ssh`), including coalesced KEX/host-key
   algorithm lists. Full KEX packet exchange remains future work.
3. HTTP state probe improvements: status line, headers, redirect target,
   body limits.
4. STARTTLS adapters for SMTP, IMAP, POP3 and FTP; compose TLS detail after the
   plaintext upgrade.
5. Cleartext h2c capability/framing probe is implemented (`h2c`); HTTP/2 over TLS, full HTTP/2
   client behavior and HTTP/3/QUIC remain future work.
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

## Release policy

Functional changes take a minor version (`2.29.x` → `2.30.0`); fixes take a
patch version. A release is not complete until the tag is pushed, the GitHub
release exists, and the build/test evidence is recorded.
