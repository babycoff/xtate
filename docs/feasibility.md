# P3 / P4 feasibility

**English** · [中文](zh-CN/feasibility.md)

This is an engineering feasibility assessment, not an implementation promise.
It assumes the 2.42.0 architecture: stateless ZBanner/UDP, HLTCP for stateful
TCP, and output-side aggregation.

> **Status note (3.0.0-rc.10).** The assessment below is historical. The
> stateless `quic` probe and the optional Linux-only `quic-state`/`http3-state`
> transport are implemented (ngtcp2 + GnuTLS; Windows builds do not ship them
> and `--list-capabilities` reports `http3: false`). The transport data plane
> uses ngtcp2, not OpenSSL's QUIC API, and TLS is provided by GnuTLS. Option A/B
> analysis and the library decision gate therefore apply only to extending the
> transport (for example dynamic QPACK or DoQ), not to whether to build it.

## QUIC probe and HTTP/3 exploration

**Verdict (historical, 2.42.0 baseline): the capability probe is implemented; a
real HTTP/3 scanner is a separate transport project and should be gated behind a
library decision.** See the status note above: the transport was subsequently
built as `quic-state`/`http3-state` on Linux with ngtcp2 + GnuTLS.

QUIC is not HTTP/2 over UDP. The protocol combines TLS 1.3, loss recovery,
packet-number spaces, connection IDs and a 1200-byte padded Initial packet.
Sending an arbitrary UDP payload with `ALPN=h3` is not a QUIC or HTTP/3 probe.

### Option A — QUIC capability probe (recommended first)

A stateless `quic`/`quic-hello` UDP probe can:

- build a valid QUIC v1 Initial packet with a random DCID/SCID and a TLS 1.3
  ClientHello (ALPN `h3`);
- derive Initial keys and apply header protection with AES-128-GCM;
- match the response to the unique DCID and classify:
  - Version Negotiation;
  - Retry (with token);
  - Initial/Handshake response;
  - connection close / stateless reset;
  - no response;
- report QUIC version, source/destination CID and response type.

What it **cannot** do:

- prove that HTTP/3 is usable;
- complete a TLS handshake or send an HTTP/3 request;
- report QPACK/control-stream behavior.

Cost: medium. It fits the existing stateless ZBanner/UDP model if the DCID is
unique per target and no connection state is retained. It still needs a
well-tested QUIC packet builder and local test servers (`aioquic`, `quiche` or
`ngtcp2`), plus version/retry/token edge cases.

### Option B — library-backed QUIC handshake and HTTP/3

A real HTTP/3 probe needs:

- UDP socket/event loop and per-connection state;
- QUIC handshake with TLS 1.3 and transport parameters;
- ACK/loss detection/timers, Retry/token and connection close;
- HTTP/3 control streams, QPACK, request/response and GOAWAY.

This cannot live inside the current stateless `udp` scan or `tcp-state` HLTCP.
It requires a new `quic-state`-style scanner (or a separate helper process), a
new probe type, and a concurrency/resource model. An optional library such as
`ngtcp2`/`nghttp3`, `quiche` or `msquic` could supply the transport, but the
scanner still owns flow scheduling, retries, output and limits.

Cost: high. It also changes the default build/CI and dependency story, so it
must remain optional and must not silently degrade.

### Option C — external sidecar

A separate QUIC/HTTP3 helper invoked per target or batch keeps the core scanner
small, but adds process/IPC overhead and makes rate/connection accounting harder.
It is a reasonable research prototype, not the first production integration.

### Option D — documented non-goal

If the measurement need is only "is this UDP port QUIC?", stop at Option A and
explicitly do not claim HTTP/3. This is safer than a fake HTTP/3 result.

### Recommendation and decision gate

1. Build a local QUIC/HTTP3 research prototype outside the hot path; compare at
   least one client library with a local `aioquic`/`quiche` server.
2. Implement **Option A** as `quic-hello` (or `quic`) only if the lab proves
   response attribution and retry/version behavior are deterministic.
3. Gate Option B on a concrete requirement for HTTP/3 responses and a library
   choice. Do not add a default dependency just because QUIC is fashionable.
4. Keep an explicit output distinction:
   - `quic`: QUIC transport observed;
   - `http3`: HTTP/3 handshake/request completed.

Acceptance for Option A:

- local QUIC server receives a valid Initial;
- Version Negotiation and Retry are classified;
- unique DCID matching prevents cross-target attribution;
- no per-target table and no unbounded retry state;
- lab tests do not need public Internet.

OpenSSL's QUIC API is not available across the whole supported OpenSSL range
(the project supports older 1.1.1 builds), so a QUIC implementation should not
silently require an OpenSSL version that breaks the normal build.

## Protocol coverage expansion

See [Protocol coverage plan](./protocol-coverage.md) for the zgrab2-referenced
protocol matrix and tiered implementation plan. It is a separate workstream from
QUIC and does not require new transport machinery for most protocols.

## P3 — scan control

### Limited target-aware probe selection

**Verdict: feasible, medium complexity, medium risk.**

Goal: use port/banner/TLS evidence to choose the next probe instead of launching
every probe against every target.

Why it is feasible:

- the scanner already emits enough evidence (classification, banner, TLS
  fields);
- selection can live outside the packet hot path;
- it does not require per-target state in ZBanner.

Main design problem: where the decision lives.

1. **External controller**: first pass to NDJSON, a controller builds a second
   target file per probe. Lowest risk; no scanner API changes; slower.
2. **Output-side schedule**: an output module produces follow-up target files.
   Still no scanner state; needs a local orchestration step.
3. **In-scanner selection**: would require per-target decision state and a
   second probe queue. This conflicts with the stateless design and should not
   be the first implementation.

Acceptance for a first version:

- deterministic input/output;
- no unbounded per-target table;
- a documented two-pass recipe;
- tests that show a target is selected only when its evidence matches.

### Adaptive packet-rate discovery

**Verdict: feasible, medium-high complexity, high measurement risk.**

Goal: start below a fixed `--rate`, observe loss/timeouts/ICMP errors, and
adjust automatically.

Required pieces:

- a bounded feedback window and control loop;
- clear min/max rate and a safe default;
- distinguish local congestion, link loss and target non-response;
- a deterministic/manual fallback (`--rate` must remain authoritative);
- lab and real-network validation.

Risks:

- a feedback loop can oscillate or amplify loss;
- a stateless scanner cannot attribute every lost packet;
- results become rate-dependent and harder to reproduce.

Recommendation: implement as an opt-in controller around the existing rate
throttle, not inside probe callbacks.

### Cross-layer service fingerprints

**Verdict: feasible, high data-model complexity.**

Combine IP/TCP options, TLS parameters and application evidence. The scanner
should emit fields; normalization and grouping belong in the output layer.
A stateless implementation must not keep a per-target fingerprint table.

### Two-stage stateless → stateful handoff

**Verdict: feasible, high complexity.**

The natural form is: ZBanner/port evidence selects a small candidate set, then
HLTCP runs stateful TLS/application probes on those targets. This needs a
handoff format and scheduler, plus TCB cost control. It overlaps with the
deferred HLTCP slot work.

## P4 — templates and traffic

### Xtate-native YAML templates

**Verdict: feasible, medium-high complexity, large surface.**

Requirements:

- a small Xtate-native schema, not Nuclei compatibility;
- compile templates to existing probes/slot plans rather than interpreting
  arbitrary code;
- bounded timeouts, payloads and output fields;
- explicit failure semantics;
- versioned schema and validation.

Avoid: embedding a general language, arbitrary file/network access, or silent
Nuclei fallback. Start with a read-only matcher/response schema and a few
compiled actions.

### Scanner-traffic fingerprint randomization

**Verdict: feasible, medium complexity, research and policy risk.**

Options: TCP option order, IP ID behavior, source-port selection, TTL, HTTP
header order, TLS extension ordering and GREASE. Some are already present in
the stack/probe design.

Risks:

- changes can affect target behavior and measurement validity;
- randomization can reduce reproducibility;
- it can be abused to evade monitoring;
- need a research switch, a deterministic seed and clear documentation.

Recommendation: treat as an opt-in research feature, never a default, and test
only in the local lab.

## Recommended order

Current direction prioritizes QUIC/HTTP3 and templates/traffic; the rest remains
backlog:

1. QUIC capability probe and HTTP/3 library decision.
2. Read-only Xtate-native YAML templates.
3. Protocol coverage Batch A (see [protocol coverage](./protocol-coverage.md)).
4. Traffic randomization research (opt-in, fixed seed, lab-only).
5. JARM failure modes and external retry manifest.
6. SSH deep KEX/host-key, full HTTP/2, HLTCP slots.
7. External target-aware selection, adaptive rate, two-stage handoff.

## Non-goals for the first pass

- in-scanner per-target state for selection;
- unconstrained template execution;
- default traffic obfuscation;
- Nuclei compatibility;
- silent fallback when a feature or dependency is unavailable.
