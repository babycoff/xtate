# P3 / P4 feasibility

**English** · [中文](zh-CN/feasibility.md)

This is an engineering feasibility assessment, not an implementation promise.
It assumes the 2.31.0 architecture: stateless ZBanner/UDP, HLTCP for stateful
TCP, and output-side aggregation.

## QUIC probe and HTTP/3 exploration

**Verdict: research; high complexity; a separate transport project.**

QUIC is not HTTP/2 over UDP. A real HTTP/3 probe needs:

- a QUIC Initial packet with a valid header protection/encryption path;
- TLS 1.3 handshake integrated into QUIC, with ALPN `h3`;
- QUIC connection IDs, packet number spaces, loss detection and timers;
- HTTP/3 control streams/QPACK if actual requests are required.

Options:

1. optional `libngtcp2`/`libnghttp3`, `quiche` or `msquic` integration;
2. a deliberately capability-only QUIC/Initial probe without HTTP/3 requests;
3. no new dependency and a documented non-goal.

Recommendation: first write a QUIC/HTTP/3 research prototype outside the
scanner hot path; do not add a fake "HTTP/3" UDP payload probe. Any optional
library must remain optional and must not change the default build.

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

1. Finish P2 protocol coverage and JARM/live comparisons.
2. External target-aware selection (P3, lowest risk).
3. Opt-in adaptive rate controller (P3).
4. Read-only YAML templates (P4).
5. Traffic randomization (P4, research only).
6. Two-stage handoff after HLTCP slot work is decided.

## Non-goals for the first pass

- in-scanner per-target state for selection;
- unconstrained template execution;
- default traffic obfuscation;
- Nuclei compatibility;
- silent fallback when a feature or dependency is unavailable.
