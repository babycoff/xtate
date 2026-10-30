# Architecture

**English** · [中文](zh-CN/architecture.md)

Xtate is a modular, all-stack network scanner for large-scale active measurement. It
turns a scan into a pipeline of four pluggable module types — **Generate** (targets),
**Scan** (L3/L4 packets), **Probe** (L5+ payloads and parsers) and **Output** (results) —
and runs that pipeline on a small, fixed set of threads. Nothing is loaded at runtime:
every module is a static struct in a NULL-terminated registry, and modules whose optional
libraries are missing are compiled out.

Two engines sit on top of this pipeline and are the reason the project exists:

- **ZBanner** — a stateless TCP handshake that returns real banners without a
  per-target connection table. See [zbanner.md](./zbanner.md).
- **HLTCP** — a hybrid-state user-space TCP stack that completes TLS handshakes and
  speaks HTTP inside them. See [hltcp.md](./hltcp.md).

This document describes the machinery both engines share.

## The pipeline

A scan moves in one direction: targets are generated, turned into packets, sent, and
the replies are parsed and reduced to results.

1. **Generate** produces the next target — a `(ip_them, port_them, ip_me, port_me,
   ip_proto)` tuple, flattened from the target set and shuffled.
2. **Scan** builds the packet for that target and hands it to the raw socket layer.
3. **Probe** contributes the application-layer payload and interprets responses.
4. **Output** formats each result as an `OutItem` and writes it wherever you asked.

At Internet scale, sending and receiving cannot live on the same thread, so the pipeline
is split across threads with lock-free rings between the stages.

## Thread model

![Xtate threading model: N transmit threads, one receive thread, one dispatcher, and M handler threads with per-thread TCB tables, connected by the NetStack follow-up queue](../screenshots/architecture.svg)

A running scan has **N + M + 3** threads: one main thread, N transmitters, one receiver,
one dispatcher and M handlers. With the default `--tx-thread-count 1` and
`--rx-handler-count 1` that is five threads.

| Thread | Count | Created by | Responsibility |
|:---|:---:|:---|:---|
| main | 1 | OS | Control plane: parse config, init modules, poll status, handle signals, drain and shut down. Not on the packet path. |
| tx | N | main | Pull targets from the generator, build packets, send them, and flush follow-up packets queued by the handlers. |
| rx | 1 | main | Receive, preprocess and validate every reply; record to pcap if asked; optionally deduplicate; dispatch. |
| dispatch | 1 | rx | Hash the source IP and enqueue the packet onto one of the M handler queues. |
| handle | M | rx | Run the scan/probe state machine, format results, and queue follow-up packets. |

The split matters because the two halves have different constraints. The transmitter side
is rate-shaped and CPU-bound on packet construction; the receiver side is I/O-bound and
must not be delayed by per-connection work. Handlers are where the expensive, per-target
logic runs, so that is the only pool you scale out when a stateful scan needs more CPU.

**Dispatch affinity.** The dispatcher computes `hash(src_ip) & (M - 1)` and enqueues onto
`handle_q[0..M-1]`. Because the hash only uses the source IP, every packet from a given
host lands on the same handler thread, in arrival order. That single decision is what
makes stateful scanning possible without locks: a handler owns its connections
exclusively, so a TCB only ever has one writer. `M` must be a power of two, and the hash
is 8 bits wide — see [known-limitations.md](./known-limitations.md) for what that implies
at very large handler counts.

**Per-handler connection tables.** A stateful scan such as `tcp-state` allocates one
user-space TCP connection table per handler thread, not one global table. The affinity
rule above guarantees no two threads touch the same connection, so the fast path needs no
mutex. The price is that connection state is bound to a thread: resize `M` and the
distribution of connections changes.

**The NetStack queues.** Handlers do not send directly. A follow-up packet — an ACK, a
RST, the next probe — is written into a shared ring called `transmit_queue`, and a tx
thread flushes that ring at the top of its loop before generating new targets. There is a
matching pool of fixed-size packet buffers (2048 bytes each) shared by the same mechanism.
This is the trick that lets a stateless receive path drive a real TCP conversation: the
receiver stays pure, and the stateful decisions are expressed as packets queued for
transmission. Dispatch and handler rings are sized at startup (16384 slots by default,
power of two). When a ring is full the producer sleeps and retries instead of dropping —
the scanner applies backpressure rather than loss.

CPU affinity is assigned in a fixed order — tx threads first, then rx, then handlers —
and is disabled with `--no-cpu-bind`.

## The four module types

| Type | Owns | Called from |
|:---|:---|:---|
| Generate | The sequence of targets and any permutation state | tx threads |
| Scan | Packet construction and the scan-level state machine | tx (`transmit`), rx (`validate`), handle (`handle`, `poll`) |
| Probe | Payload bytes, response parsing, optional per-connection session | tx or handle (`make_payload`), rx (`get_payload_length`), handle (`handle_response`, state callbacks) |
| Output | Result formatting and delivery | handle threads, serialised by one lock |

Each interface is a small set of callbacks with documented thread ownership. A scan module
sees a reply three times: in `validate`, where it decides whether the packet is yours and
whether it should be deduplicated; in `handle`, where the state machine runs and results
are produced; and in `poll`, which the handler calls every loop to service timeouts. A
probe module has two shapes: stateless (payload in, bytes out) and stateful (a session with
`conn_init` / `make_hello` / `parse_response` / `conn_close`, always called on the handler
thread that owns the connection).

The four registries are ordinary C arrays, so adding a module means writing one struct and
one line. The same metadata drives `--list-*`, `--help-*`, parameter parsing, fuzzy search
and interactive completion. There is no plugin ABI and no dynamic discovery.

## Packet construction

Packets are not built from scratch per target. At startup the template layer pre-bakes a
small set of packet templates — SYN, generic TCP with data, RST, and the equivalents for
UDP, ICMP, ARP, NDP and SCTP — and per-target transmission patches the addresses, ports,
sequence numbers and IP ID into a copy, then recomputes the transport and IP checksums.
Different templates carry different assumptions: the SYN template advertises MSS 1460 and
a 64240-byte window, the non-SYN TCP template carries no options and a 1024-byte window,
and the RST template advertises a zero window. Those defaults are why `tcp-state` can be
tuned with `--tcp-win` and `--tcp-mss`.

## Target space and randomisation

The target set is flattened into a single index space of `ip × port` and walked in a
permuted order. The default generator is **BlackRock**, a stateless DES-like permutation:
given a seed and an index it computes the shuffled index without storing the list, so
memory stays flat no matter how large the scan is. The space is limited to 63 bits, and a
request for more than a billion addresses without an explicit `--exclude` is refused as a
guard against accidentally scanning the whole Internet.

Source addresses and ports can be randomised inside their configured ranges. The source
port range deserves attention: both ZBanner and HLTCP encode the probe slot in the source
port (`first + index`), which is how a reply is matched to the probe that produced it.
`--source-port` must therefore be at least as wide as the probe's `multi_num`, or
multi-probe replies will be filtered out. `--shard` and `--resume-index` split one logical
scan across processes and restart points, both on top of the same permutation.

## Results

Every result is an `OutItem`: a target tuple, a level (`info`, `failure` or `success`), a
`classification` and `reason` string, plus three typed key-value chains — one for scan
fields, one for probe fields, one for output fields. The output module is chosen once and
receives results from whichever handler produced them; a single mutex serialises that call,
so a slow sink (a synchronous database insert, for example) slows down handling. That is a
deliberate simplicity trade-off, and the reason throughput-sensitive runs should prefer the
local formats.

## Two engines, one pipeline

| | ZBanner | HLTCP |
|:---|:---|:---|
| State | none per target | a TCB after the SYN-ACK |
| Sends | SYN, then ACK carrying the probe | a full TCP conversation |
| Returns | open/closed and first banner(s) | TLS handshake, certificates, HTTP over TLS |
| Module | `-scan zbanner` | `-scan tcp-state` |
| Detail | [zbanner.md](./zbanner.md) | [hltcp.md](./hltcp.md) |

Both engines rely on the same two infrastructure invariants: follow-up packets travel
through the NetStack queue rather than being sent inline, and the host kernel must be
prevented from resetting connections it does not know about. See
[zbanner.md](./zbanner.md) for the firewall setup both of them need.

## What the design deliberately gives up

- **One receiver.** Receive-side processing, validation and deduplication are single
  threaded by construction. That keeps ordering and dedup simple, but it caps receive-side
  throughput and is the first thing to profile on a fast link.
- **No output queue.** Results are emitted from the handler threads under a global lock.
  There is no separate writer thread and no buffering to absorb a slow sink.
- **Thread-affine state.** Connection state cannot migrate between handlers, so capacity
  and latency follow the per-thread table sizes rather than a global budget.
- **Static modules.** Optional features are compile-time decisions; a missing library
  removes the module instead of failing at runtime.

These are not bugs — each one buys something in the other column. They are documented so
you can tell which part of the scanner you are paying for when a scan behaves unexpectedly.

## Where to go next

- [zbanner.md](./zbanner.md) — stateless TCP banners and the cookie arithmetic.
- [hltcp.md](./hltcp.md) — hybrid-state TCP, TLS and nested state probes.
- [scanning-modes.md](./scanning-modes.md) — which scan module to use for what.
- [known-limitations.md](./known-limitations.md) — the honest list of what does not work.
