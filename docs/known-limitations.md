# Known limitations

**English** · [中文](zh-CN/known-limitations.md)

Xtate v2.20.0 is built around a deliberate trade: very high packet rates and cheap per-target cost, at the price of reliability and protocol completeness. This page lists what the current version does not do, what it means for your results, and how to work around it.

The mechanisms behind these limits are described in [ZBanner](./zbanner.md), [HLTCP](./hltcp.md) and [Architecture](./architecture.md). Everything below was verified against the v2.20.0 source tree.

| Area | Main limitation in v2.20.0 | Workaround |
|:---|:---|:---|
| ZBanner | no timeout or retransmission per target | re-run the range and merge results |
| `tcp-state` | closed results are `info`-level; no SYN retry | use `tcp-syn` for coverage, `tcp-state` for evidence |
| IPv6 | fragments and most extension headers are dropped | avoid fragmented paths, scan per /64 |
| Windows | Npcap; no PF_RING/`sendmmsg`; no host-wide RST helper | use Npcap + admin; local-stack RST behavior tested as non-interfering |
| Output | one sink at a time; non-JSON escaping by default | local text/NDJSON, then import |

## ZBanner (stateless TCP)

Applies to v2.20.0, the entire `zbanner` scan path.

- **No per-target timeout and no retransmission.** A lost SYN or a lost banner segment simply produces no result for that target; nothing is retried and there is no timeout table. Workaround: re-run the range (`--repeat 1`, or another full pass with a different `-seed`) and merge the results.
- **Deduplication is approximate.** The dedup table is a fixed set of 4-way buckets with random aging (default `-dedup-win 1000000`, roughly 70 MB), and the IPv4 hash uses only the low address bits. Under load, entries are evicted and the `repeats` counter becomes wrong. Impact: repeated-result suppression is best-effort, and any feature that depends on `repeats` (notably `--all-banner` numbering and `-all-banner-limit`/`-all-banner-floor`) is not reliable at Internet scale. Workaround: raise `-dedup-win`, and do not treat `repeats` as a precise counter.
- **`--all-banner` is a heuristic, not a stream reassembler.** Continuation segments are acknowledged and deduplicated by data length; out-of-order segments are not ordered, and the segment index comes from the approximate dedup counter. Impact: long banners can be truncated or mis-numbered. Workaround: keep responses small, raise `-tcp-win`, or use `tcp-state` for full TLS/HTTP bodies.
- **The default closes the connection after the first banner segment.** Multi-segment responses (large TLS ServerHello, certificate chains, long HTTP headers) are cut off unless you pass `-scan-arg "-all-banner"`.
- **Probe payloads are limited to the packet buffer.** The payload must fit in a 2048-byte packet alongside the IP/TCP headers (about 2000 bytes of payload). A larger payload is not truncated — the packet is not transmitted, and a warning is logged. Workaround: keep probe payloads under about 2000 bytes.
- **Zero-window SYN-ACKs are classified `fake-open`** and get no probe payload by default. Real services with a full SYN backlog can look "fake open". `-scan-arg "--probe-zerowin"` is a research switch that keeps the `fake-open` classification but sends the probe payload anyway.
- **Banner scans require host-wide firewall rules on Linux.** ZBanner depends on the kernel not answering unknown connections; the supplied scripts drop *all* outgoing TCP RST from the host for as long as they are installed. There is no in-process RST filter in the v2.20.0 production path. Forgetting to run `./firewall/rm_rules.sh` leaves the machine with broken TCP resets.
- **No Windows host-wide RST helper ships with v2.20.0.** Windows uses Npcap. A local test (Windows 11, Npcap loopback + WSL target) observed SYN-ACK and ACK acknowledgement without host-wide RST suppression, so the Linux `iptables` helper may not be needed for the local-stack RST problem. Because the Windows stack does not RST unknown half-open connections, use `-scan-arg "--send-rst"` for `tcp-syn` to close them actively; `zbanner` and `tcp-state` send their own RST. Windows still requires Npcap, administrator access for the capture driver and correct adapter selection; there is no PF_RING/`sendmmsg` equivalent.
- **Output is event-based, not per-target.** One target can produce an `open` line, several `banner` lines and an `acknowledged` line. Downstream consumers must aggregate by target/port themselves.
- **A 1024-byte window is used after the handshake** (default `-tcp-win`), which limits how much data can be in flight and encourages small segments. Workaround: raise `-tcp-win` (and use `--all-banner` for multi-segment data).
- **Cookie strength is measurement-grade, not authentication-grade.** The 32-bit SipHash cookie and the deterministic source port (`-src-port` base + probe index) make responses verifiable against a friendly peer, but are predictable to an off-path attacker who knows the seed.
- **Multi-probe needs source-port headroom.** Each probe slot of a multi-probe module consumes one port from the source-port range (`-src-port`, 256 ports by default); if the range is smaller than the probe count, the extra slots fall outside the range and their replies are discarded silently. Workaround: widen `-src-port`.

## Stateless scan modules (beyond ZBanner)

Applies to v2.20.0, `tcp-syn`, `udp`, the ICMP scans, `arp-req`, `ndp-ns`, `sctp-init` and the Yarrp modules.

- **UDP, ARP and NDP have no cookie check.** UDP replies are validated by target-set membership plus the probe's own callback; ARP/NDP additionally require the default `blackrock` generator to invert the target set. With other generators, ARP/NDP degrade to "any reply counts" and UDP loses its closed-port logic.
- **ICMP identification is short.** `icmp-echo`/`icmp-time` put only 8 bits of cookie in the ICMP id (and 8 more in the sequence field), so false attribution is far more likely than for TCP's 32-bit cookie.
- **Yarrp deduplication can merge targets.** Per-hop results are deduplicated on the outer source and the TTL; different destinations behind the same router at the same distance can be treated as repeats and dropped. Impact: multi-target topology measurement loses paths. Workaround: smaller batches, or accept the loss and post-process.
- **Fragmented IP packets are discarded** before validation — IPv4 with MF/fragment offset set, and IPv6 with a Fragment header. Enabling `--no-bpf` does not change this.

## HLTCP / `tcp-state` (hybrid-state TCP)

Applies to v2.20.0, the `tcp-state` scan and all `*-state` probes.

- **Only three TCP states exist** (SYN-SENT, SENDING, RECEIVING). There is no LISTEN, FIN-WAIT, CLOSE-WAIT or TIME-WAIT, no graceful shutdown, and a peer FIN is answered with RST. Impact: some servers log abnormal terminations, and half-closed exchanges are not modelled.
- **SYN is sent once, with no retransmission.** A lost SYN means the target silently produces nothing. Workaround: lower the rate, re-run with `--repeat`, or prefer `zbanner` for wide coverage.
- **A lost ACK is not retransmitted.** Duplicate SYN-ACKs are ignored instead of re-acked, and the connection is eventually reclaimed by `tcp-state`'s own connection expiry (`-scan-arg "-conn-expire 30"`, default 30 s).
- **The RTO is fixed at 1 second**, with no RTT estimation and no exponential backoff. High-latency paths waste time and bandwidth. Workaround: prefer low-latency vantage points.
- **There is no out-of-order reassembly.** Data beyond the expected sequence number is dropped and the stack waits for the peer's own retransmission; large TLS flights over lossy paths may never complete. Workaround: keep rates low enough to avoid loss, or accept partial exchanges.
- **Closed ports are `info`-level, not failure.** A RST for an unknown connection is emitted as `"closed" because "rst"` and deduplicated by the rx table; without `-show info` these rows stay hidden. ZBanner exposes closed at `info` too unless promoted.
- **TLS SNI/ALPN are opt-in.** `tls-state` sends no SNI or ALPN by default: CDNs and virtual hosts answer with their default certificate/site, and HTTP/2 is never negotiated. Pass `-sni <hostname>` / `-alpn <list>` to the `tls-state` probe when the target IPs belong to one known hostname; there is no automatic hostname mapping.
- **Closing is a RST, not `close_notify`, by default.** TLS sessions are torn down with a TCP reset; the peer never sees a clean TLS close. The research switch `-probe-arg "--graceful-tls-close"` sends a `close_notify` before the RST at the cost of an extra packet/round trip; it is not enabled by default.
- **Memory grows with OpenSSL.** A plain HLTCP connection costs a few hundred bytes, but TLS sessions add OpenSSL state (typically several KB to tens of KB per connection, dominated by `SSL*`/certificates), plus a fixed per-handle TCP table and timer wheel (about 8 MiB per handle thread). The TCBs are recycled in a pool, not returned to the OS until exit.
- **Receive-side deduplication is disabled** for `tcp-state`; correctness depends on the state machine being idempotent, which makes the missing-ACK case above more visible.
- **Multi-probe connections share the source-port space.** Each probe slot maps to a source port, so the probe count must stay below the `-src-port` range or connections collide between slots.

## IPv6

Applies to v2.20.0, all IPv6 scans.

- **Only the hop-by-hop extension header is understood.** Destination Options, Routing headers and — critically — the Fragment header cause the packet to be dropped before scan logic (`--no-bpf` does not help). Workaround: avoid fragmented IPv6 paths; lower rates/MTU-sensitive probes.
- **Source address pools only span the low 64 bits** of an IPv6 range and must share the same high 64 bits; link-local sources must be given explicitly. Workaround: run separate scans per /64.
- **`-src-ip` ranges must be power-of-two sized**, exactly as for IPv4.
- **IPID is not recorded for IPv6** (it does not exist); `-scan-arg "-ipid"` only affects IPv4 results.
- **The scan space is capped at 63 bits** by the default `blackrock` generator (addresses × ports). Large IPv6 surveys must be split with `--shard` or narrower prefixes.
- **`icmp-time` and `arp-req` are IPv4-only**; use `ndp-ns` and `icmp-echo` for IPv6.

## Windows

Applies to v2.20.0, Windows builds.

- **No PF_RING and no `sendmmsg`/AF_PACKET path.** Transmit is limited to Npcap's send-queue or per-packet send; `--send-queue` reaches much higher rates but adds latency, so keep it off for `zbanner`/`tcp-state`.
- **Receive is blocking** (`pcap_next_ex`); there is no non-blocking adapter mode on Windows, so a slow sink or very high rate shows up as missed replies.
- **Interactive mode cannot restart itself.** On Linux an interactive scan re-executes the binary with `recover.conf`; on Windows `-interact` returns after a scan and you must start it again manually.
- **Adapter names are unfriendly.** Use the numeric index printed by `--list-if` (e.g. `-if 3`) instead of the full Npcap device name.
- **Handshake-based banner scans have no kernel-RST suppression path** (the firewall scripts are `iptables`/`ip6tables` only).

## Output and I/O

Applies to v2.20.0, all platforms.

- **Only one OutputModule can be active at a time**, and writing happens inside the handler threads under a global mutex. A slow sink (MongoDB over the network, a slow disk) throttles the whole scan. Workaround: write text/NDJSON locally, then import.
- **Default string escaping is not JSON-compliant.** Quotes, backslashes and control characters become `\xNN`; add `--no-escape-char` when the consumer is a JSON parser. BSON/MongoDB modules must stay in the default mode.
- **`classification` and `reason` are emitted verbatim** by the CSV/NDJSON writers, so a quote or newline can break a record. Workaround: prefer BSON, or sanitize those fields downstream.
- **`--max-packet-len` defaults to 1514 bytes**; larger received frames are ignored entirely (not just truncated). Raise it together with `--adapter-snaplen` for jumbo frames, tunnels or large TLS records.
- **`--pcap` stores received packets only** and is not a replay facility; transmitted packets are absent from the file.

## Framework and scale

Applies to v2.20.0, all platforms.

- **Modules are registered at compile time.** There is no runtime plugin loading: adding a module means editing a registry and rebuilding. Optional dependencies (OpenSSL, PCRE2, LibXml2, libbson, libmongoc) remove their modules from the binary at build time.
- **Lua probes are runtime-loaded**, so a missing `liblua` shows up as a startup failure of `lua-tcp`/`lua-udp`, not as a missing module. Workaround: install Lua 5.3/5.4. Lua probes use a shared process-wide Lua state, so Xtate forces `--rx-handler-count 1` when one is selected.
- **There is a single receive thread**, and deduplication lives inside it. Rx-side throughput cannot be scaled with threads; use several hosts or `--shard`.
- **Very large IPv4 surveys need explicit confirmation.** More than 1,000,000,000 target IPs and no `--exclude` is refused at startup; `--exclude 255.255.255.255` is the documented acknowledgement.
- **The default generator randomizes over the whole scan space.** `--shard` is documented for the default `blackrock` generator only; `--resume` (reload a saved configuration) and `--resume-index` (start at an absolute scan index) assume index-addressable targets, which holds for the default generator.

## Getting the most out of v2.20.0

Use `tcp-syn` for coverage and open/closed classification, `zbanner` for stateless banners at scale, and `tcp-state` for a small number of high-value TLS/HTTP targets. Add firewall rules only around the scans that need them, keep payloads and rates modest, and read the module-level limitations in [Scanning modes](./scanning-modes.md) before choosing a probe.
