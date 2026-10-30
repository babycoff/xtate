# ZBanner: stateless TCP banners

ZBanner obtains real TCP responses from real services **without keeping per-target
connection state**. The peer's TCP stack holds the connection; Xtate holds only a key and
some arithmetic. When a reply arrives, the key is recomputed from the packet's own fields
and compared — if it matches, the reply is ours.

This is the difference that makes large-scale banner grabbing affordable. A conventional
banner grab allocates a TCB, a timer and a retransmission queue per target; ZBanner
allocates none of these. It sends two packets and reads two, then closes the connection
with a RST.

## The idea

TCP needs three things to establish a connection: an initial sequence number from the
client, the server's acknowledgement of it, and the client's acknowledgement of the server.
ZBanner fills the first slot with a **SipHash cookie** derived from the connection tuple:

```
cookie = siphash24(entropy, ip_them, port_them, ip_me, port_me)   // low 32 bits
```

The cookie is unpredictable to an off-path attacker who does not know `entropy`, and it is
reproducible by us at any later moment from any packet of the same tuple. That is the whole
state: `entropy` is one global seed; the tuple comes back in every reply.

Because the cookie is our ISN, the server's SYN-ACK acknowledges `cookie + 1`. When a
packet claims to be a reply, we recompute the cookie and check the acknowledgement field.
No lookup table is consulted, because there is no table.

## The sequence

![ZBanner sequence: SYN with a SipHash cookie, SYN-ACK acknowledging cookie plus one, ACK with probe payload, ACK with banner, then RST; no TCB and no timeout table](../screenshots/zbanner-sequence.svg)

1. **SYN** — `seq = cookie`, `ack = 0`. The source port is `source_port_start + probe_slot`,
   so the probe slot travels in the port number rather than in memory.
2. **SYN-ACK** — the server acks `cookie + 1`. We accept the packet only if
   `ackno == cookie + 1`, and only if the destination port is in our source port range.
3. **ACK + payload** — `seq = cookie + 1` (the value the server just acknowledged),
   `ack = server_seq + 1`. The probe payload is appended to this ACK.
4. **ACK + banner** — the server acknowledges our data. Its `ackno` equals
   `cookie + 1 + payload_len`, which is both a liveness check and a length check.
   The payload bytes are handed to the probe module.
5. **RST** — close the connection. Nothing needs to be cleaned up, because nothing was
   allocated.

### The header fields, precisely

| Packet | `seq` | `ack` | Accepted when |
|:---|:---|:---|:---|
| SYN (ours) | `cookie` | 0 | sent unconditionally |
| SYN-ACK (theirs) | `server_seq` | `cookie + 1` | `ackno == cookie + 1` |
| ACK + probe (ours) | `cookie + 1` | `server_seq + 1` | sent after an accepted SYN-ACK |
| ACK + banner (theirs) | `server_seq + 1` | `cookie + 1 + payload_len` | `ackno == cookie + payload_len + 1` |
| RST (ours) | the banner's `ackno` | the banner's `seq + 1` | sent after a banner |

All comparisons are 32-bit unsigned, so a cookie near `2^32 - 1` wraps correctly.

The banner condition is worth restating. We sent `payload_len` bytes starting at sequence
`cookie + 1`, so the next byte the server expects is `cookie + 1 + payload_len`. Its
`ackno` is exactly that. The check therefore verifies three things at once: the packet
belongs to this connection, the server received all of our data, and the number of bytes we
think we sent matches what the probe actually constructed.

## Why the payload rides the third ACK

A TCP ACK is allowed to carry data. Sending `ACK + payload` in one segment means the
handshake and the request cost a single packet, and it means the server processes the
request the moment the connection is established. There is no round trip of "complete the
handshake, then send".

This is an optimisation with a price: the third ACK is generated on the handler thread
from the SYN-ACK, not on the transmitter thread, so the probe payload must be reconstructible
at that point. The probe exposes two functions, `make_payload` (used here) and
`get_payload_length` (used on the receive path for validation), and the two must return the
same length for the same target. If they disagree, every banner is silently dropped rather
than misclassified.

`--with-ack` inserts a bare ACK before the data segment, producing a textbook three-way
handshake and then the payload. It costs one extra packet per target. It exists because
some servers (the module documentation is candid that this is not well understood) appear to
accept only that shape of connection, and because it was the early form of ZBanner; in the
current code it is a research switch, not an optimisation.

## Closing, or not closing

After the first data segment the default behaviour is to send a RST. Because no TCB exists,
the RST is not "cleanup" — it is the only thing that tells the server the conversation is
over. If the RST is filtered somewhere along the path, the server keeps a half-open or
established connection and may retransmit its banner; that is why slow scan rates can look
like the target is chatty.

`--no-rst` suppresses the RST and leaves the server holding the connection until it times
out. It is a research switch: useful for observing what a target does after a banner, not
useful for a census.

`--all-banner` is the other direction: instead of closing after one segment, ZBanner
acknowledges each data segment (`ack = seqno_them + app_length`) and keeps reading.
`--all-banner-limit` caps the number of segments, `--all-banner-floor` suppresses results
from segments below a threshold. The segment index used by these two knobs is the dedup
repeat counter, not a sequence-number-derived counter, which is an approximation (see
limitations).

## Usage

ZBanner requires a TCP-type probe module — something that can produce bytes and interpret
a response. The module flags go through `--scan-arg`, the probe flags through `--probe-arg`.

```bash
# Linux: stop the kernel from resetting connections it does not know about
./firewall/add_rules.sh

# Grab a banner with an HTTP request
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http -show info

# A TLS ClientHello without a full handshake; ServerHello is parsed for fingerprints
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan zbanner -probe tls-hello -show info

# Read every banner segment, not just the first
sudo ./bin/xtate -ip 10.0.0.0/24 -p 80 -scan zbanner -probe http \
  -scan-arg '--all-banner --all-banner-limit 8' -show info

# A textbook handshake before the payload (research; one extra packet per target)
sudo ./bin/xtate -ip 10.0.0.0/24 -p 22 -scan zbanner -probe hello \
  -scan-arg '--with-ack'

./firewall/rm_rules.sh
```

`--show info` is usually necessary: ZBanner tags its results `info`-level, and `info` output
is hidden by default. `-p` accepts `80,443,8000-8100` and the `u:`/`s:`/`o:` prefixes for
non-TCP protocols.

## Before you scan: suppress the kernel

ZBanner's packets describe connections the local kernel knows nothing about. When a
SYN-ACK or a banner arrives at a source port the kernel considers closed, it will send a
RST to the target — killing the very connection ZBanner is trying to use. The scanner
cannot prevent this from inside the process; it must be prevented at the firewall:

```bash
./firewall/add_rules.sh   # drop outgoing RST and ICMP port-unreachable
./firewall/rm_rules.sh    # remove the rules afterwards
```

The rules are global: while they are installed, **every** application on the host loses
outgoing RST, so abnormal connections from browsers or SSH cannot be reset cleanly. Remove
the rules when the scan ends. The scripts are Linux-only; on Windows there is no equivalent
bundled helper, and you are on your own to arrange it. Both ZBanner and
[HLTCP](./hltcp.md) need this.

## Reading the results

| `classification` | `reason` | Meaning |
|:---|:---|:---|
| `open` | `syn-ack` | The port answered the SYN; the probe payload was sent. |
| `fake-open` | `zerowin` | SYN-ACK with a zero window. Often a SYN-proxy or a full backlog; no payload is sent. |
| `closed` | `rst` | The port answered with RST — unless `--record-ack` swallowed it, see below. |
| `responsed` | `ack with data` | Fallback when the probe module set no classification. |

A single target can produce several rows: `open` from the SYN-ACK, one row per banner
segment, and an `acknowledged` row if `--record-ack` is enabled. Merging those rows into
one record per target is the consumer's job — doing it inside ZBanner would require exactly
the per-target state it was built to avoid.

## What ZBanner is not

| | masscan / zmap SYN scan | ZBanner |
|:---|:---|:---|
| SYN sequence number | random, not verifiable | a keyed cookie, verifiable on receipt |
| On SYN-ACK | accept, record, RST | verify, complete the handshake, send the probe |
| Application data | none — the connection never exists | carried on the third ACK |
| Connection state | none | none (the peer holds it) |
| Result | open / closed | open / closed plus real banner bytes |

The comparison with [HLTCP](./hltcp.md) is different in kind. ZBanner asks one question and
reads the first answer; HLTCP keeps a conversation. ZBanner can send a ClientHello and parse
the plaintext ServerHello, but it cannot complete a TLS 1.3 handshake, cannot follow a
multi-segment certificate chain, and cannot send a second request. When you need that, use
`-scan tcp-state`. When you need a census, ZBanner is the only one of the two that scales
without a table.

## Known limitations

- **No per-target timeout and no retransmission.** A dropped SYN is a missing result; a
  dropped banner segment is a missing banner. `--repeat-synack`, `--repeat-banner`,
  `--repeat-ack` and `--repeat-rst` re-emit results that arrive more than once, but nothing
  re-sends a packet that never arrived.
- **Deduplication is approximate.** It is a 4-way bucket table with random eviction, sized
  by `--dedup-win`. Under high fan-out from one address block, entries are evicted and the
  repeat counter becomes unreliable — which also degrades `--all-banner` bookkeeping.
- **`--record-ack` can hide closed ports.** A closed port answers with `RST|ACK`. With
  `--record-ack` enabled, the ACK branch can consume it before the RST branch sees it, and
  because the ACK branch requires `ackno == cookie + payload_len + 1`, a non-empty probe
  payload makes the check fail and the packet is dropped. Leave `--record-ack` off for
  closed-port census.
- **Zero window is always reported as `fake-open`.** A real service whose accept queue is
  full also advertises a zero window; such a target is classified but its banner is never
  requested.
- **One banner segment by default.** The non-SYN template advertises a 1024-byte window
  and the connection is RST immediately after the first data segment, so large banners and
  multi-segment TLS handshakes are truncated. Use `--all-banner` and tune `--tcp-win`,
  `--max-packet-len` and `--snaplen`.
- **No out-of-order handling.** Segments are processed in arrival order; there is no
  reassembly queue and no re-sorting.
- **Payload size is bounded by the packet buffer.** A probe payload that does not fit is
  not sent, and the failure is silent.
- **Single receiver.** Deduplication and validation run on the one receive thread, so
  receive-side processing is the throughput ceiling regardless of how many transmitters or
  handlers you configure.

The full list, including the transport-layer and platform caveats, is in
[known-limitations.md](./known-limitations.md). For choosing between ZBanner and the
stateful engine, see [scanning-modes.md](./scanning-modes.md) and
[hltcp.md](./hltcp.md).
