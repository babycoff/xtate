# 07 · Protocols and HTTP/3

This chapter explains how Xtate probes application protocols, what is
implemented today, and how the HTTP/3 and QUIC path differs from the rest of
the scanner. It is the reference for the protocol questions that come up in
lab work: which probe to use, what the probe actually sends, what the result
fields mean, and which parts are deliberately out of scope.

The short version:

- Every protocol is a **probe module**. Probes have a type (`tcp`, `udp` or
  `state`) and must be paired with a scan engine that speaks that type.
- HTTP/1.1 and HTTP/2 work on Linux and Windows.
- HTTP/3 and the QUIC transport layer are **Linux-only**, built only when
  ngtcp2 and GnuTLS are present. Windows keeps the capability probe and
  reports the transport as unsupported.
- `--list-capabilities` is the machine-readable answer to "does this build
  have QUIC transport?" — use it instead of guessing from the module list.

## How a protocol probe is selected

A scan command always selects a scan engine with `-scan`. Engines that carry
application data also need a probe selected with `-probe`:

```bash
xtate -ip <targets> -p <ports> -scan <engine> [-probe <probe>] [args]
```

The pairing is checked at startup. A probe declares one of three types:

| Probe type | Paired with | Shape of the exchange |
|:---|:---|:---|
| `tcp` | `zbanner` (and stateless TCP scans) | One request, one reply, no per-target state |
| `udp` | `udp` | One datagram request, one datagram reply |
| `state` | `tcp-state` (HLTCP) | Full TCP/TLS conversation with a user-space TCB |

A mismatch is a startup error, not a silent fallback:
`ScanModule <name> needs probe of <type> type.` Use `--list-probe` to see each
probe's type, and `--help-probe <name>` for the parameters that probe accepts.
Probe-specific arguments are passed as one quoted string:

```bash
-probe-arg "--sni example.com --alpn h2,http/1.1"
```

Protocol-aware probes emit **structured fields** (versions, selected
algorithms, status codes, server identity) in addition to raw bytes. The
generic `null` and `hello` probes are not protocol-aware: they capture bytes
and classify the response, nothing more.

## Coverage at a glance

The table lists the protocols with a dedicated probe in this tree. The full module reference is
[05 · Modules and parameters](./05-modules-and-parameters.md); the deep protocol matrix lives in
[Protocol coverage plan](../protocol-coverage.md).

| Protocol | Probe(s) | Type | Notes |
|:---|:---|:---|:---|
| HTTP/1.1 | `http`, `http-state` | `tcp`, `state` | Structured status/headers/body metadata; stateful variant inside HLTCP |
| HTTP/2 | `h2c`, `h2` | `tcp`, `state` | `h2c` is cleartext prior knowledge; `h2` runs inside `tls-state` with ALPN `h2` |
| HTTP/3 | `http3-state` (probe) on `quic-state` (scan) | `state` | Linux + ngtcp2/GnuTLS only |
| QUIC transport | `quic` (capability), `quic-state` (transport) | `udp`, `state` | `quic` classifies a server's Initial response; `quic-state` completes handshakes |
| TLS | `tls-state`, `tls-hello` | `state`, `tcp` | Certificates, ALPN, SNI, version, cipher |
| JARM | `jarm` | `tcp` | Salesforce 1.0 TLS fingerprint |
| DNS | `dns` | `udp` | Plain DNS over UDP |
| DoT | `dot` | `state` | Inside `tls-state` with ALPN `dot` |
| DoH | `doh`, `doh-h2` | `state` | HTTP/1.1 or HTTP/2 inside `tls-state` |
| SSH | `ssh`, `ssh-kex` | `tcp`, `state` | Banner/software; unauthenticated curve25519 KEX |
| SMTP/IMAP/POP3/FTP/ManageSieve | `*-state` | `state` | Plaintext or post-TLS flow |
| Databases and services | `mysql`, `postgres`, `mongodb`, `redis`, `memcached`, `mqtt`, `socks5`, `telnet`, `ntp`, `ipp`, `amqp`, `pptp` | `tcp`/`udp`/`state` | Identification only |

`tls-hello` is a stateless probe that reads a ServerHello without completing a
handshake. It is useful for a quick version/cipher check but cannot produce
certificates or an ALPN decision.

## HTTP/1.1

Two probes cover HTTP/1.x:

- **`http`** — a stateless `tcp` probe. It sends one request and parses the
  first response segment. This is the probe for Internet-scale banner work.
- **`http-state`** — a `state` probe running inside HLTCP. It sends a request
  over a real TCP connection and can carry TLS through `tls-state`.

Both share the structured parser added in the first rewrite pass: status code,
reason phrase, HTTP version, response headers, `Content-Length`, and bounded
body/chunked metadata. Raw bytes and the classic banner/regex fields remain
available, so existing workflows keep working.

The default request is:

```text
GET / HTTP/1.0
User-Agent: xtate/<version> <project URL>
Accept: */*
```

Useful request parameters (see `--help-probe http` for the full list):

| Option | Meaning |
|:---|:---|
| `--method` | Replace `GET` (for example `POST`) |
| `--url` | Replace the request path |
| `--version` | Replace `HTTP/1.0` |
| `--host` | Add a `Host` header |
| `--dynamic-host` | Set `Host` to the target IP per target |
| `--user-agent` | Replace the `User-Agent` header |
| `--header Name:value` | Add or replace a header |
| `--remove Name` | Remove the first matching default header |
| `--cookie` | Add a `Cookie` header |
| `--payload` | Append a request body (adds `Content-Length`) |
| `--no-record-status`, `--no-record-headers` | Suppress parsed fields |
| `--record-body`, `--max-body` | Record the parsed body, bounded (default 4096 bytes) |
| `--keyword`, `--regex`, `--match-scope` | Match against `all`, `headers` or `body` |

A stateless HTTP request looks like this:

```bash
xtate -ip 198.51.100.10 -p 80 -scan zbanner -probe http \
  -probe-arg "--host example.com --user-agent xtate-manual" -show info
```

The same request through a stateful connection, including TLS:

```bash
xtate -ip 198.51.100.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -sni example.com -alpn http/1.1 \
              -subprobe-arg '--host example.com --record-body'" -show info
```

Two limits are intentional rather than bugs:

- `http` sees one response segment. It cannot reassemble a chunked body that
  spans segments without per-target state, which would contradict the
  stateless design; it reports the first-segment status/headers and the
  captured bytes instead of claiming a complete body.
- `http-state` is stateful transport plus banner/segment collection, not a full
  HTTP/1.1 conversation parser. A bounded chunked decoder is possible there
  and is tracked as follow-up work, but it is not enabled by default.

HTTP/1 request building is still duplicated between the two probes. That is an
internal maintenance issue (a fix can drift between probes), not a protocol
difference visible in results.

## HTTP/2

HTTP/2 support is deliberately split along the same line as HTTP/1:

- **`h2c`** is a `tcp` probe that sends the HTTP/2 client preface, a
  configurable SETTINGS frame and an optional PING, then reports the server's
  frame headers, SETTINGS entries and optionally raw frames. It is cleartext
  HTTP/2 with prior knowledge — not HTTP/2 over TLS.
- **`h2`** is a `state` probe used *inside* `tls-state` with ALPN `h2`. It runs
  in HLTCP, sends the preface, SETTINGS and a minimal HPACK request, then
  parses SETTINGS, HEADERS (static table plus HPACK, including Huffman-coded
  response headers) and DATA. Response matching supports the same keyword and
  regex machinery.

The TLS composition is explicit, because HLTCP must complete the handshake and
negotiate `h2` before the probe can speak HTTP/2:

```bash
xtate -ip 198.51.100.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe h2 -sni example.com -alpn h2" -show info
```

Neither probe is a silent fallback to HTTP/1. If ALPN does not select `h2`, the
composition fails; use `-probe-arg "-fail-handshake"` on `tls-state` if you
want handshake failures promoted to the `failed` level.

## HTTP/3 and QUIC

HTTP/3 is the one protocol area with a platform split, and the manual states it
plainly:

| Platform | QUIC transport (`quic-state`) | HTTP/3 (`http3-state`) |
|:---|:---|:---|
| Linux, GCC/Clang, ngtcp2 + GnuTLS present | supported | supported |
| Windows, MSVC | **not supported** | **not supported** |
| Windows, MinGW/MSYS2 | not tested, not supported | not tested, not supported |

On Windows there is no native ngtcp2/GnuTLS build path, so the two modules are
simply absent from the catalog. The capability probe and
`--list-capabilities` report this explicitly instead of failing later with a
confusing module error.

### How the QUIC path is built

`quic-state` is a stateful transport scanner, not a browser QUIC stack. Xtate
itself sends and receives raw IPv4/IPv6 UDP; **ngtcp2** owns the QUIC packet
state; **GnuTLS** provides TLS 1.3. Xtate keeps the parts that matter for
measurement: source ports, L3/L4 headers, pacing, flow budgets, timers and
output. The pipeline is:

```text
target/source tuple
  -> ngtcp2_conn_writev_stream()      (QUIC UDP payload)
  -> udp_create_packet()              (IPv4/IPv6 + UDP + Ethernet)
  -> raw socket / NetStack
  -> pcap receive -> strip IP/UDP
  -> ngtcp2_conn_read_pkt()           (TLS handshake, certificate)
  -> state sub-probe (http3-state)
```

The flow table is bounded and guarded by one global mutex in the first
milestone. Treat `quic-state` as a correctness-first transport: it is not yet a
high-rate benchmark target.

Build dependencies on a Debian/Ubuntu host:

```bash
sudo apt install libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev
./build.sh --compiler gcc --config release
```

`WITH_NGTCP2` defaults to `ON`. Configure with `-DWITH_NGTCP2=OFF` to remove the
modules, and expect them to be absent when ngtcp2/GnuTLS or pkg-config is
missing. A normal build without these packages is fully supported — it just
does not register `quic-state`/`http3-state`.

### Using `quic-state` and `http3-state`

Check that the module exists:

```bash
xtate --list-scan      # quic-state appears only in an ngtcp2/GnuTLS build
```

A certificate-only probe of a QUIC endpoint:

```bash
sudo xtate -ip 192.0.2.10 -p U:443 -scan quic-state -probe close-state \
  -scan-arg "--sni example.com" -show info
```

A full HTTP/3 request:

```bash
sudo xtate -ip 192.0.2.10 -p U:443 -scan quic-state -probe http3-state \
  -scan-arg "--alpn h3" -probe-arg "--path / --authority example.com" \
  --wait 5 --no-status -show info
```

Key `quic-state` options (`--help-scan quic-state`):

| Option | Meaning |
|:---|:---|
| `--alpn` | ALPN list; default `h3`, first token used |
| `--sni` | TLS server name; none by default |
| `--max-flows` | Maximum concurrent flows (default 100000) |
| `--flow-timeout` | Flow timeout in seconds (default 30) |
| `--max-udp-payload` | Advertised max UDP payload, 1200–65527 (default 1200) |
| `--handshake-timeout` | Handshake timeout in seconds (default 10) |
| `--initial-rtt` | Initial RTT estimate, for example `100ms` |
| `--max-data`, `--max-stream-data`, `--max-streams` | Flow-control limits |
| `--idle-timeout` | Idle timeout in milliseconds |
| `--cc-algo` | Congestion control: `reno`, `cubic`, `bbr` or `bbr2` |
| `--no-cert` | Skip certificate capture |

`http3-state` accepts `--path`, `--authority`, `--method`, `--header`,
`--content-type`, `--data`, `--data-file`, `--max-body`, `--max-headers`,
`--record-body` and `--record-headers`. Matching uses the standard
`--keyword`/`--regex` plus `--match-scope all|headers|body`.

Output fields from a successful QUIC handshake:

```text
quic_version  quic_tls_version  quic_alpn
quic_cert_subject  quic_cert_issuer  quic_cert_sha256
```

and from an HTTP/3 request:

```text
http3_status  http3_header_count  http3_body_len  http3_body_total
http3_header_<n>_name / http3_header_<n>_value
http3_content_type  http3_server  http3_location
```

Certificate verification is intentionally disabled: the certificate is
evidence about the endpoint, not a trust decision. There is no SNI-based
hostname validation either, so read the fields as observations of what the
peer presented.

### QUIC and HTTP/3 limits

These are the current boundaries, not roadmap promises:

- QUIC **version 1 only**.
- No 0-RTT, session resumption, connection migration or multipath.
- One connection per target; no cross-connection follow-up.
- HTTP/3 supports configurable methods, request headers/body, Huffman QPACK
  string literals and the full QPACK static table.
- Dynamic QPACK table updates, server push, server-initiated streams and
  HTTP/3 CONNECT are not implemented. A response that requires dynamic
  insertion is marked `http3_qpack_partial: 1` instead of being silently
  mis-decoded.
- No DNS over QUIC (DoQ) yet, and no DoH over HTTP/3.
- A QUIC handshake response alone is not HTTP/3 success; the classification
  distinguishes `quic handshake` from `http3`.
- Windows (MSVC) is explicitly unsupported; do not treat the absence of
  `quic-state` as a packaging bug.

## Capability reporting with `--list-capabilities`

Any client that needs to know what the binary can do should ask it:

```bash
xtate --list-capabilities
```

The command prints one JSON object and exits `0`, without starting a scan. The
object reports the build's platform, whether raw sockets are available, whether
zstd result compression and the QUIC transport/HTTP/3 are compiled in, the
reason when HTTP/3 is not, and the module counts. Abridged shape (the version and the counts are
build-specific):

```json
{
  "version": "<build version>",
  "platform": "linux",
  "raw_sockets": true,
  "zstd": true,
  "http3": true,
  "quic_transport": true,
  "http3_reason": null,
  "modules": {"scan": 12, "probe": 60, "output": 7, "generate": 5}
}
```

(Counts are build-specific; the values above are a full Linux build.)

When the transport is not compiled in, both booleans are `false` and
`http3_reason` is a string:

- Windows: `"HTTP/3 requires ngtcp2/GnuTLS; not built for Windows"`
- other platforms: `"HTTP/3 requires ngtcp2/GnuTLS; not present in this build"`

Use `platform` and `http3`/`quic_transport` rather than inferring support from
`--list-scan` output: a module can be absent for several reasons, while the
capability object states the build decision directly. If the module catalog
cannot be read, the command fails with `xtate: cannot read module catalog` and
a non-zero exit instead of printing a partial object.

`raw_sockets` is currently reported as `true` on every supported build; raw
socket use still requires the operating-system privilege described in chapter
01.

## DNS over TLS and DNS over HTTPS

DoT and DoH are **state sub-probes**: TLS is owned by `tls-state`, and the
sub-probe only speaks the DNS mapping inside the TLS channel.

```text
DoT:  tcp-state -> tls-state (ALPN dot)      -> dot
DoH:  tcp-state -> tls-state (ALPN http/1.1) -> doh
      tcp-state -> tls-state (ALPN h2)       -> doh-h2
```

DNS over TLS (`dot`, RFC 7858) sends one length-prefixed DNS query and parses
the response:

```bash
sudo xtate -ip 203.0.113.10 -p 853 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe dot -alpn dot -sni dns.example \
              -subprobe-arg '--req-name=example.com --dnssec'" -show info
```

Options: `--req-name` (required), `--req-type` (default `A`),
`--recursive-desired`, `--dnssec` (EDNS0 DO=1), `--edns-size` (default 1232).
Output: `dot_dns_len`, `dot_rcode`, `dot_ad`, `dot_answer`,
`dot_rrsig_count`, `dot_dnskey_count`, `dot_ds_count`, `dot_nsec_count`,
`dot_dnssec_present`.

DNS over HTTPS (`doh` for HTTP/1.1, `doh-h2` for HTTP/2 — the normal public
deployment) carries the raw DNS message as the HTTP body; there is no 2-byte
length prefix:

```bash
sudo xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe doh-h2 -alpn h2 -sni dns.example \
              -subprobe-arg '--dns-name=example.com --authority=dns.example \
                             --path=/dns-query'" -show info
```

`doh` options: `--req-name`, `--req-type`, `--doh-path` (default
`/dns-query`), `--doh-host`, `--dnssec`, `--edns-size`. `doh-h2` uses
`--dns-name`, `--dns-type`, `--path`, `--authority` and `--dnssec`. Output
fields mirror DoT with a `doh_` prefix, plus `doh_status` and
`doh_content_type`.

Caveats for both:

- The `-alpn` value must match the transport you asked for. A server that does
  not negotiate `dot`, `http/1.1` or `h2` fails before the sub-probe runs.
- `*_dnssec_present` is deployment evidence (RRSIG/DNSKEY/DS/NSEC records
  observed), not a validated DNSSEC chain.
- Only one query/response is sent per connection.
- On Linux the RST/ICMP suppression rules are required before any of this can
  complete; see [09 · Troubleshooting](./09-troubleshooting.md).

## Stateful TLS and STARTTLS composition

`tls-state` is not an application probe. It is the TLS middle layer inside
HLTCP:

```text
tcp-state -> tls-state -> state sub-probe inside TLS
```

Two composition modes exist:

- **Implicit TLS** — the server speaks TLS immediately (SMTPS 465, IMAPS 993,
  POP3S 995, FTPS 990, MySQL/PostgreSQL/MongoDB TLS ports, or any TLS service):
  `tls-state` handshakes and starts the sub-probe inside TLS.
- **STARTTLS** — the connection starts in plaintext and upgrades
  (SMTP `EHLO`/`STARTTLS`, IMAP `STARTTLS`, POP3 `STLS`, FTP `AUTH TLS`,
  ManageSieve `STARTTLS`, PostgreSQL `SSLRequest`). `tls-state` consumes the
  plaintext greeting and upgrade response; the sub-probe starts after the
  handshake.

The sub-probe flag `--after-tls` does **not** enable TLS. It tells the
sub-probe's state machine that the plaintext greeting already happened (or that
it is already inside TLS) and to skip that phase:

```bash
# STARTTLS SMTP: tls-state handles the plaintext upgrade, then SMTP state runs
sudo xtate -ip 203.0.113.10 -p 25 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe smtp-state --starttls smtp \
              -subprobe-arg --after-tls -sni mail.example" -show info
```

Do not pass `--after-tls` on a plaintext direct scan: it skips a real server
greeting and the probe will fail or misparse. `mysql-state --after-tls` and
`managesieve-state --after-tls` are lab/compatibility wake-ups, not standard
handshakes; strict servers may reject them.

`tls-state` parameters include `--sni`, `--alpn`, `--version`, `--cipher`,
`--starttls <proto>`, `--subprobe <name>`, `--subprobe-arg "<args>"`,
`--dump-cert`, `--dump-cert-details`, `--dump-subject`, `--dump-version`,
`--dump-cipher`, `--fail-handshake`, `--graceful-tls-close` and
`--ssl-keylog`. Certificate details are evidence; the scanner does not decide
whether the certificate is trustworthy.

Two practical notes:

- `tls-state` sends **no SNI and no ALPN by default**. Virtual hosts and CDNs
  will often answer with a default certificate/site. Pass `--sni` when you know
  the hostname, and pass the ALPN you actually want (`h2,http/1.1`, `dot`,
  etc.). Without SNI, read the result as "default virtual host", not as the
  requested hostname.
- `tls-state` has no usable default sub-probe. Always pass `-subprobe` with a
  state-type probe, or the TLS session ends immediately.

## Raw sockets, link types, TUN and fake-IP

Xtate sends from raw sockets (`raw_sockets: true`). That is what makes
stateless handshakes and HLTCP possible, and it is why Linux needs the
firewall rules and why Windows needs Npcap with Administrator privileges.

The receive path accepts three pcap link types:

| Link type | Header | Consequence |
|:---|:---|:---|
| `EN10MB` (Ethernet) | Ethernet | Normal MAC/ARP; the preferred case |
| `NULL` | BSD loopback | Loopback captures |
| `RAW` | Raw IP | No Ethernet header, no MAC, no ARP |

TUN/VPN adapters commonly publish `198.18.0.0/15` (the RFC 2544 benchmarking
range) and answer DNS with fake addresses. Xtate still scans what it is given,
so resolve the real address first (for example through `--doh` or a resolver
outside the tunnel), then check the selected route and link type with
`--explain-target`:

```bash
xtate --explain-target=203.0.113.10 --check
```

The preflight prints the interface, link type, source address and gateway, and
warns when the link type cannot carry an IP scan. A `RAW` link is accepted but
may silently fail: no MAC/ARP means no L2 resolution, and some tunnel drivers
rewrite or drop packets. When you see an `UNSUPPORTED` link type, select the
physical Ethernet/Wi-Fi adapter explicitly with `-if`.

The `RAW` link-type reporting was introduced in 2.44.2; see
[release notes 2.44.2](../release-notes/2.44.2.md) for the details.

## What this chapter does not promise

A few boundaries are worth repeating so they are not mistaken for gaps in the
build:

- HTTP/3 and QUIC transport are Linux-only. On Windows the answer is
  `http3: false` and an explicit reason, not a hidden retry through TCP.
- There is no DNS over QUIC (DoQ) and no DoH over HTTP/3.
- The HTTP/1 parser is frozen at the current structured-parser pass; a full
  chunked HTTP/1.1 conversation parser is follow-up work, and the stateless
  probe never reassembles bodies across segments.
- Raw byte output is always available; protocol claims come from the
  structured fields and classifications, not from banner text.
- Nothing here bypasses authorization, rate limits or the firewall
  prerequisites.

See also:

- [Scanning modes](../scanning-modes.md) (deep reference for engines and probes)
- [Protocol coverage plan](../protocol-coverage.md)
- [QUIC state](../quic-state.md), [DoT](../dns-over-tls.md),
  [DoH](../dns-over-https.md), [TLS composition](../tls-composition.md)
- [HTTP probe audit](../http-probes-audit.md) for the parser scope
- [08 · Architecture and security](./08-architecture-and-security.md) for how
  the pieces fit together
- [09 · Troubleshooting](./09-troubleshooting.md) when a protocol probe returns
  only `open`
