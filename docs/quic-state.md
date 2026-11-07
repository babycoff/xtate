# QUIC state

**English** · [中文](zh-CN/quic-state.md)

`quic-state` is an optional stateful QUIC transport scanner. It sends and receives
raw IPv4/IPv6 UDP packets itself; ngtcp2 owns QUIC packet state and GnuTLS owns
TLS 1.3. Xtate retains control of source ports, L3/L4 headers, pacing, flow
budgets, timers and output.

It is not a browser QUIC client. The transport milestone completes the
QUIC/TLS handshake, emits certificate/version/ALPN evidence and runs a state
application probe. An HTTP/3 request probe (`http3-state`) is included as the
first real child; DoQ remains a later application probe.

## Build

```bash
sudo apt install libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev
./build.sh --compiler gcc --config release
```

CMake option:

```bash
-DWITH_NGTCP2=OFF   # remove quic-state from the build
```

`WITH_NGTCP2=ON` is the default; if ngtcp2/GnuTLS or pkg-config is missing,
the module is simply absent. A normal build does not require ngtcp2.

## Platform support

| Platform | quic-state | http3-state | Notes |
|:---|:---:|:---:|:---|
| Linux (GCC/Clang) with ngtcp2 + GnuTLS | supported | supported | Reference build and lab |
| Windows MSVC | **not supported** | **not supported** | GnuTLS is not available for native MSVC; modules are absent from the build |
| Windows MinGW/MSYS2 | not tested | not tested | Possible future path, not a supported configuration |

**Windows TODO:** add an ngtcp2 OpenSSL backend and CMake discovery for
`vcpkg install ngtcp2[openssl]:x64-windows`; the current implementation uses
GnuTLS directly and cannot be built with MSVC. Until that work lands, Windows
MSVC builds simply do not register `quic-state` or `http3-state`.

## Architecture

```text
target / source port
  -> ngtcp2_conn_writev_stream()       # QUIC UDP payload
  -> udp_create_packet()               # IPv4/IPv6 + UDP + Ethernet
  -> Xtate raw socket / NetStack
  -> pcap receive
  -> strip IP/UDP
  -> ngtcp2_conn_read_pkt()
  -> TLS handshake + certificate
  -> state sub-probe
```

The flow table is currently a bounded hash table with one global mutex; it is a
first milestone, not the final high-rate design. A later revision should move
flows to per-worker hashed tables, remove the global lock and add a raw-packet
send path for timer retransmits that does not depend on the TX thread's stack
flush.

## Minimal use

```bash
# HTTP/3 request
xtate -ip 192.0.2.10 -p U:443 -scan quic-state -probe http3-state \
  -scan-arg "--alpn h3" --wait 5 --no-status -show info

# Certificate/version evidence only
xtate -ip 192.0.2.10 -p U:443 -scan quic-state -probe close-state \
  -scan-arg "--alpn h3 --sni example.test" --wait 5 --no-status -show info

# Check the module is present
xtate --list-scan | grep quic-state
```

The probe must be a `state` probe; `close-state` is the certificate-only probe.

## Options

| Option | Default | Meaning |
|:---|:---|:---|
| `--alpn` | `h3` | ALPN list; the first comma/space token is used. |
| `--sni` | none | TLS SNI host name. |
| `--max-flows` | `100000` | Concurrent flow budget. |
| `--flow-timeout` | `30` | Scanner flow lifetime in seconds. |
| `--max-udp-payload` | `1200` | QUIC UDP payload size (1200..65527). Also advertised as `max_udp_payload_size`. |
| `--handshake-timeout` | `10` | Total QUIC handshake timeout in seconds. |
| `--initial-rtt` | `100` | Initial RTT in ms for loss timers; not a measured RTT. |
| `--max-data` | `1048576` | Advertised connection flow-control limit. |
| `--max-stream-data` | `131072` | Advertised per-stream limit. |
| `--max-streams` | `3` | Advertised unidirectional stream count. |
| `--idle-timeout` | `30000` | Advertised idle timeout in ms. |
| `--cc-algo` | `reno` | `reno`, `cubic`, `bbr` or `bbr2`. |
| `--no-cert` | off | Skip certificate parsing/output. |

## Output fields

Successful handshake results use classification `quic handshake` and include:

- `quic_version`
- `quic_tls_version`
- `quic_alpn`
- `quic_cert_subject`
- `quic_cert_issuer`
- `quic_cert_sha256`

Certificate verification is intentionally disabled for scanning; the fields are
evidence, not a trust decision.

## Deliberate limits

- QUIC v1 only.
- No 0-RTT, session resumption, migration, multipath or connection migration.
- Single connection per target; no long-lived sessions.
- HTTP/3 supports configurable methods, request headers/body, Huffman QPACK
  string literals and the full QPACK static table.
- Dynamic QPACK, push, server-initiated streams and HTTP/3 CONNECT are not
  supported. Dynamic QPACK references are rejected and marked with
  `http3_qpack_partial` rather than guessed.
- DoQ is not implemented in this milestone.
- No cross-connection follow-up; use `close-state` or a future application probe.
- Flow table is global, hash-bucketed and mutex-protected in this milestone; do
  not use it as a high-rate benchmark yet.
- The scanner does not claim HTTP/3 merely because ALPN is `h3`.
- Windows MSVC is explicitly unsupported for `quic-state`/`http3-state` in this
  milestone; see the platform table and TODO above.

## HTTP/3 child probe

`http3-state` opens the client control and QPACK streams, sends one request on
a client bidirectional stream, and parses response HEADERS/DATA. Output uses
classification `http3` and includes `http3_status`, `http3_header_count`,
`http3_body_len`, `http3_body_total`, optional `http3_body`, and structured
`http3_header_<n>_name` / `http3_header_<n>_value` fields (plus
`http3_content_type`, `http3_server`, `http3_location` shortcuts). The same
item also carries `quic_version`, `quic_tls_version`, `quic_alpn` and the
certificate fields.

Supported request options: `--path`, `--authority`, `--method`,
`--header`, `--content-type`, `--data`, `--data-file`, `--max-body`,
`--max-headers`, `--record-body`, `--record-headers`.

Response matching uses `--keyword`/`--regex` with `--match-scope all|headers|body`;
see [HTTP response matching](./matching.md). Huffman string literals and the full
QPACK static table are decoded. Dynamic
QPACK is deliberately disabled: the client advertises a zero-capacity QPACK
table, and a server reply that still requires a dynamic insertion is reported
as `http3_qpack_partial: 1` rather than being treated as fully decoded.

## Validation

The local lab uses aioquic with a self-signed certificate:

```bash
bash tests/lab/run.sh
```

The `quic-state` case asserts `quic handshake`, ALPN, TLS 1.3 and certificate
fields. `tests/i18n/check_parity.py` checks the English/Chinese help.
