# QUIC state

**English** · [中文](zh-CN/quic-state.md)

`quic-state` is an optional stateful QUIC transport scanner. It sends and receives
raw IPv4/IPv6 UDP packets itself; ngtcp2 owns QUIC packet state and GnuTLS owns
TLS 1.3. Xtate retains control of source ports, L3/L4 headers, pacing, flow
budgets, timers and output.

It is not a browser QUIC client and it is not HTTP/3 yet. The first milestone
completes the QUIC/TLS handshake, emits certificate/version/ALPN evidence and
runs a state sub-probe. HTTP/3 and DoQ are application probes layered above this
transport.

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
- HTTP/3/QPACK and DoQ are not implemented in this first milestone.
- No cross-connection follow-up; use `close-state` or a future application probe.
- Flow table is global, hash-bucketed and mutex-protected in this milestone; do
  not use it as a high-rate benchmark yet.
- The scanner does not claim HTTP/3 merely because ALPN is `h3`.

## Validation

The local lab uses aioquic with a self-signed certificate:

```bash
bash tests/lab/run.sh
```

The `quic-state` case asserts `quic handshake`, ALPN, TLS 1.3 and certificate
fields. `tests/i18n/check_parity.py` checks the English/Chinese help.
