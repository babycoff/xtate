# Shared offline pcap toolkit

`lib.py` builds deterministic Ethernet/IPv4/IPv6 TCP or UDP packets and writes
classic pcap files for Xtate's receive-only `file:` adapter.

It is test-only and never transmits or captures. Typical use:

```python
import lib
with lib.PcapWriter("fixture.pcap") as out:
    out.add(lib.tcp(target_ip, target_port, source_ip, source_port,
                    server_seq, cookie + 1,
                    lib.TCP_SYN | lib.TCP_ACK), 1.0)
    out.add(lib.tcp(target_ip, target_port, source_ip, source_port,
                    server_seq, 0,
                    lib.TCP_SYN | lib.TCP_ACK), 1.2)  # invalid trailer
```

The cookie helpers match Xtate's IPv4/IPv6 SipHash cookie inputs. The trailer is
important: a pcap savefile reaches EOF immediately after its last record and the
receive thread can otherwise finish before the last valid packet is dispatched.

Suites using this library:

- `tests/zbanner/` — full ZBanner matrix;
- `tests/http-pcap/` — HTTP keyword/regex/scope matching;
- `tests/tcp-syn-pcap/` — SYN-ACK/RST basics.

## Synthetic and recorded fixtures

Prefer synthetic fixtures for protocol invariants (flags, cookies, ACK numbers,
malformed tails). For protocols where reproducing a full server flight is
impractical, a small checked-in capture is acceptable: record it once with the
server scoped to a test address, keep only the packets needed by the receive
path, and replay it with fixed `--source-ip`, source port and seed. Do not
commit captures containing public Internet peers or credentials.
