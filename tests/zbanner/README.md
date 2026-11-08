# ZBanner offline regression matrix

This suite replays generated pcap files through Xtate's receive-only
`file:` adapter. It needs no network, raw-socket privilege, target container or
firewall rules.

```bash
XTATE_BIN=/path/to/xtate-linux bash tests/zbanner/run.sh
```

For a container without root privileges:

```bash
docker run --rm --network none \
  -v "$PWD/bin/xtate-linux:/xtate:ro" \
  -v "$PWD:/src:ro" \
  xtate-builder:24.04 \
  bash -lc 'cp -a /src/. /work && cd /work && \
            find tests -name "*.sh" -exec sed -i "s/\r$//" {} + && \
            XTATE_BIN=/xtate bash tests/zbanner/run.sh'
```

The image needs Python 3 for the fixture generator. Add it if the image does not
ship it.

## Fixtures

| Case | Expected |
|:---|:---|
| `synack` | open / syn-ack |
| `rst` | closed / rst |
| `banner` | responsed / ack with data, HTTP 200 |
| `retrans` | `banner idx: 0` then `banner idx: 1` in all-banner mode |
| `all2` | two results, second has `truncated: 1` |
| `wrongack` | open only; wrong ACK number is not a banner |
| `mismatch` | Lua declares 1 byte, emits 4; actual length validates the banner |
| `ipv6` | IPv6 SYN-ACK and banner path |
| `zerowin` | zero-window SYN-ACK -> fake-open |
| `floor2` | all-banner floor 2 suppresses the first segment |

`mismatch` requires the `lua-tcp` probe and is skipped when it is not built.
`ipv6` uses `2001:db8::1`/`2001:db8::2`; the TCP cookie is the IPv6 SipHash
variant. `zerowin` uses a zero TCP window; no banner ACK is exercised.

Every fixture ends with an invalid trailer packet. A pcap savefile reaches EOF
immediately after its last record; without the trailer the receive thread can
finish before the last valid packet is dispatched and the test becomes racy.

## HTTP payload length

The HTTP fixtures use:

```text
-probe http -probe-arg '--user-agent=a'
```

With the current request builder this is exactly 47 bytes (the request includes
the trailing NUL byte). `make_fixture.py --payload-len 47` computes the banner
ACK number from that length. If the HTTP request builder changes, update the
fixture constant and the test will fail loudly rather than silently accepting a
wrong ACK.
