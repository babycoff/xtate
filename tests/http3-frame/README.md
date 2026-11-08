# Decrypted HTTP/3 frame fixture

The `http3-state` probe has an embedded decrypted-frame fixture in
`src/probe-modules/http3-state-probe.c` (`h3_frame_selftest`). It parses:

```text
HEADERS type=1, length=3
  QPACK Required Insert Count = 0
  QPACK Delta Base = 0
  indexed static table entry 25 -> :status 200 (QPACK T=1 -> 0xD9) -> :status 200

DATA type=0, length=5
  hello
```

No QUIC/TLS handshake is involved. The fixture is run during `http3-state`
probe initialization and is also exercised by `tests/lab/ci-quic.sh`.

This is intentional: encrypted TLS/QUIC handshakes should not be replayed as
plain pcap; frame-level coverage gives deterministic QPACK/frame tests while
the local QUIC lab covers the handshake.
