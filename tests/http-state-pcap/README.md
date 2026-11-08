# HTTP-state recorded pcap matrix

`httpstate.pcap` is a small, local-only capture of the server side of a
plaintext HTTP/1.0 exchange. It is replayed through the receive-only `file:`
adapter with the source/target addresses and seed used at capture time.

```bash
XTATE_BIN=/path/to/xtate bash tests/http-state-pcap/run.sh
```

This covers the stateful `tcp-state -probe http-state` path, including
keyword/header and no-match matching. TLS state cannot be replayed this way
without a TLS transcript simulator because ClientHello randomness is not
reproducible from the pcap alone.
