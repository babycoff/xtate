# UDP echo pcap matrix

Replays a UDP echo response containing Xtate's 4-byte scan cookie, plus an
invalid response. Uses `-show success` because the echo result is an explicit
success-level item.

```bash
XTATE_BIN=/path/to/xtate bash tests/udp-pcap/run.sh
```
