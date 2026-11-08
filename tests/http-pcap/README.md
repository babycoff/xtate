# HTTP offline matching matrix

Replays one synthesized HTTP response through `zbanner -probe http`. No
network, raw socket or target container is needed.

```bash
XTATE_BIN=/path/to/xtate bash tests/http-pcap/run.sh
```

Cases: body keyword, header regex, case-insensitive header keyword, and a
no-match result that still emits status/headers/body.
