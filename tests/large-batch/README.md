# Local large-batch regression

This test exercises real scan and output paths with a large result volume while
keeping **all traffic inside a dedicated Docker bridge network**. It never scans
the Internet.

Default workload:

- 5 target containers x 100 address aliases = **500 target IPs**
- ports `8080,1-19` = **20 endpoints per target**
- **10,000 expected results** (500 open, 9,500 closed)
- output modules: `ndjson`, `csv`, `bson`, `text`
- receive handler counts: 1 and 4

## Requirements

- Docker
- A Linux `xtate` binary (`XTATE_BIN`)
- The builder image used by the other lab tests (`XTATE_LAB_IMAGE`, default
  `xtate-builder:24.04`)

On Windows, run through Git Bash.

```powershell
$env:XTATE_BIN = "C:\path\to\xtate-linux"
$env:XTATE_LAB_IMAGE = "xtate-builder:24.04"
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /c/path/to/xtate && bash tests/large-batch/run.sh"
```

## What is verified

- `ndjson`: exactly one JSON object per result; parses every line; open/closed
  split matches the expected 500 / 9,500.
- `csv`: one header plus one row per result.
- `bson`: non-empty binary stream (full BSON parsing is left to the consumer).
- `text`: one line per result.
- Multi-handler path (`-rx-handler-count 4`) produces the same count.
- Target address aliases and the isolated Docker subnet are created
  dynamically, so the test does not collide with other local labs.

## Why not 1,000 targets by default?

The local Docker bridge starts dropping/evicting neighbor entries when a single
run addresses roughly 1,000 aliases on this host; that is a test-environment
ARP/neigh limit, not an xtate result bug. The default is kept at 500 targets /
10,000 results so the assertion is deterministic. Increase `BATCH_BLOCKS` and
`BATCH_ALIASES` when testing on a host with a larger neighbor table.

## Failure injection and memory

The first version focuses on count/schema/flush correctness. Planned follow-ups:

- open output file descriptor / `/dev/full` write failures
- Mongo disconnect
- RSS high-water measurement
- SIGINT during a large scan
