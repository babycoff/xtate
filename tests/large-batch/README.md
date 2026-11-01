# Local large-batch regression

Two complementary tests:

- `run.sh` — real local network/target regression on an isolated Docker bridge.
- `replay.sh` — deterministic high-rate pcap replay through xtate's real receive,
  validation and output paths, with **no network at all** (`--network none`).

Neither test scans the Internet.

## Quick start

```bash
# live local targets (500 targets, 10,000 results)
XTATE_BIN=/path/to/xtate-linux bash tests/large-batch/run.sh

# deterministic high-rate replay (1,000 targets x 1,000 ports = 1,000,000 results)
XTATE_BIN=/path/to/xtate-linux bash tests/large-batch/replay.sh
```

On Windows, run through Git Bash:

```powershell
$env:XTATE_BIN = "C:\path\to\xtate-linux"
$env:XTATE_LAB_IMAGE = "xtate-builder:24.04"
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /c/path/to/xtate && bash tests/large-batch/replay.sh"
```

## Live-network test: `run.sh`

### Scale options

| Option | Meaning | Default |
|:---|:---|:---|
| `--blocks N` | number of target containers | 5 |
| `--aliases N` | address aliases per container | 100 |
| `--ports LIST` | ports per target, e.g. `80,1-19` | `80,1-19` |
| `--endpoints N` | endpoints per target; must match `--ports` | 20 |
| `--rate N` | scan rate, packets/second | 500 |
| `--out DIR` | output directory | `../reports/docker/out/large-batch` |
| `--bin PATH` / `--image IMAGE` | binary / builder image | `XTATE_BIN` / `xtate-builder:24.04` |

Targets are local Docker aliases. The default is:

- 5 containers × 100 aliases = **500 target IPs**
- 20 endpoints each = **10,000 results**
- 500 open ports / 9,500 closed ports
- output: ndjson, csv, bson, text
- handler counts: 1 for ndjson/text/bson, 4 for csv

Example, roughly 8x larger (make sure the Docker/ARP table can handle it):

```bash
XTATE_BIN=/path/to/xtate-linux bash tests/large-batch/run.sh \
  --blocks 8 --aliases 100 --ports '80,1-99' --endpoints 100 --rate 1000
```

That is 800 targets × 100 endpoints = **80,000 results**.

### Live-test limits

The local Docker bridge and neighbor/ARP table are the limiting factors. On this
host, about 1,000 address aliases in one live run starts to lose replies due to
neighbor-table pressure. That is a test-environment limit, not an xtate result
bug. For much larger deterministic workloads use `replay.sh` instead.

## High-rate replay: `replay.sh`

### Scale options

| Option | Meaning | Default |
|:---|:---|:---|
| `--targets N` | generated target IPs | 1,000 |
| `--ports RANGE` | inclusive port range, e.g. `1-1000` | `1-1000` |
| `--pps N` | pcap replay pacing, packets/second | 20,000 |
| `--handlers N` | receive handler count (power of 2) | 4 |
| `--dispatch-buf N` | dispatch queue size | 65,536 |
| `--seed N` | cookie/seed | 123 |
| `--source-port N` | scanner source port | 40000 |
| `--ip-me ADDR` | scanner source address in packets | `192.0.2.1` |
| `--out DIR` | output directory | `../reports/docker/out/large-batch-replay` |
| `--bin PATH` / `--image IMAGE` | binary / builder image | `XTATE_BIN` / `xtate-builder:24.04` |

`make_pcap.py` computes the same SipHash cookie as xtate, builds valid
Ethernet/IPv4/TCP SYN-ACK packets, and writes a pcap fixture. The pcap is replayed
through `--adapter file:...`; the scanner container runs with `--network none`, so
no packets leave the machine.

The replay is paced from pcap timestamps. This prevents a burst from flooding the
handler queues and makes exact counts deterministic.

### Examples

Small CI smoke test:

```bash
XTATE_BIN=/path/to/xtate-linux bash tests/large-batch/replay.sh \
  --targets 20 --ports 1-100 --pps 5000 --handlers 2
# 2,000 results
```

Default: 1,000 targets × 1,000 ports = **1,000,000 results** at 20,000 pps.

Very large run on a strong host:

```bash
XTATE_BIN=/path/to/xtate-linux bash tests/large-batch/replay.sh \
  --targets 5000 --ports 1-1000 --pps 100000 --handlers 8
# 5,000,000 results
```

Approximate costs for replay (actual disk depends on output module):

| Results | pcap size | ndjson/bson output (each) | Expected scan time at 20k pps |
|---:|---:|---:|---:|
| 100,000 | ~5 MB | ~15 / 19 MB | ~5 s |
| 1,000,000 | ~54 MB | ~150 / 190 MB | ~50 s |
| 5,000,000 | ~270 MB | ~750 / 950 MB | ~250 s |

The test writes four output files. Keep at least **2–4 GB free disk** for the
5M-result case.

The generated target list uses `10.0.X.Y`; this supports up to 65,536 replay
targets. Use a different generator scheme if you need more.

## What is verified

### Live `run.sh`

- ndjson: one JSON object per result, every line parses, open/closed split exact.
- csv: header plus one row per result.
- bson: non-empty binary stream.
- text: one line per result.
- multi-handler (`-rx-handler-count 4`) same count.
- dynamic Docker subnet and aliases; cleanup on exit.

### Replay `replay.sh`

- exact result count for 1,000,000 generated replies;
- all four output modules;
- receive, validation, dispatch and output paths;
- pcap pacing and end-of-file handling (an invalid trailer avoids racing the
  final valid replies);
- no external network (`--network none`).

## Requirements

- Docker
- a Linux `xtate` binary (`XTATE_BIN`)
- `xtate-builder:24.04` or `XTATE_LAB_IMAGE`
- Python 3 on the host for `replay.sh`
- enough disk/RAM for the chosen scale

## Notes

- The live test starts five target containers and needs `NET_ADMIN` for aliases;
  the scanner needs `NET_RAW`/`NET_ADMIN`.
- The replay test needs no target containers; only Docker to execute the binary.
- Firewall RST suppression is not needed for `tcp-syn`; the tests use
  `-scan-arg "--send-rst"` in live mode.
- Output files are written outside the repository by default.

## Failure injection and RSS: `failure.sh`

```bash
XTATE_BIN=/path/to/xtate-linux bash tests/large-batch/failure.sh
```

Checks:

- output write failures (`/dev/full`, 1 MiB tmpfs);
- SIGINT during replay (small 100k fixture; output is flushed);
- SIGPIPE when a downstream consumer exits early (`exit 141` observed);
- RSS high-water for 100k vs 1M results (currently about 117 MB peak for
  both, which is the expected flat profile);
- unreachable MongoDB (clean diagnostic, no hang);
- MongoDB normal write, plus stopping MongoDB during a scan (bulk insert path), if a local MongoDB image is available.

The failure script uses `--network none` for every non-Mongo case. The Mongo
section is skipped when the image is not already present, so it never pulls
from a registry during a test run.

Mongo tests cover: normal write (10,000 docs), scan-time disconnect (no hang/
crash, diagnostic), restart + a fresh recovery scan (10,000 docs), and a
same-scan stop/restart. The same-scan case currently exposes a known data-loss
window: while Mongo is down the output callback logs "No suitable servers" and
drops those results; after restart later results are written, but the dropped
ones are not replayed. The test prints the recovered document count and keeps the
log for review.

For a larger RSS run:

```bash
BATCH_RSS_TARGETS=5000 bash tests/large-batch/failure.sh
# 5,000 x 1,000 = 5,000,000 results
```

RSS is sampled from `/proc/<pid>/status` (`VmRSS`) at ~50 ms intervals and the
peak is reported. The guard fails only on a dramatic super-linear jump or a very
large absolute peak; use the printed values for capacity planning.
