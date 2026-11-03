# Local benchmark harness

This directory contains a small, reproducible benchmark suite for the Linux
scanner path. It does **not** scan the public Internet and is not part of the
normal CI gate: run it manually before and after a performance-sensitive
change.

## What is measured

| Case | Path | What it isolates |
|:---|:---|:---|
| `parse-inline` | no packets | target-file tokenizer + RangeList build |
| `parse-ranges` | no packets | explicit ranges / list formatting |
| `syn-offline-1m` | no raw send | target generation + Tx loop |
| `syn-offline-16m` | no raw send | large target-space Tx loop |

The offline `tcp-syn` cases use `--offline`, so they do not require root, raw
sockets or a lab network. They are for relative comparisons, not as a claim
about real NIC throughput.

Wall time and peak RSS are recorded per case in `results.jsonl`. Peak RSS is
read from `/proc/<pid>/status` when `/usr/bin/time` is unavailable.

## Linux host

```bash
# Build a Release binary first, then:
XTATE_BIN=./bin/xtate bash tests/bench/run.sh

# Faster, 100k input lines instead of 1M:
XTATE_BIN=./bin/xtate bash tests/bench/run.sh --quick

# One case:
XTATE_BIN=./bin/xtate bash tests/bench/run.sh --case parse-inline
```

Results default to:

```text
bench-results/<timestamp>/
  data/
  results.jsonl
  *.stdout / *.stderr
```

Use `--out DIR` or `XTATE_BENCH_OUT` to choose another directory.

## Windows / Docker

The benchmark itself is Linux-only. From Windows Git Bash, use a Linux
`xtate` binary and the builder image:

```bash
export XTATE_BIN=/path/to/xtate-linux
export XTATE_BENCH_QUICK=1
bash tests/bench/docker.sh
```

The wrapper copies the benchmark scripts into a writable container directory,
normalizes CRLF, mounts the binary and writes results under
`bench-results/`.

## Real packet-path lab

`lab.sh` runs the scanner against a private Docker bridge target. It requires
Docker, a Linux `xtate` binary and permission to create containers with
`NET_RAW`/`NET_ADMIN`:

```bash
# Mainland network: use the opt-in mirrors for the container package install
XTATE_CN_MIRROR=1 XTATE_BIN=/path/to/xtate-linux bash tests/bench/lab.sh

# Quick functional run
XTATE_BENCH_QUICK=1 XTATE_BIN=/path/to/xtate-linux bash tests/bench/lab.sh

# One case
XTATE_BENCH_CASE=tx XTATE_BIN=/path/to/xtate-linux bash tests/bench/lab.sh
```

Cases:

- `tx`: `tcp-syn` to a target whose firewall silently drops the port range;
  reports incoming SYN packets counted by a target-side raw socket (not just
  the scanner's own rate).
- `zbanner`: HTTP banner scan against a multi-port local target.
- `output`: `tcp-syn` output comparison (`null`, `text`, `csv`, `ndjson`)
  against closed ports.
- Full mode uses six target IP aliases and a 20k-port HTTP target, giving
  roughly 100k-140k target endpoints depending on the case.
- `stateful`: `tcp-state` against the multi-port HTTP target with
  `tcb-mem=1`, exercising the active-TCB budget.

The lab is intentionally separate from `run.sh`: it needs Linux raw sockets and
Docker, while parser/offline cases do not.

## Reading the results

`results.jsonl` contains one JSON object per case:

```json
{"case":"parse-inline","targets":100000,"elapsed_ms":99,
 "rc":0,"rss_kb":7636,"stdout_bytes":0}
```

Compare runs made with:

- the same binary build type and compiler;
- the same target counts and rate;
- the same output module (`-out null`);
- the same host/container resources.

Docker startup and container filesystem overhead are included in the wall
time. For absolute pps measurements, use a dedicated Linux host and a sink
lab; the offline cases are intentionally for relative Tx-path comparisons.

## Future cases

- Tx-only lab sink (`veth`/network namespace) for real raw-send pps.
- ZBanner HTTP lab throughput and dedup behavior.
- Output module comparison: `null` vs `text` vs `ndjson`.
- Stateful `tcp-state` TCB budget/drop behavior.
- Large-file target ingestion at 10M lines.
