# Aggregating results

**English** · [中文](zh-CN/aggregation.md)

Xtate emits an **event stream**, not one final row per target. ZBanner can emit an
open line, several banner segments and an acknowledged line for the same port;
HLTCP can add state/probe events. Aggregation is therefore a **downstream**
responsibility. This page shows the bundled post-processing example.

## Recommended model: post-run

```text
xtate -> NDJSON file -> aggregate-events.py -> per-target JSONL/CSV
```

This is the default recommendation because:

- the raw event stream remains available for re-aggregation and audit;
- a slow consumer cannot backpressure the scanner;
- the scan and the aggregation can be re-run independently;
- it is easy to validate event counts.

A runtime pipe is useful for a live dashboard:

```bash
xtate ... -output-module ndjson -output-file - --no-status |
  python scripts/aggregate-events.py - --format jsonl
```

Piping is NDJSON-only and the consumer must keep up; use post-run processing for
large scans.

## Bundled example

[scripts/aggregate-events.py](../scripts/aggregate-events.py) uses only the
Python standard library.

```bash
xtate ... -output-module ndjson -output-file scan.jsonl
python scripts/aggregate-events.py scan.jsonl -o per-target.jsonl --stats
```

Small smoke test:

```bash
head -n 10000 scan.jsonl |
  python scripts/aggregate-events.py - --format jsonl
```

Options:

| Option | Meaning |
|:---|:---|
| `input` | NDJSON file, or `-` for stdin |
| `-o/--output` | output file, or `-` for stdout |
| `--format` | `jsonl` (default), `json`, `csv` |
| `--group-by` | comma-separated grouping fields (default `ip_proto,ip_them,port_them`) |
| `--strict` | abort on malformed JSON (default: skip + stderr note) |
| `--stats` | input/output count, groups, elapsed time, and max RSS where supported |

For each group it emits:

```json
{
  "ip_proto": "TCP",
  "ip_them": "192.0.2.10",
  "port_them": 443,
  "status": "open",
  "status_reason": "syn-ack",
  "events": 3,
  "first_seen": "2026-11-01T12:00:00Z",
  "last_seen": "2026-11-01T12:00:02Z",
  "levels": {"success": 1},
  "classifications": {"open": 1},
  "reasons": {"syn-ack": 1},
  "scan_report": {"ttl": 54},
  "probe_report": {"tls version": "TLSv1.3"},
  "output_report": {}
}
```

Status is chosen by a small priority table (`open` > `fake-open` > `responsed`
> `acknowledged` > `closed`), then by the latest event. Unknown classifications
are preserved in `classifications` and counted.

## Module-specific fields

NDJSON keeps the common fields plus nested module reports:

```text
time, level, ip_proto, ip_them, port_them, ip_me, port_me,
classification, reason, scan_report, probe_report, output_report
```

The aggregator merges `scan_report`, `probe_report` and `output_report` as
opaque objects; it does not assume TLS/HTTP/ZBanner field names. Repeated keys
use the last non-empty value. Consumers that need every banner segment or every
probe event should keep the raw NDJSON stream.

## Other output formats

| Output | Aggregation |
|:---|:---|
| NDJSON | Recommended: one structured object per event |
| BSON | Parse with libbson/`bson` Python package, or convert to NDJSON |
| MongoDB | Use MongoDB aggregation pipelines directly |
| CSV | Common columns plus escaped JSON-like report strings; parsing is awkward |
| Text | Human-readable only; not recommended for aggregation |
| List/null | Not enough information |

The example intentionally supports NDJSON only; adding BSON/CSV adapters is a
separate small layer.

## Memory and scale

The default example keeps one Python dict per group. It is a **post-run** tool,
so the scanner's memory is unaffected.

A local 1M-event benchmark on this tree (1,000,000 unique target/port groups,
184 MB NDJSON input):

```text
input_events=1000000 groups=1000000 bad_json=0 elapsed≈25s
```

Output is about 361 MB of JSONL because every group carries its own metadata.
For very large runs:

- aggregate only the fields you need;
- use `--group-by` to reduce cardinality;
- for 10M+ groups, use SQLite/external sort or partition by IP prefix;
- do not try to build a full 10M dict in memory.

`--stats` reports `maxrss_kb` on platforms with Python `resource` support
(Linux/macOS); Windows may not provide that field.
