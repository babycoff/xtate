# 06 · Results and files

Every scan produces result records and, optionally, a result file. This chapter
describes the record model, the output formats, the escaping rules, and the
files a managed job adds (heartbeat, chunks, manifest, index). It closes with
how the console and MCP read those files.

If you have not chosen an output module yet, the default is stdout with one
line per result. The deep references are [Output](../output.md),
[Job model](../job-model.md) and [Control plane](../control-plane.md).

## What a result is

A result is one `OutItem`: the target pair, a level, an optional classification
and reason, and three groups of typed key/value fields.

| Field | Meaning |
|:---|:---|
| `time` | Result timestamp |
| `level` | `success`, `failure` or `information` |
| `ip_proto`, `ip_them`, `ip_me` | Protocol and the two addresses |
| `port_them`, `port_me` | Ports; omitted for portless results |
| `classification` | Short verdict, for example `open` or `closed` |
| `reason` | Short explanation, for example `syn-ack` |
| `scan report` | Fields recorded by the scan engine (TTL, window, flags, …) |
| `probe report` | Fields parsed by the probe (banner, certificate, …) |
| `output report` | Fields added by output processing (for example ASN) |

`scan report`, `probe report` and `output report` are flat objects; values are
strings, numbers, booleans or null. They are absent when empty.

## Levels and filtering

The default stream shows only `success`. Failures, closed ports and
informational observations are recorded but hidden until you ask for them:

```bash
xtate -ip 203.0.113.10 -p 80,443 -scan tcp-syn -show failed
xtate -ip 203.0.113.10 -p 80,443 -scan tcp-syn -show info
xtate -ip 203.0.113.10 -p 80,443 -scan tcp-syn -show all
```

`--show-output` (short `-show`) accepts `failed`, `info`, `success` and `all`,
and can be repeated. `--no-show-output` removes a level again:
`-show all -no-show success` leaves failures and information.

Filtering happens **before** the output module, so a file or database only
contains the levels you asked for. An unexpectedly empty file is usually a
level-filtering mistake, not a scan failure.

Different engines assign levels differently. `tcp-syn` reports open as success
and closed as failure. `zbanner` and `tcp-state` report open ports as
information by default, and their engines provide switches
(`--port-success`, `--port-failure`, `--ack-success`) to promote them. Check
the engine's help page before filtering.

## stdout

Without an output module, Xtate writes text lines and keeps the status bar on
stderr:

```text
[+] host: 203.0.113.10 port: 443 in tcp is "open" because "syn-ack",  ttl: 64,  win: 64240
[x] host: 203.0.113.10 port: 80 in tcp is "closed" because "rst",  ttl: 64
[*] host: 203.0.113.10 port: 8443 in tcp is "open" because "syn-ack"
```

- `[+]` success, `[x]` failure, `[*]` information.
- Binary values are printed as `(N bytes bin)`; BSON and MongoDB keep the full
  bytes.
- Results without a port omit the `port:` part.
- `--no-ansi` disables colour and `--no-status` disables the status bar, which
  keeps stdout and stderr machine-readable.

## NDJSON

`ndjson` is the machine-readable stream: one JSON object per line, UTF-8,
newline-terminated, no trailing comma and no enclosing array.

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -show all \
  -output-module ndjson -o results.ndjson
```

```json
{"time":"2026-11-13T09:00:00Z","level":"success","ip_proto":"tcp","ip_them":"203.0.113.10","port_them":443,"ip_me":"192.168.1.24","port_me":40001,"classification":"open","reason":"syn-ack","scan report":{"ttl":64,"win":64240}}
```

The contract is defined by `schemas/result.schema.json`:

- Required keys: `time`, `level`, `ip_proto`, `ip_them`, `ip_me`.
- `level` is exactly `information`, `failure` or `success`.
- Ports, when present, are integers from 0 to 65535.
- The three report objects contain only scalar values.
- Unknown top-level keys are not allowed.

`-o -` selects stdout for `text`, `csv`, `ndjson` and `list`. `bson` has no
stdout convention: `-o -` creates a file literally named `-`.

## Other formats

| Module | Command | Output |
|:---|:---|:---|
| `text` | `-output-module text -o results.txt` | stdout-style lines in a file |
| `csv` | `-output-module csv -o results.csv` | header plus one row per result |
| `list` | `-output-module list -o results.txt` | `address port`, one per line |
| `bson` | `-output-module bson -o results.bson` | binary BSON documents |
| `mongodb` | `-output-module mongodb -o mongodb://...` | documents inserted into a collection |
| `null` | `-output-module null` | discards everything (benchmarks) |

CSV always writes this header, including when appending:

```text
time,level,ip_proto,ip_them,port_them,ip_me,port_me,classification,reason,scan report,probe report,output report
```

The last three columns are quoted JSON-like objects. Other columns are not
field-escaped: a `classification` or `reason` containing a comma or quote can
break a row. Use NDJSON when you need unambiguous records.

`list` prints the bare port for TCP and prefixes `u:`, `s:` or `o:` for the
other protocol spaces. `--output-arg "--no-port"` prints addresses only.

`bson` output can be converted on a build with libbson:

```bash
xtate --parse-bson results.bson > results.json
```

MongoDB options are passed with `-output-arg`: `--database-name` (default
`xtate`), `--collection-name` (default a timestamp), `--application-name`,
`--insert-bulk`, `--bulk-size`, `--compact-mode`, `--retry-count` and
`--retry-delay`. Failures are retried a bounded number of times; a final
failure marks the output fatal and the scan exits non-zero.

## Appending, screen copy and escaping

- `--append-output` (`-output-append`) appends to the file instead of
  truncating it.
- `--output-screen` also prints results to stdout while the module writes its
  destination.
- Only one output module can be active. There is no fan-out to several files.

Escaping is deliberately conservative because results can contain arbitrary
bytes:

- Default: `"`, `'`, `\` and non-printable bytes become `\xNN`. This keeps
  text readable but is **not valid JSON**.
- `--no-escape-char` (`--no-escape`): the same bytes become `\\xNN`, which is
  valid JSON. The value round-trips as the literal four characters `\xNN`,
  not the original byte.
- `classification` and `reason` are copied as-is and are never escaped, so
  they can break an NDJSON line or a CSV row.
- BSON and MongoDB escape themselves. Do not combine them with
  `--no-escape-char`.

For byte-exact transport use BSON or MongoDB; for text formats, accept that
binary fields are lossy.

`--output-as-info` (aliases `--output-as`, `--out-as`, `--output-asn`,
`--out-asn`) adds ASN, country and description fields to `output report` for
targets whose address is in a loaded ip2asn table:

```bash
xtate --ip2asn-v4 ip2asn-v4.tsv --output-as-info \
  -ip 203.0.113.10 -p 443 -scan tcp-syn -show all
```

The table must be loaded at startup, otherwise Xtate refuses to run.

## Managed jobs: heartbeat, chunks and manifest

A job started through the control plane (GUI, TUI, MCP, or
`--job-run`) writes its results to a file owned by the job manager:

```bash
xtate --job-run=request.json --job-result=out.ndjson --job-timeout=30
```

The request is the JSON scan request (`schemas/scan-request.schema.json`); the
worker produces NDJSON with `--show all` semantics. On completion the CLI
prints one status object:

```json
{"job":{"id":"job-1","state":"completed","exit_code":0,"result":"out.ndjson"}}
```

While the worker runs it maintains `<result>.heartbeat`, rewritten atomically
about once per second:

```text
time=1763023200
sent=861
targets=287
success=3
failed=1
info=857
phase=tx
```

`phase` is `tx` while sending and `draining` after transmission stops; a stale
heartbeat makes the job `stalled` (default timeout 30 seconds). Plain,
non-job scans do not write a heartbeat.

Chunking is optional and is applied after the scan, not while writing:

```bash
xtate --job-run=request.json --job-result=out.ndjson \
  --result-chunk-size 10485760 --result-index --result-compress zstd
```

- `--result-chunk-size N` splits the NDJSON file into chunks of roughly `N`
  bytes (0, the default, leaves a single file). A chunk can exceed `N` by at
  most one line. Chunks are named `out.ndjson.00001.ndjson`,
  `out.ndjson.00002.ndjson`, …
- The original file is removed once at least one chunk was written.
- The manifest is `out.ndjson.manifest.json`:

  ```json
  {"format":"ndjson","compression":"none",
   "chunks":[{"id":1,"path":"out.ndjson.00001.ndjson","bytes":10485760,"records":20000}],
   "total_bytes":10485760,"total_records":20000}
  ```

  With zstd the chunk paths end in `.ndjson.zst`, `compression` is `zstd`, and
  `bytes` is the compressed size. If the build has no zstd, Xtate warns and
  writes uncompressed chunks. On Windows, install `zstd:x64-windows` with vcpkg
  before building; `--list-capabilities` reports whether zstd is available.
- `--result-index` additionally writes `out.ndjson.index.json`, containing the
  same `chunks` array without the format and totals.
- Chunks are only built for a job that reaches a terminal state. The CLI
  `--job-run` path builds them only when the job completed; the control plane
  builds them for any terminal state, so a cancelled or timed-out job can
  produce chunked partial results.

`--result-quota N` is different: it is enforced **during** the scan. When the
output file grows beyond `N` bytes, Xtate logs "result file exceeds quota;
stopping scan", marks the output fatal and stops transmission. The job manager
also reports a post-run warning if a result file exceeds its quota. A quota is
a safety valve, not a precise record limit.

A timeout or cancel does not delete the result file: whatever was written
before the stop remains readable.

## Reading job status and manifests

The control plane's `job.status` returns counters derived from the heartbeat:

```json
{"job_id":"job-1","state":"running","phase":"tx","sent":512,"targets":861,
 "heartbeat_age_ms":420,"heartbeat":true,"exit_code":0,
 "result":"out.ndjson","log_path":"out.log","error":"",
 "stderr_tail":"","elapsed_ms":12000}
```

`job.results` and `job.result_manifest` return metadata only, never records:

```json
{"job_id":"job-1","state":"completed","result_path":"out.ndjson",
 "manifest_path":"out.ndjson.manifest.json","result_bytes":10485760,
 "complete":true}
```

`complete` means the job reached a terminal state, not that every planned
target was scanned successfully. Read records from `result_path` (or the
chunks in the manifest) yourself; the control plane is not a result server.

## The console

The GUI's **Live scan** page polls `job.status` and shows state, sent,
targets, phase, heartbeat age, elapsed time, exit code and a result-manifest
card. Each GUI scan gets a managed run folder
`<state>/runs/<YYYYMMDD-HHMMSS>-<seq>/` containing `scan.ndjson`,
`scan.ndjson.log`, the manifest and the index; the run time is shown in Live and
Results, so identical scans remain distinguishable. The **Results** page lists
scans managed by the control plane (run time, id, state, result file) newest
first; selecting a scan returns to its Live view. The Live view also has a
**Result records** card that pages the job's result through
`/api/results` (50 valid NDJSON records at a time). It follows manifest chunks
and transparently decompresses zstd chunks when the server was built with zstd;
use your own tooling when you need the raw chunk bytes. This is also why result
paths must be real files on the machine running the daemon.

See [02 · GUI console](./02-gui-console.md) for the page-by-page description
and the token/loopback security model.

## Post-processing recipes

```bash
# Open ports only, as compact JSON lines
jq -c 'select(.level=="success")' results.ndjson

# Tally classifications
jq -r '.classification // "none"' results.ndjson | sort | uniq -c | sort -nr

# Join JARM slots
./tools/jarm_aggregate.py results.ndjson > jarm.jsonl

# Read a specific chunk of a large job
wc -l out.ndjson.00003.ndjson
zgrep -c '"level":"success"' out.ndjson.00003.ndjson.zst
```

If you need a different transport, filter or aggregate, do it on the NDJSON
stream; it is the only format that preserves every field without ambiguity.

## Limits and risks

- One output module at a time. Results are formatted in the receive handler
  and serialized through the module, so a slow destination (especially a
  synchronous MongoDB insert) backpressures the whole scan.
- `--show` filtering happens before output: files and databases inherit it.
- Default escaping is not valid JSON; `--no-escape-char` produces valid JSON
  but not byte-exact values.
- `classification`/`reason` are never escaped and can corrupt CSV/NDJSON rows.
- Chunking happens after the job reaches a terminal state; a killed process
  leaves a single un-chunked file.
- Result files are not cleaned up automatically. Copy what you need before
  the job manager prunes old jobs, and treat result paths as sensitive: they
  contain every scanned address and any banner/certificate data.
- `--result-quota` stops the scan; it does not repair or truncate an
  over-quota file.

## See also

- [03 · CLI and jobs](./03-cli-and-jobs.md) — control plane and job commands
- [05 · Modules and parameters](./05-modules-and-parameters.md) — output
  modules and their arguments
- [Output](../output.md) — the full format reference
- [Job model](../job-model.md) — states, heartbeat and timeout semantics
- [Control plane](../control-plane.md) — transport, methods and limits
- [JSON contracts](../json-contracts.md) — schemas and error codes
