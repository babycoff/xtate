# Output

**English** · [中文](zh-CN/output.md)

By default Xtate prints results to **stdout**, one line per reply. An *OutputModule* can
instead write text, CSV, NDJSON, BSON or a `list` file, or insert results into MongoDB. The
status bar is separate: it is drawn on **stderr**, so redirecting stdout keeps the result
stream clean.

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan tcp-syn > results.txt
```

> Documented against Xtate v2.20.1. `--help` and `--help-output <module>` are authoritative
> for the exact flags of your build.

## The result line

```
[+] host: 192.168.1.10 port: 80 is "open" because "syn-ack",  ttl: 64,  win: 64240
[*] host: 192.168.1.11 port: 80 is "closed" because "rst"
```

The prefix encodes the level: `[+]` success, `[x]` failure, `[*]` information. Then come the
target (`host`, `port`), the module's `classification` and `reason`, and finally the report:
typed key-value pairs from the scan, probe and output modules (`ttl`, `banner`, `cert_0`,
`distance`, `ASN`, ...). Strings are quoted and escaped; integers and booleans are literal.
On a terminal the prefix is colourised and a status bar is refreshed; `--no-ansi` disables
colour and `--no-status` disables the bar.

Internally a result is an `OutItem`: `timestamp` (auto-filled), `level`, the `target`
(protocol, both addresses, both ports), `classification` and `reason` (30-byte buffers), and
three typed key-value chains - `scan_report`, `probe_report`, `output_report`. Binary values
print as `(N bytes bin)` in text formats but are stored in full by `bson`/`mongodb`; a
`no_port` flag hides ports for port-less results.

## Result levels and `-show`

The level decides whether a result is emitted at all - **this filter runs before the
OutputModule**, so it applies to files and databases too.

| Level | Printed by default? | Typical meaning |
|:---|:---:|:---|
| `success` | yes | a positive answer (`open`, `alive`, a banner, a certificate) |
| `failure` | **no** | a negative answer (`closed`, `abort`, handshake failure) |
| `information` | **no** | context, not a finding (ZBanner and `tcp-state` port state, TLS alerts) |

Use `-show` (`--show-output`) to add a level and `-no-show` (`--no-show-output`) to remove
one; both may be repeated. `-show` accepts `failed`/`fail`/`failure`, `info`/`information`
and `success`/`successed`; `-no-show` accepts `failed`/`fail`, `info`/`information` and
`success`.

The status-bar totals count every result that reaches the output layer, including filtered
ones. Which level a module assigns is its own business: `tcp-syn` calls `closed` a `failure`,
while `zbanner` calls both `open` and `closed` `information` unless you pass
`-scan-arg "--port-success"` or `--port-failure` - the usual cause of an empty-looking scan.

## Output modules

| Module | Needs `-output-file` | Writes |
|:---|:---:|:---|
| `text` | yes | the same line format as stdout, to a file |
| `ndjson` | yes | one JSON object per line (JSONL) |
| `bson` | yes | concatenated BSON documents (binary) |
| `csv` | yes | a header row plus one row per result |
| `list` | yes | only `ip` and optional `port` |
| `mongodb` | yes | inserts into a MongoDB collection; the "file" is a **URI** |
| `null` | no | nothing (benchmarking) |

Modules whose optional libraries are missing at compile time are absent from `--list-output`; see [Modules](./modules.md).

## Files, appending and the screen

```bash
# Text file, closed ports included through the level filter
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn \
  -output-module text -output-file scan.txt -show failed

# NDJSON, appending, and additionally echoing to stdout
sudo ./bin/xtate -ip 10.0.0.0/24 -p 80 -scan zbanner -probe http -show info \
  -output-module ndjson -output-file scan.jsonl -output-append -output-screen
```

- `-output-module` (aliases `--output`, `--out`) selects the module; `-output-file`
  (aliases `--out-file`, `-o`) sets the destination.
- Without a module, results always go to stdout. With a module, stdout stays silent unless
  `-output-screen` (alias `--out-screen`) is given.
- `-output-append` (primary name `--append-output`, alias `--append`) opens the destination
  in append mode instead of truncating it. `csv` writes its header on every run, appending
  runs included.
- For `text`, `csv`, `ndjson` and `list`, a destination of exactly `-` means stdout. `bson`
  does not support that, and `mongodb` treats `-output-file` as a connection URI.
- Module options go through `-output-arg` as one quoted string, e.g.
  `-output-arg "-compact-mode"` for `bson`.

## Format notes

### text and csv

`text` mirrors the stdout line with an extra `in tcp` protocol word, no colour and no status
bar. `csv` starts with this header:

```text
time,level,ip_proto,ip_them,port_them,ip_me,port_me,classification,reason,scan report,probe report,output report
```

The three report columns are embedded JSON-like strings with their inner quotes doubled; the
other columns are not field-escaped, so a classification containing a comma or quote breaks
the row. Keep a CSV consumer tolerant.

### ndjson

One compact object per line:

```json
{"time":"2024-05-01T12:00:00Z","level":"success","ip_proto":"tcp","ip_them":"192.168.1.10","port_them":80,"ip_me":"192.168.1.5","port_me":40001,"classification":"open","reason":"syn-ack","scan report":{"ttl":64,"win":64240},"probe report":{"banner":"HTTP/1.1 200 OK"}}
```

The `scan report` / `probe report` / `output report` sub-objects are omitted when empty, as
are `port_them`/`port_me` for port-less results.

### bson and mongodb

`bson` writes a stream of binary documents to the file and has no stdout convention; a
destination of `-` becomes a file literally named `-`. Dump it back to JSON with
`--parse-bson` (libbson build): `xtate --parse-bson out.bson > out.json`. `mongodb` uses
`-output-file` as the URI and connects directly:

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 443 -scan zbanner -probe tls-hello -show info \
  -output-module mongodb -output-file "mongodb://127.0.0.1:27017" \
  -output-arg "-database-name xtate -collection-name scan1"
```

Its sub-parameters are `--database-name` (default `xtate`), `--collection-name` (default: a
timestamp), `--application-name`, `--insert-bulk` / `--bulk-size` (default 200) and
`--compact-mode`. Inserts happen in the result path; with `--bulk-size` documents are buffered
and flushed in batches. Both modules escape strings themselves, so never combine them with
`--no-escape-char`. Either format can be imported offline with
`--store-bson` / `--store-json` plus `--mongodb-uri`, `--mongodb-db-name` and
`--mongodb-col-name`; `--store-json` insists on valid JSON per line.

### list and null

`list` writes only the target (`192.168.1.10 80`), which makes it a good input for the next
stage. UDP, SCTP and "other" ports are prefixed `u:`, `s:`, `o:`; TCP ports are bare.
`-output-arg "--no-port"` writes addresses only. `null` discards everything and is intended
for rate benchmarks.

## Escaping: `--no-escape-char` and the JSON trap

Banner and UTF-8 report fields are normalised by the result layer: printable characters pass
through, while `"`, `'`, `\` and every unprintable byte become `\xNN`. That is readable but
**not valid JSON** - a single backslash is an illegal escape. Add `--no-escape-char` (alias
`--no-escape`) and the escape is itself escaped, producing `\\xNN`: valid JSON that
round-trips to the literal text `\xNN`.

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe http -show info \
  -output-module ndjson -output-file scan.jsonl --no-escape-char
```

Caveats: do **not** use the flag with `bson`/`mongodb` (they escape natively, so it
double-escapes); `classification` and `reason` are printed with `%s` and are never escaped,
so a quote or newline in them breaks JSON/CSV regardless; the flag changes report-string
escaping only, never the raw bytes a probe saw.

## AS annotation with `--output-as-info`

`--output-as-info` (aliases `--output-as`, `--out-as`, `--out-asn`) looks up the target in the
loaded `ip2asn` tables and appends `ASN`, `AS country code` and `AS desc` to `output_report`.
Load the tables with `--ip2asn-v4` / `--ip2asn-v6`.

```bash
sudo ./bin/xtate --ip2asn-v4 /path/to/ip2asn-v4.tsv -ip 10.0.0.0/24 -p 443 \
  -scan zbanner -probe tls-hello -show info --output-as-info \
  -output-module ndjson -output-file scan.jsonl
```

Without a loaded table, `output_init` refuses to start; the lookup runs per result, so the flag costs a little on very large scans.

## Practical notes

- Only one OutputModule can be active at a time; there is no fan-out to two modules.
- Results are formatted in the receive-handler threads and serialised by a mutex around the
  output module, so a slow destination (especially synchronous MongoDB inserts) back-pressures
  the whole scan; prefer `bson`/NDJSON with the offline `--store-*` path for large runs.
- `-show`/`-no-show` filtering happens first, so an `-output-file` never contains the levels
  you hid - if a file is unexpectedly empty, check the level, not the module.
- A result flagged `no_output` (duplicates, suppressed repeats) never reaches any destination,
  whatever the level filter says.

## See also

- [Scanning modes](./scanning-modes.md) - which module produces which levels and fields
- [Modules](./modules.md) - the module inventory and optional-dependency cut
- [Troubleshooting](./troubleshooting.md) - missing results and format problems
- [README](../README.md) - feature overview
