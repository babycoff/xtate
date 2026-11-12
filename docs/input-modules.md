# Input and Generate Modules

## Two input models

- Static target set: `-ip`, `-iL/--include-file`, `--exclude-file`.
- Generate modules: `--generate`, runtime target generation.

`include_file` is static (parsed before the scan). `ip-stream`/`addr-stream`/
`ip-list`/`addr-list` read during the scan.

## Generate modules

| Module | One line means | Main args |
|---|---|---|
| `ip-stream` | IP/CIDR/range | `ip-file`, `default-port`, `no-random`, `rounds` |
| `addr-stream` | IP range + splitter + port range | `address-file`, `splitter`, `default-port`, `no-random` |
| `ip-list` | one IP | `ip-file`, `default-port`, `no-random` |
| `addr-list` | one IP + splitter + one port | `address-file`, `splitter` |

All four read one physical line at a time, count `line_number` per physical
`fgets`, reject lines longer than 255 bytes instead of splitting them, report
`file:line: reason`, skip invalid lines by default, and support only one TX
thread.

```bash
xtate --generate ip-stream \
  --gen-arg "--ip-file targets.txt --default-port 443" \
  -scan tcp-syn -if eth0 -wait 0 -o out.ndjson --no-status
```

## Error policy

- Invalid data line: log `file:line`, increment `bad_lines`, continue.
- EOF with no valid targets: exit 1.
- More than 1000 invalid lines: exit 1.
- `--strict-errors`: first invalid line exits 1.
- `--max-errors N`: abort after N invalid lines.
- `--max-error-rate P`: abort when invalid lines exceed P% of lines read.
- Read error: failure.

Strict mode is currently an environment variable, not yet a `--gen-arg` option.

## Why MCP does not expose streams

MCP stdin is JSON-RPC. Stream generators default to stdin, cannot report a target
count up front, and cannot be route-grouped before scanning. MCP uses static
`targets` or `include_file`; mixing both is rejected.

## Known issues

- strict/max-errors/max-error-rate are not formal `--gen-arg` parameters;
- max-errors is fixed at 1000;
- no error-rate limit;
- stream errors are not reflected in `job_status`.
