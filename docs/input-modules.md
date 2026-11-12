# Input and Generate Modules

## Two input models

Xtate has two ways to supply targets:

- **Static target set** — parsed before the scan starts: `-ip`, `-iL`/`--include-file`, `--exclude-file`.
- **Generate module** — target generation at scan time: `--generate <module>`.

`include_file` is static. `ip-stream`, `addr-stream`, `ip-list` and `addr-list`
read during the scan. `blackrock` is the default generate module used to randomize
a static target set.

## Generate modules

| Module | One input line means | Main arguments |
|---|---|---|
| `blackrock` | internal randomization of a target set | default; not a line reader |
| `ip-stream` | IP/CIDR/range | `--ip-file`, `--default-port`, `--no-random`, `--rounds` |
| `addr-stream` | IP range + splitter + port range | `--address-file`, `--splitter`, `--default-port`, `--no-random` |
| `ip-list` | one IP | `--ip-file`, `--default-port`, `--no-random` |
| `addr-list` | one IP + splitter + one port | `--address-file`, `--splitter` |

The four line-reading modules:

- read one physical line at a time and keep a shared `line_number`;
- consume an overlong line instead of splitting it into several targets, and count
  it as invalid;
- report errors as `file:line: reason`;
- skip invalid lines by default and continue;
- support one TX thread only; the scan rate is capped but not guaranteed while the
  stream blocks.

```bash
xtate --generate ip-stream \
  --gen-arg "--ip-file targets.txt --default-port 443" \
  -scan tcp-syn -if eth0 -wait 0 -o out.ndjson --no-status
```

## Error policy

- Invalid target line: print `file:line`, increment `bad_lines`, continue.
- End of input with no valid target: exit 1.
- Read error: failure.
- `--strict-errors` (alias `--strict`): abort on the first invalid line.
- `--max-errors N` (alias `--max-bad`): abort after `N` invalid lines; `0` disables
  (the default).
- `--max-error-rate P` (alias `--max-bad-rate`): abort when invalid lines exceed
  `P` percent of lines read; `P` is 0-100 and `0` disables (the default).

All three are `--gen-arg` module parameters, for example:

```bash
--gen-arg "--ip-file targets.txt --strict-errors"
--gen-arg "--ip-file targets.txt --max-errors 100"
--gen-arg "--ip-file targets.txt --max-error-rate 5"
```

## Why MCP does not expose streams

MCP stdin is JSON-RPC. Stream generators default to stdin, cannot report a target
count up front, and cannot be route-grouped before scanning. MCP uses a static
`targets` array or `include_file`; mixing both is rejected. Large target sets
therefore go through `include_file`, not a generate module.

## Known issues

- Stream error counters are not yet reflected in `job_status`.
- Route discovery from `include_file` is not implemented; Windows multi-NIC users
  must pass `interface` explicitly.
