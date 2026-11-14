# Input / Generate Modules Audit

Status: initial audit, 2026-11-12. Resolution status below.

## Resolution (post-2.42.0)

Fixed and covered by tests (the section later in this document, now headed
"Findings (pre-fix baseline)", records the original issues; the resolution list
here supersedes it):

- all four line-based generators use `src/generate-modules/stream-reader.h`:
  one physical line is one record, overlong lines are consumed and counted,
  and errors carry `file:line`;
- `--strict-errors`, `--max-errors N` and `--max-error-rate P` for all four;
- IPv4-only adapters no longer require IPv6 (`init-nic`);
- count/overflow checks in `ip-stream` and `addr-stream`;
- `addr-list` no longer leaks a `RangeList` per line;
- file options open UTF-8/UTF-16 paths and close the previous stream;
- job workers get a NUL stdin, so an unconfigured stream cannot block on the
  control/MCP stdin; MCP also rejects mixed `targets` + `include_file`;
- stream generators reject more than one TX thread instead of silently degrading.

Tests: `tests/input/test_generate.py` (all four modules, invalid line 2,
all-invalid exit 1, strict exit 1). Remaining coverage is listed below.

## Two input models

1. Static `TargetSet`: `-ip`, `-iL/--include-file`, `--exclude-file`, `--list-ranges`.
2. Generate modules (`--generate`): `blackrock` (default), `ip-stream`,
   `addr-stream`, `ip-list`, `addr-list`. These read targets at scan runtime.

`--include-file` is not a generate module. It parses a static file into
`TargetSet`; `--generate ip-stream` reads a file during the scan.

## Findings (pre-fix baseline)

These are the issues that were found before the fixes listed under Resolution.

### High

- `ip-stream` and `addr-stream` set `init_ipv4 = init_ipv6 = true`
  unconditionally. On an IPv4-only adapter, `init_nic` fails with
  `failed to detect IPv6 address of interface`.
- `--include-file` clears the existing `TargetSet`; if `targets` and
  `include_file` are both supplied, inline targets are silently discarded.
- `ip-stream`/`addr-stream` compute work as
  `(count_ipv4s + count_ipv6s.lo) * count_ports`. IPv6 counts above 2^64 are
  truncated and the multiplication can overflow `uint64_t`.
- Stream/list generators use 256-byte `fgets` buffers with no overlong-line
  detection; long lines split into malformed fragments.

### Medium

- Stream errors log line content without `file:line`; invalid lines are skipped
  and scanning continues. Static include-file logs `file:line` and aborts.
- `addr-list` leaks a local `RangeList` per line.
- File parameters use `fopen`; Unicode paths fail on Windows.
- File setters leak previous `FILE*` and do not close on reconfiguration.
- `--gen-arg` syntax is fragile; a missing/unparsed file falls back to stdin.
- Stream generators support only 1 TX thread; job path does not enforce it.
- stdin is the default input and conflicts with MCP/job stdin.
- `--list-ranges`/`--list-target` only see static TargetSet.

## Tests performed

- `--include-file file --list-ranges`: PASS.
- `--generate ip-stream --gen-arg "-ip-file file -default-port 1"` on IPv4-only
  adapter: FAIL, IPv6 adapter detection.
- `--gen-arg ip-file=file`: FAIL, unknown parameter.
- Malformed invocation fell back to stdin and hung until cancelled.

## Remaining test coverage

1. Valid/invalid/comment/blank lines for all four generators.
2. IPv4-only and IPv6-only files/adapters.
3. Lines >255 bytes.
4. Unicode/space file paths.
5. Reused file options.
6. stdin forbidden in job/MCP mode.
7. include_file + targets conflict.
8. Count/overflow boundaries.
9. One-TX-thread enforcement.
10. file:line/column errors.

## Design direction

- `input_mode = static | stream`.
- Static: targets xor include_file, countable and routable.
- Stream: generate + input_file + explicit interface, targets_known=false,
  no automatic route grouping.
- Reject stdin for jobs/MCP.
- Shared UTF-8/UTF-16 opener and shared parser error type.
