# Parameter parser test plan

**English** · [中文](zh-CN/parser-test-plan.md)

This is a research/implementation plan for the CLI and module-parameter parser.
An initial `tests/config/test.sh` suite is implemented, and the pure parser has
a `--selftest` cover for strict bool/int/size/time parsing, quoting and nested
parameter strings. The trailing-`--arg` missing-value out-of-bounds path and
the truncating long-name path have been fixed and are covered. The remaining
matrix is still open.

## Current parser surface

- Global table: `src/xconf.c` (`ConfParam config_parameters[]`).
- Module tables: `Probe.params`, `Scanner.params`, `Output.params`,
  `Generator.params`.
- Parsing entry points: `conf_set_params_from_args`,
  `conf_set_params_from_str`, `conf_set_params_from_substr`.
- Argument splitting: `safe_str_to_args` (double quotes) and
  `safe_substr_to_args` (single quotes).
- Nested module args: `-scan-arg`, `-probe-arg`, `-output-arg`, `-gen-arg`;
  `tls-state` additionally has `-subprobe` and `-subprobe-arg`.

## Findings to test

### Argument syntax

- `--name=value`, `--name:value`, `--name value`;
- single-dash aliases and punctuation-insensitive matching
  (`exclude-file` / `excludefile`);
- `--flag` with and without an accidental value;
- unknown option, missing value, value starting with `-`;
- duplicate options: last wins or rejected consistently;
- very long option names and values;
- `--` handling and non-option positional tokens.

### Value parsers

- `conf_parse_int`: empty, partial digits, leading `+/-`, overflow;
- `conf_parse_bool`: accepted aliases, invalid values, `0/1`;
- `conf_parse_size`/`conf_parse_time`: suffix boundaries, overflow, invalid
  suffixes (must not call `exit()` inside a parser test);
- hex parsing in module setters (`settings-hex`, `--header` forms);
- MAC/address parsing boundaries.

### Quoting and nesting

- double quotes, single quotes, escaped quotes and backslashes;
- `-probe-arg "-subprobe h2 -subprobe-arg --path=/h2"`;
- a subprobe argument containing spaces;
- an unclosed quote: deterministic error, no hang;
- nested quotes in HTTP header values;
- values containing `=`, `:`, `[` and `]`;
- Windows/Git Bash path conversion is a shell concern, not parser behavior.

### Module integration

Representative modules from each registry:

- probe: `http`, `ssh`, `h2`, `jarm`;
- scan: `zbanner`, `udp`, `tcp-state`;
- output: `ndjson`, `csv`;
- generate: `blackrock`, `ip-list`.

Check that parse errors are reported before any scan starts and return nonzero.

### Interactive/recovery

- `set key = value`, `set-scan`, `set-probe`;
- malformed `recover.conf`;
- unknown/missing keys in recovered config;
- interactive help does not mutate config.

## Test harness design

Add `tests/config/test.sh` plus small C helpers only where needed:

1. Build with an isolated `XTATE_BIN`.
2. Run subprocesses with a timeout and capture stdout/stderr/rc.
3. Assert exact failure text for invalid input.
4. Use `--selftest`-style unit helpers for pure functions
   (`conf_parse_int`, `conf_parse_bool`, splitters) instead of forking for every
   case.
5. For dangerous exit paths (`size` suffix), refactor to return an error
   status before adding tests.
6. Never run a real scan in parser tests; use `--list-*`/`--help-*` and
   module-help paths that initialize config without transmitting.

## Acceptance

- Parser tests run in Linux CI and do not need network or root.
- Every invalid form returns nonzero and an explicit message.
- No out-of-bounds read for missing values; no `exit()` from a setter is
  untested.
- Nested module args have at least one passing and one failing case.
- Existing CLI behavior is characterized before changing parser semantics.

## Priority

P2/P3. Do this before large HTTP probe rewrites or more nested subprobe
options, because both depend on the same parser.
