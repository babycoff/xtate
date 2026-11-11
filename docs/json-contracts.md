# JSON contracts

**English** · [中文](zh-CN/json-contracts.md)

These schemas are the machine-readable boundary for AI/MCP integration. The
CLI and NDJSON output remain the source of truth; schemas describe them.

## Schemas

| File | Purpose |
|:---|:---|
| [`schemas/module.schema.json`](../schemas/module.schema.json) | module metadata (scan/probe/output/generate) |
| [`schemas/scan-request.schema.json`](../schemas/scan-request.schema.json) | closed scan request object used by agents/MCP |
| [`schemas/result.schema.json`](../schemas/result.schema.json) | one NDJSON result line |
| [`schemas/error.schema.json`](../schemas/error.schema.json) | stable error envelope |
| [`schemas/error-codes.json`](../schemas/error-codes.json) | known error codes |

## Runtime metadata

```bash
xtate --list-modules-json
```

emits every scan/probe/output/generate module with `name`, `kind`,
`probe_type`, descriptions and parameters. Coverage validation:

```bash
XTATE_BIN=build/bin/xtate python3 tests/schema/validate_modules.py
```

Direct C runtime:

```bash
xtate --scan-request=request.json
```

It builds the internal configuration without a shell or subprocess. `dry_run`
maps to a target-listing operation, so no packets are sent. Errors are emitted
as `{"error":{"code":"...","message":"..."}}`.

Reference scan-request adapter:

```bash
python3 tools/scan_request_to_cli.py < request.json
```

It validates against `scan-request.schema.json` and prints an argv array; it
does not execute anything.

## Rules

- JSON is UTF-8 and one object per line for results.
- Unknown fields are rejected (`additionalProperties: false`) at the request
  boundary.
- `scan-request` is data, never a shell string. No command substitution, pipes
  or redirection.
- `targets` are exactly what the caller supplied; no implicit expansion.
- `dry_run` defaults to `true` for agent-originated requests.
- Results must validate against `result.schema.json`; report values are scalar.
- Errors use stable uppercase `code` values, not localized prose.

## Versioning

Schemas are versioned with the Xtate release. Additive fields are allowed only
after a schema revision; removing or renaming a field is a breaking change.

## Validation

```bash
python3 -m pip install jsonschema
python3 tests/schema/validate_schemas.py
```

The test checks schema metaschema validity, positive/negative fixtures, and a
real NDJSON result line. The MCP server must validate both requests and
generated result lines before returning them.
## JSON error mode

In `--scan-request` mode every `LOG(LEVEL_ERROR)` is emitted as:

```json
{"error":{"code":"INVALID_ARGUMENT","message":"...","retryable":false}}
```

No colored `[ERR]` text is used for these errors. Hints/warnings remain human
text. Runtime errors use `INTERNAL_ERROR` until they are given dedicated codes.
