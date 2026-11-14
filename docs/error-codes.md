# Error codes

**English** · [中文](zh-CN/error-codes.md)

Stable codes used by JSON error envelopes. The machine-readable list is
[`schemas/error-codes.json`](../schemas/error-codes.json).

| Code | Retryable | Meaning |
|:---|:---:|:---|
| `INVALID_JSON` | no | malformed JSON |
| `INVALID_ARGUMENT` | no | field/type/value invalid |
| `UNSUPPORTED_SCAN` | no | scan module unknown |
| `UNSUPPORTED_PROBE` | no | probe module unknown |
| `TARGET_INVALID` | no | target range/IP invalid |
| `PERMISSION_DENIED` | no | raw socket/Npcap permission |
| `FIREWALL_RULES_MISSING` | no | Linux RST/ICMP rules missing |
| `OUTPUT_WRITE_FAILED` | no | output file write/close failed |
| `IO_ERROR` | yes | transient file/IO failure |
| `CONFIG_ERROR` | no | configuration rejected |
| `SCAN_TIMEOUT` | yes | job deadline reached |
| `SCAN_STALLED` | no | no output progress before stall timeout |
| `SCAN_CANCELLED` | no | job cancelled |
| `JOB_NOT_FOUND` | no | unknown job id |
| `JOB_ALREADY_RUNNING` | yes | job already active |
| `JOB_LIMIT_REACHED` | yes | concurrency limit |
| `UNSUPPORTED_OPERATION` | no | operation not supported |
| `NOT_FOUND` | no | object not found |
| `INVALID_STATE` | no | lifecycle state invalid |
| `INTERNAL_ERROR` | no | unexpected internal failure |

## Rules

- Codes are uppercase and stable; do not localize them.
- `retryable` is advisory for agents.
- A code is added only when a real path can emit it; lifecycle codes become
  active with the job/timeout model.
- Runtime paths not yet specialized use `INTERNAL_ERROR`.

## Current behavior

- `TARGET_INVALID`: invalid single IP and invalid CIDR/range syntax are
  rejected before the CLI parser runs.
- `FIREWALL_RULES_MISSING`: in `--scan-request` mode a missing Linux RST/ICMP
  rule aborts the scan with this code; normal CLI mode remains a warning.
- `PERMISSION_DENIED`: set by raw socket/PCAP permission failures; other NIC
  failures may still be `INTERNAL_ERROR`.
- `OUTPUT_WRITE_FAILED`: file output modules write through `out_fprintf`,
  `out_fputc` and `out_fwrite`. The first failed write sets a process-wide
  failed flag, logs the error once, and later writes short-circuit; open and
  close paths check `fflush`/`fclose` (and pcap rewrite) failures explicitly.

End-to-end failure check (Linux):

```bash
XTATE_BIN=build/bin/xtate bash tests/schema/test_output_failure.sh
```
