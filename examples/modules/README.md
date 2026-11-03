# Module templates

These files are compile-checked templates for the four Xtate module types. They
are intentionally **not** registered in the production binaries. Copy the file
into the matching `src/*-modules/` directory, change the relative includes to
local names, register it, add i18n text and docs, then add a test.

| File | Type | What it demonstrates |
|:---|:---|:---|
| `tcp-probe.c` | Probe | Single-slot TCP payload and response report |
| `udp-probe.c` | Probe | UDP payload, response validation, probe-slot index |
| `state-probe.c` | Probe | HLTCP per-connection hello/response sequence |
| `output-module.c` | Output | Minimal text/NDJSON-like sink |
| `generate-module.c` | Generate | A deterministic target enumerator |

Compile check:

```bash
bash tests/module-examples/test.sh
```

The runtime examples are the built-in `slot-test` and `slot-test-udp` probes,
covered by `tests/lab/run.sh`.
