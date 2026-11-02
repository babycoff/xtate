# Plugin protocol (draft, Go sidecar)

**English** · [中文](zh-CN/plugin-protocol.md)

Status: design draft for the planned Go sidecar. There is **no C plugin ABI** and
no runtime plugin loading in the core.

## Why a sidecar

Xtate's packet path is C and performance-sensitive. Go is a good fit for output
post-processing, aggregation, orchestration, UI and AI/MCP adapters, but not for
per-packet callbacks. The boundary is a process, not a shared library.

```text
xtate (C) ── NDJSON / JSON-RPC ──> xtate-plugin (Go)
```

## Protocol shape

- transport: stdio or a local socket; no remote bind by default;
- framing: one JSON object per line for result streams; JSON-RPC 2.0 for
  request/response;
- version: protocol major/minor and a capability list in the plugin manifest;
- capability examples: `result.consume`, `scan.start`, `scan.stop`,
  `module.list`, `result.summary`;
- permissions: target access, filesystem paths, network access and rate limits
  are declared and checked by the core before dispatch.

## Data boundary

The C side must expose **plain serialized values**, not pointers:

- target address/port/protocol;
- result level, classification, reason, timestamp;
- key/value result chains already used by `OutItem`;
- error code/message and a correlation id.

`OutItem` remains an internal C type. A future `result-json` writer maps it to a
versioned envelope; the Go side never dereferences C structures.

## Core integration points

1. **Output stream**: an output module writes the same result data as NDJSON;
   the plugin consumes it. This requires no hot-path change.
2. **Control plane**: optional JSON-RPC calls for start/stop/status and module
   listing. Scans still execute in C.
3. **Optional scan orchestration**: plugin may generate commands/targets and
   read results; it does not construct packets.

## Non-goals for the first version

- Go callbacks inside Tx/Rx/handle threads;
- C ABI compatibility guarantees;
- loading arbitrary Go plugins into the C process;
- exposing raw packet buffers to the plugin.

## C-side rules that keep this possible

- Keep result types POD and pointer-free across the boundary.
- Do not make `XConf`, `OutConf` or module registries a public ABI.
- Version the serialized envelope; unknown fields are ignored.
- Keep output serialization separate from packet processing.
- Validate plugin-provided targets/commands like any external input.

## Next steps

1. Define the versioned result envelope and error schema.
2. Add a Go example that consumes NDJSON and aggregates results.
3. Add a small JSON-RPC control example.
4. Only then evaluate a C ABI for cross-language probes.
