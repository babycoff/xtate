# Migrating from 2.44.x to 3.0

**English** · [中文](zh-CN/migration-3.0.md)

Xtate 3.0 is a release-candidate line focused on the operator experience: a
scan-first GUI, a one-command MCP server, a bilingual manual, explicit protocol
capability reporting, and managed result storage. The packet engines and module
types are unchanged, but several interfaces and defaults moved. Read this page
before upgrading automation that wraps Xtate.

> 3.0.0 is currently an RC. Trial it before replacing a stable deployment. The
> last stable tag is 2.44.2.

## Quick upgrade checklist

1. Replace the binary and its DLLs; keep the old binary until the new one passes
   `--selftest` and one scan.
2. If you automate MCP, change `start_scan` to the flat request shape and run
   the contract tests.
3. If you parse result paths, stop assuming files appear in the current working
   directory. Use `xtate-state`, `XTATE_STATE_DIR`, or your own `result_path`.
4. If you use `--tui`, migrate to `--gui`; TUI is deprecated in 3.0.
5. Re-check HTTP/3 and QUIC expectations: Linux-only, and only when built with
   ngtcp2/GnuTLS.
6. Read the [3.0 release notes](./release-notes/3.0.0-rc.7.md) and
   [known limitations](./known-limitations.md).

## Breaking or behavior-changing items

### MCP `start_scan` is flat

In 3.0 the JSON-RPC `params.arguments` object **is** the scan request. Do not
wrap it in another `arguments` object.

```json
{"name":"start_scan","arguments":{
  "scan":"tcp-syn",
  "targets":["203.0.113.0/24"],
  "ports":[80,443],
  "rate":1000,
  "timeout_sec":300,
  "authorized":true
}}
```

The old nested shape (`arguments.arguments`) is rejected with
`unknown field: arguments`. The schema also rejects unknown top-level fields
instead of silently ignoring them. See [MCP server](./mcp-server.md).

### `preflight`, `check`, and capability discovery

- `preflight` accepts `targets` and `ports` as JSON arrays or the older
  comma-separated strings. The response is still packet-free.
- `check` now really performs the route/link check. It reports link capability;
  Linux firewall rules are reported by the firewall resource, not by `check`.
- `capabilities` and `--list-capabilities` are the supported way to discover
  HTTP/3, QUIC, zstd, raw-socket and module availability. Do not infer support
  from a build name.
- Tool arguments are still bounded by the MCP line limit (8 KiB). Use
  `include_file` for large target sets; an oversized request now returns an
  explicit `request too large` error.

### Results no longer land in the current directory

2.44.x jobs could create `xtate-job-<epoch>.ndjson` in the working directory.
3.0 defaults to a managed state root:

| Platform | Default state root |
|---|---|
| Windows | `<directory containing xtate.exe>\xtate-state` |
| Linux | `${XDG_STATE_HOME:-$HOME/.local/state}/xtate` |
| Override | `XTATE_STATE_DIR=/path` |

Results are written under `runs/<YYYYMMDD-HHMMSS>-<seq>/scan.ndjson` with a
matching `scan.ndjson.log`; request and heartbeat files are temporary. The GUI
shows the run time instead of only a job id. To keep your own layout, pass
`result_path` to `job.start` (MCP/API) or use the CLI output flags.

### TUI is deprecated

`xtate --tui` still exists in 3.0 for one transition window, but it receives no
new work and is not part of the 3.0 interface. Use `xtate --gui` or MCP.
Clients that need the old control-plane contract can still start a control
plane and attach with `--control-connect`.

### The GUI opens no browser

`xtate --gui` starts a private control plane, prints the URL and a session
token, and waits. It does not launch Explorer, Edge, or `xdg-open`.
`--gui-no-open` is accepted as a deprecated no-op. Open the printed loopback URL
yourself. In Docker, set `XTATE_GUI_ALLOW_REMOTE=1` and publish the port; see
[Docker build](./docker-build.md).

### Module names and parameter editing

The GUI now uses Xtate's own taxonomy: **scan modules**, **probe modules**,
**output modules**, and **generate modules**. Modules can be expanded to show
their full description and parameter table. The GUI exposes only the 23 global
options that are safe to combine with its scan fields (`global_args`); the
control plane fixes output/result/job fields. Use the CLI or MCP for other
global options.

### HTTP/3 and QUIC are capability-gated

A full Linux build with ngtcp2/GnuTLS reports `http3:true` and
`quic_transport:true` and includes `http3-state`/`quic-state`. Windows builds
report both false with a reason. This is a supported 3.0 limitation, not a
missing DLL warning.

### zstd is optional

If built without zstd, results are written uncompressed and
`capabilities.zstd` is `false`. The Ubuntu 24.04 Docker image enables it. See
[Docker build](./docker-build.md) and [Windows dependencies](./windows-dependencies.md).

## Compatibility matrix

| Surface | 2.44.x | 3.0 |
|---|---|---|
| CLI scan flags | unchanged | unchanged |
| MCP `start_scan` | nested `arguments` | flat request |
| MCP `check` | alias of explain | real `--check` |
| MCP unknown fields | often ignored | rejected |
| MCP `preflight` targets | strings | arrays or strings |
| Result location | often cwd | managed state root / `runs/<ts>` |
| GUI | job dashboard | scan-first console |
| TUI | supported | deprecated |
| GUI browser launch | auto-open | no auto-open |
| HTTP/3, QUIC | build-dependent | explicit capability; Linux-only in official builds |

## Validation after upgrading

```bash
xtate --version
xtate --selftest
xtate --list-capabilities
xtate --explain-target=192.0.2.10 --check
```

For MCP:

```bash
python3 tests/mcp/test_mcp_contract.py
python3 tests/skill/test_skill_contract.py
```

Then run one authorized scan and confirm:

- the job reaches `completed`;
- the result manifest is complete;
- `job.records` (MCP) or `/api/results` (GUI) returns records;
- the result files are under the expected state root.

## Rollback

Keep the previous binary and `bin/` DLLs until the trial scan succeeds. The
state root is additive; removing it removes local run history. To return to
2.44.x, restore the old binary and remove `XTATE_STATE_DIR` from automation if
you added it only for 3.0.

## Related

- [3.0 manual](./manual/README.md)
- [MCP server](./mcp-server.md)
- [GUI console](./gui.md)
- [Control plane](./control-plane.md)
- [Docker build](./docker-build.md)
- [Known limitations](./known-limitations.md)
