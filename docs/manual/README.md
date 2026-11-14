# Xtate 3.0 manual

This is the task-oriented manual for Xtate 3.0. The command line is the primary
interface and the reference for everything the scanner does: scan options,
module behavior, job control and result formats are defined by the CLI and the
local control plane. The browser console (chapter 02) and the MCP server are
additional local clients of the same scan engine and job manager.

The manual is written against the code in this tree: the browser console in
`web/gui.html`, the local GUI server in `src/util-scan/gui.c` and the scan
engine, control plane and job manager it uses.

This manual describes the **3.0.0-rc.10 release candidate**. It documents what
exists in this tree and is exercised by the tests; where behavior is still
limited, it says so instead of promising a future feature.

## Who this manual is for

- **New users and script authors.** Start with
  [01 · Install and quick start](./01-install-and-quickstart.md), then
  [03 · CLI and jobs](./03-cli-and-jobs.md), the reference chapter.
- **Operators who want the browser console.** Follow
  [01](./01-install-and-quickstart.md), then the optional
  [02 · GUI console](./02-gui-console.md). Anything the console can do is also
  available from the CLI and the control plane.
- **Automation and AI clients.** Read the control-plane and job material in
  [03](./03-cli-and-jobs.md), then the deep references
  [MCP server](../mcp-server.md) and [Agent Skill](../agent-skill.md).
- **People migrating from 2.44.x.** Scan engines and result formats are
  unchanged; the new part is the scan-first console, server-side preflight and
  one-command GUI/MCP startup. See the
  [3.0.0-rc.10 release notes](../release-notes/3.0.0-rc.10.md).

## Chapters

| Chapter | What it covers |
|:---|:---|
| [01 · Install and quick start](./01-install-and-quickstart.md) | Build or verify a binary, permissions, first scan, optional first GUI session |
| [02 · GUI console](./02-gui-console.md) | Optional browser console: every page and field, preflight, authorization, security model, limits |
| [03 · CLI and jobs](./03-cli-and-jobs.md) | Reference chapter: scan options and examples, output, control plane, managed jobs, result files |
| [04 · Targets and scanning](./04-targets-and-scanning.md) | IPv4/IPv6, CIDR/ranges/files/excludes, ports, scan engines and attempt counts |
| [05 · Modules and parameters](./05-modules-and-parameters.md) | Scan/probe/output/generate modules, pairing rules, common parameters |
| [06 · Results and files](./06-results-and-files.md) | NDJSON records, manifests, chunks, index, compression and quotas |
| [07 · Protocols and HTTP/3](./07-protocols-and-http3.md) | HTTP/1.1, HTTP/2, HTTP/3/QUIC, DNS/TLS, capability reporting, RAW links |
| [08 · Architecture and security](./08-architecture-and-security.md) | Pipeline, threads, control plane, GUI/MCP boundaries, deployment |
| [09 · Troubleshooting](./09-troubleshooting.md) | Empty results, firewall, permissions, TUN/fake-IP, Windows specifics |

## Reading paths

1. **First scan, fastest path:** [01](./01-install-and-quickstart.md) → first CLI
   scan → [03](./03-cli-and-jobs.md) for output and job control.
2. **Console (optional):** [01](./01-install-and-quickstart.md) → `xtate --gui`
   → [02](./02-gui-console.md) page by page.
3. **Banner and stateful work:** [04](./04-targets-and-scanning.md) →
   [05](./05-modules-and-parameters.md) →
   [firewall rules](../firewall.md).
4. **Long or automated scans:** [03](./03-cli-and-jobs.md) → control plane →
   [06](./06-results-and-files.md) → [MCP server](../mcp-server.md).
5. **HTTP/3 and QUIC:** [07](./07-protocols-and-http3.md) →
   `xtate --list-capabilities` → [quic-state](../quic-state.md).
6. **Something is wrong:** [09](./09-troubleshooting.md) →
   [known limitations](../known-limitations.md).

## Conventions

- Commands run from the repository root. Linux uses `./bin/xtate`; Windows uses
  `.\bin\xtate.exe`. Installed binaries can be called as `xtate`.
- Raw-socket scans need root on Linux or Administrator on Windows. Examples
  show `sudo` where it is required.
- `-ip` is the short form of `--target-ip`; `-p` is the short form of `--port`;
  `-if` selects an adapter. Options are case-sensitive.
- Result levels in this manual are `success`, `failed` and `info`, matching the
  output contract.
- The CLI is the reference interface. The GUI and MCP are clients of one local
  control plane, so a job started in one client can be listed and cancelled
  from another. The GUI is the supported interactive interface.

## Accuracy and scope

This manual is checked against the built binary and the test suites. It is not a
substitute for `--help`: when the manual and `--help` disagree, the binary is the
authority. The console behavior is covered by `python tests/gui/test_gui.py`;
the MCP behavior by `python tests/mcp/test_mcp.py`.

The manual does not cover building the embedded browser page or packaging; see
[Build artifacts](../build-artifacts.md).

## Related documentation

- [Documentation index](../README.md)
- [Repository README](../../README.md)
- [GUI console](../gui.md) and [MCP server](../mcp-server.md)
- [Control plane](../control-plane.md) and [job model](../job-model.md)
- [JSON contracts](../json-contracts.md) and [error codes](../error-codes.md)
- [Troubleshooting](../troubleshooting.md) and
  [known limitations](../known-limitations.md)
