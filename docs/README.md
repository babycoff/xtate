# Xtate Documentation

**English** · [中文](zh-CN/README.md)

This directory is the user manual for **Xtate v2.42.0** — a modular all-stack network scanner for Internet-scale surveys.

The [README](../README.md) is the landing page. Start here if you want to use Xtate rather than skim its feature list.

**Release notes:** [2.42.0](./release-notes/2.42.0.md) — managed jobs, control plane and MCP server.

## Where to start

| If you are… | Read |
|---|---|
| New to Xtate | [Getting started](./getting-started.md) |
| Planning a scan | [Targets and ports](./targets-and-ports.md) → [Scanning modes](./scanning-modes.md) |
| Wiring results into a pipeline | [Output](./output.md) → [Aggregation](./aggregation.md) |
| Choosing a module | [Modules](./modules.md) |
| Writing a module | [Module development](./module-development.md) |
| Planned work | [Roadmap](./roadmap.md) → [P3/P4 feasibility](./feasibility.md) |
| HTTP probe quality | [HTTP probe audit](./http-probes-audit.md) |
| Parser testing | [Parameter parser plan](./parser-test-plan.md) |
| Protocol expansion | [Protocol coverage plan](./protocol-coverage.md) |
| DNS over HTTPS | [DNS over HTTPS](./dns-over-https.md) |
| DNS over TLS | [DNS over TLS](./dns-over-tls.md) |
| Input/output audit | [Input/output audit](./input-output-audit.md) |
| Job model | [Job model](./job-model.md) |
| Automating scans / AI client | [Agent Skill](./agent-skill.md) → [MCP server](./mcp-server.md) → [Control plane](./control-plane.md) |
| Large target files or stream input | [Input modules](./input-modules.md) |
| Error codes | [Error codes](./error-codes.md) |
| JSON contracts | [JSON contracts](./json-contracts.md) |
| AI integration design | [AI integration design](./ai-integration.md) |
| Linux firewall | [Linux firewall prerequisite](./firewall.md) |
| Curious how it works | [Architecture](./architecture.md) → [ZBanner](./zbanner.md) / [HLTCP](./hltcp.md) / [TLS composition](./tls-composition.md) |
| Stuck | [Troubleshooting](./troubleshooting.md) → [Known limitations](./known-limitations.md) |
| Chinese help / localization | [Help i18n](./help-i18n.md) |
| Windows first try | [Windows quick start](./windows-quickstart.md) |
| Windows optional dependencies | [Windows dependencies](./windows-dependencies.md) |
| Build artifact names | [Build artifacts](./build-artifacts.md) |
| Interactive mode | [Interactive mode](./interactive-mode.md) |
| Platform / build compatibility | [Platform support](./platform-support.md) |
| Testing and compatibility policy | [Testing policy](./testing.md) |
| Plugin protocol (Go sidecar) | [Plugin protocol](./plugin-protocol.md) |

## Contents

### Using Xtate

- [Getting started](./getting-started.md) — build, permissions, first scan, firewall
- [Targets and ports](./targets-and-ports.md) — IPv4/IPv6 input, files, ASN, excludes, sharding
- [Scanning modes](./scanning-modes.md) — stateless vs stateful, scan/probe pairings, recipes
- [Output](./output.md) — result levels, text/CSV/NDJSON/BSON/MongoDB, escaping
- [Aggregation](./aggregation.md) — post-run NDJSON aggregation, schema and scale
- [Modules](./modules.md) — the four module types and the modules that ship with Xtate
- [Module development](./module-development.md) — C interfaces, registration and ProbeSlotPlan examples
- [Roadmap](./roadmap.md) — completed work and planned P2/P3 changes
- [HTTP probe audit](./http-probes-audit.md) — current gaps and rewrite plan
- [Parameter parser plan](./parser-test-plan.md) — coverage and harness design
- [Protocol coverage plan](./protocol-coverage.md) — zgrab2-referenced protocol matrix and batches
- [P3/P4 feasibility](./feasibility.md) — target selection, adaptive rate, templates and traffic randomization
- [Chinese help and i18n](./help-i18n.md) — `--lang`, catalog fallback and UTF-8 help layout
- [Windows quick start](./windows-quickstart.md) — beginner install, Npcap, build, first scan and troubleshooting
- [Windows optional dependencies](./windows-dependencies.md) — vcpkg/MSYS2 setup for PCRE2, LibXml2, bson/mongoc and MinGW caveats
- [Build artifacts](./build-artifacts.md) — aliases vs per-toolchain binaries, Debug names and DLLs
- [Interactive mode](./interactive-mode.md) — commands, TTY/script mode, history and completion
- [Platform support](./platform-support.md) — old CMake/distro baseline, Ninja and musl builds
- [Testing policy](./testing.md) — Tier 0/1/2 checks, matrix and evidence rules
- [Plugin protocol](./plugin-protocol.md) — Go sidecar boundary, result envelope and non-goals

### Automation and integration

- [MCP server](./mcp-server.md) — stdio tools, resources, prompts, route planning and limits
- [Control plane](./control-plane.md) — local JSON-lines API shared by MCP/TUI/GUI
- [Job model](./job-model.md) — managed jobs, timeout, heartbeat, cancellation and results
- [Input modules](./input-modules.md) — static targets vs generate streams and error policy
- [Agent Skill](./agent-skill.md) — installable playbook for external agents using MCP
- [JSON contracts](./json-contracts.md) — scan-request, module metadata and error schemas
- [AI integration design](./ai-integration.md) — boundaries, safety requirements and remaining work

### How it works

- [Architecture](./architecture.md) — threads, queues, the scan pipeline
- [ZBanner](./zbanner.md) — stateless TCP responses and banner grabbing
- [HLTCP](./hltcp.md) — the hybrid-state TCP stack, TLS, and nested probes
- [QUIC state](./quic-state.md) — optional ngtcp2/GnuTLS QUIC handshake scanner and sub-probes
- [HTTP response matching](./matching.md) — keyword/regex and header/body/all scopes for HTTP/1, h2 and http3
- [ZBanner audit](./zbanner-audit.md) — state-machine findings, boundaries and refactor plan

### When things go wrong

- [Troubleshooting](./troubleshooting.md) — no replies, kernel RST, pcap/Npcap, output surprises
- [Known limitations](./known-limitations.md) — what Xtate deliberately does not do (yet)

## A note on accuracy

Xtate's command-line help is the source of truth for flags:

```bash
xtate --help
xtate --help-scan <module>
xtate --help-probe <module>
```

The docs are written against the v2.42.0 tree. If you are on a newer commit and something differs, trust the binary and please open an issue.

## Planned

These are not written yet:

- Generated CLI and per-module reference

Recipes for common surveys (HTTP banners, TLS certificates, IPv6, LAN discovery)
live in [Scanning modes](./scanning-modes.md#recipes).

A browsable documentation site is planned as a separate step; for now everything is plain Markdown in this directory.
