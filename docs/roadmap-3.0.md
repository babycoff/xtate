# Xtate 3.0 roadmap

**English** · [中文](zh-CN/roadmap-3.0.md)

This is the working plan for Xtate 3.0. It starts from the released 2.44.2
codebase. It is a scope and acceptance document, not a promise of dates.

## Product definition

Xtate 3.0 is a product-level release built on four deliverables:

1. **A scan console GUI.** The GUI is the primary human interface: choose a
   target, inspect the route and interface, set scan parameters, authorize,
   start, watch results live, and stop or export. It is not a job monitor with
   a form bolted on.
2. **AI-native operation.** External agents use Xtate through MCP and the Agent
   Skill. Xtate does not embed an LLM, API keys, or a chat service.
3. **Protocol depth.** HTTP/1.1 and HTTP/2 are supported on Windows and Linux.
   HTTP/3 and QUIC transport are supported on Linux where ngtcp2/GnuTLS is
   available; Windows keeps the capability probe and shows an explicit
   unsupported state instead of pretending the transport exists. Both are
   documented, tested against local peers, and visible in the GUI/MCP catalog
   when the build supports them.
4. **A real bilingual manual.** A structured manual, generated module
   reference, in-app help, and CLI help share one source of truth.

### TUI

The TUI is not part of 3.0. Existing `--tui` is a 2.44.x feature, is deprecated
in the 3.0 documentation, and receives no new work. The code may remain until
the GUI covers the supported actions, then it is removed. The GUI is the only
supported interactive interface.

### Non-goals for 3.0

- No embedded LLM, cloud account, telemetry, or hosted scanning service.
- No arbitrary shell execution from the GUI or MCP.
- No scanning without explicit authorization.
- No attempt to expose every experimental module in the first GUI release.
- No silent protocol claims: a QUIC transport response is not HTTP/3 success.

## Current gaps (2.44.2 baseline)

| Area | Baseline | 3.0 target |
|---|---|---|
| GUI | One page that lists jobs and proxies a small `job.*` allowlist | Scan-first workspace with interfaces, modules, live records, results, help |
| GUI data | Only job list/status/manifest/cancel/start | Structured interfaces, module metadata, preflight, bounded record reads |
| AI | MCP supports static targets or `include_file`; control plane must be started separately | One-command MCP, complete tool surface, streamed results, generate input, Skill v2 |
| HTTP/1.1 | `http` and `http-state` exist | Audited request/response parsing, chunked bodies, TLS composition, tests |
| HTTP/2 | `h2` (TLS/ALPN) and `h2c` exist | Audited HPACK/frames/settings/GOAWAY, local interop tests |
| HTTP/3 | `http3-state` exists but is optional and depends on ngtcp2/GnuTLS | Linux release build with QPACK/static-table coverage and interop tests; Windows reports unsupported |
| QUIC | `quic` capability probe; optional `quic-state` transport | Linux release build with version/retry/handshake tests; Windows keeps the capability probe |
| Docs | Many focused pages, counts drift, no single manual | Manual + generated reference + bilingual parity gate |

The current Windows module catalog shows 11 scan modules and 59 probe modules;
`quic-state` and `http3-state` are absent when ngtcp2 is not found. There is no
reliable Windows ngtcp2 build path yet, so 3.0 accepts HTTP/3 and QUIC transport
as **Linux-only**, while Windows reports the capability as unsupported. The
dependency state must be explicit in the module catalog, GUI, MCP and manual;
the release matrix tests the Linux transport path.

## Workstream A — GUI scan console

### Information architecture

- **New scan** (default page): target, scan mode, probe, ports, rate, timeout,
  interface, result path, advanced module arguments, preflight, authorization,
  start.
- **Live scan**: progress, sent/targets, rate, elapsed/ETA, live records,
  filters, stop.
- **Results**: records for the selected scan, search/filter, detail drawer,
  export.
- **Interfaces**: adapter cards/table with IPv4/IPv6, MAC, gateway, link type,
  default route, state, and “use this interface”.
- **Modules & help**: scan/probe/generate/output catalog, parameters, examples,
  bilingual help, “use in new scan”.
- **Sessions**: scans in the current control-plane session; clear explanation
  of private-mode lifetime.
- **Settings**: endpoint/token status, MCP command/config copy, language,
  theme, diagnostics.

The word “job” is not part of the primary UI. A job id appears only in an
advanced detail drawer.

### Required backend additions

- `iface.list`: structured adapters, including link type and default route.
- `iface.explain`: route/source/gateway/link-type preflight for a target.
- `module.list` / `module.describe`: registry metadata for forms and help.
- `scan.preflight`: one call that validates targets, route, and scan config.
- `job.records`: bounded offset/limit reads of result records. The GUI must not
  read arbitrary paths from the browser.
- Status fields or derived UI fields for packets/sec and ETA.

Security rules stay: loopback bind, Host validation, per-run session token,
method allowlist, explicit `authorized=true`, no shell, bounded request bodies.

### Visual direction

The design target is a professional instrument panel, not an admin dashboard:

- graphite dark surface with a restrained mint/cyan accent; optional light theme
- left navigation, top context bar, main workspace
- 8 px spacing grid; clear type scale; monospace for IPs, ports, and protocols
- dense but calm data tables; skeleton loading; inline actionable errors
- keyboard navigation, visible focus, reduced-motion support
- no external CDN and no runtime asset directory

Prototype first, then implement. The first release covers the primary path plus
interfaces, modules, and results; the remaining Xtate actions follow.

### Acceptance

- A new user can go from launch to an authorized scan in under 60 seconds
  without reading CLI documentation.
- The route, interface, link type, and parameter errors are visible before the
  first packet.
- Live results appear during the scan; stop is confirmed and terminal states are
  unambiguous.
- No primary screen requires understanding a job id.
- Core flows pass on Windows and Linux, with browser tests and screenshots.

## Workstream B — AI and MCP

- `xtate --mcp` starts a private control plane like `--gui` does.
- MCP tools for interfaces, module catalog, preflight, bounded result reads,
  status, and cancel.
- Generate/stream input support, not only static `targets`/`include_file`.
- Agent Skill v2 covering the GUI-equivalent flow, safety rules, and errors.
- Evaluation scenarios: an agent must preflight, authorize, start, monitor, and
  read results without source-code knowledge.
- GUI settings can copy the MCP command and Skill install path.

## Workstream C — protocol support

Define a support matrix and test each cell:

| Protocol | Windows | Linux | Required behavior |
|---|---|---|---|
| HTTP/1.1 | supported | supported | request methods/headers/body, chunked response, match scopes, TLS composition |
| HTTP/2 | supported | supported | `h2` over TLS and `h2c`, HPACK, SETTINGS, DATA, GOAWAY/RST |
| HTTP/3 | not supported in 3.0 | ngtcp2/GnuTLS builds | `http3-state` on `quic-state`, QPACK static table/Huffman, GET/POST, headers/body |
| QUIC | capability probe only | ngtcp2/GnuTLS builds | `quic` probe plus `quic-state` transport: Version Negotiation, Retry, Initial, Handshake |

Build and test HTTP/3/QUIC transport on Linux with ngtcp2/GnuTLS. Windows must
show an explicit unsupported capability; it must not fail silently or claim the
transport exists. Local peers (nghttp2, nghttp3, aioquic or quic-go) and a small
real-endpoint sample form the interop matrix.

## Workstream D — manual and help

Create `docs/manual/` with:

1. install and quick start
2. GUI guide (every page and field)
3. targets, ports, interfaces
4. scan modes
5. probe reference, including separate HTTP/1, HTTP/2, HTTP/3, QUIC chapters
6. output and results
7. MCP, Agent Skill, automation
8. troubleshooting (fake-IP, TUN, firewall, permissions)
9. security and authorization
10. full parameter reference

Module reference is generated from the module registry. GUI help, `--help`, and
the manual use the same metadata. English and Chinese must have matching
chapters and zero broken links.

## Workstream E — Ubuntu 24.04 full-feature build environment

Ship a standard Docker build environment so users can reproduce the fully
featured Linux build without assembling dependencies by hand. Linux is the
reference platform for HTTP/3 and QUIC, so this image is also the supported way
to exercise those features.

Deliverables:

- `docker/ubuntu24-build/Dockerfile` based on `ubuntu:24.04`, installing the
  complete optional dependency set: OpenSSL, PCRE2, libxml2, libbson/mongoc,
  ngtcp2/GnuTLS, zstd and Lua. Pin package versions where the Ubuntu archive is
  known to drift; document any source-built dependency and its checksum.
- `scripts/build-docker-full.sh` and a PowerShell wrapper. Both accept
  `--mirror=official|tuna|ustc|aliyun` (or `APT_MIRROR`), default to the
  official archive, and can produce a binary into a mounted output directory.
- Mainland mirror presets rewrites both `archive.ubuntu.com` and
  `security.ubuntu.com` (and `ports.ubuntu.com` on arm64); the Docker build must
  not hard-code a single mirror.
- The build verifies `cmake`, Release build, `--selftest`, `--list-capabilities`
  and the core test suites. The capability JSON must report `http3:true`,
  `quic_transport:true` and `zstd:true` on Linux.
- GUI access from the Docker host is part of the acceptance test. The documented
  paths are host networking (`--network=host`, GUI bound to `127.0.0.1`) and an
  explicit opt-in bind for port publishing (`--gui-listen=0.0.0.0:8787` with
  `-p 127.0.0.1:8787:8787`). Port publishing must keep the per-session token,
  Host validation and loopback-only host exposure; the GUI must never be
  reachable from a non-loopback host address by default.
- `docs/docker-build.md` + Chinese translation, linked from install/quickstart
  and the manual. Include build, mirror, GUI-access, troubleshooting and
  cleanup examples.
- CI uses the same image for Linux builds so local and CI results cannot drift.

Acceptance: a clean Ubuntu host can build and run the full Linux binary with the
documented command, all optional capabilities are present, and GUI port
publishing works without weakening the security defaults.

## Phases

| Phase | Output | Exit gate |
|---|---|---|
| P0 design and baseline | 3.0 scope, GUI brief, static prototypes, gap/API list | visual direction approved |
| P1 AI/MCP | one-command MCP, tools, result reads, Skill v2, eval baseline | agent completes a safe scan without source reading |
| P2 GUI backend | interface/module/preflight/records APIs, security tests | API contracts stable |
| P3 GUI console | new scan, live, results, interfaces, modules/help | core flows pass Windows/Linux |
| P4 protocols | HTTP/1/2 audit, Linux HTTP/3/QUIC build and interop, Windows capability reporting | protocol matrix green |
| P5 manual/help | bilingual manual, in-app help, example checks | zero broken links, parity gate |
| P6 hardening/release | Ubuntu 24.04 full-feature Docker environment, CI, ASan/fuzz, performance, security, RC | release gate below |

P1 and P2 can run in parallel; P5 starts early and finishes alongside P4/P6.

## Release gate

3.0.0 is not released until:

- no P0/P1 defects and no High security findings;
- Windows and Linux full suites pass;
- GUI core flows have browser/e2e coverage;
- HTTP/1.1 and HTTP/2 interop tests pass on Windows and Linux;
- HTTP/3 and QUIC transport interop tests pass on Linux, and Windows reports the unsupported state explicitly;
- ASan/UBSan, fuzz, and config fuzzing show no new findings;
- the Ubuntu 24.04 Docker image builds the full feature set and its GUI
  publishing path is verified from the host;
- the manual has zero broken links and bilingual chapter parity;
- every module is visible and explained in CLI/GUI/MCP;
- version, tag, release notes, checksums, and source archives are complete;
- migration notes exist for 2.44.x → 3.0.0.

## Immediate next steps

1. Mark TUI deprecated in 3.0 docs; remove it after the GUI covers the supported actions.
2. Review the static GUI prototypes and pick a visual direction.
3. Record the API gap list and protocol build gap list as implementation tasks.
4. Implement the scan-first GUI shell and backend slice.
5. Build the Ubuntu 24.04 full-feature Docker environment with mainland mirror
   presets and host GUI access.
6. Run a first usability review with screenshots before expanding scope.
