# Xtate 3.0 GUI design brief

**Status:** implementation brief for the 3.0 scan console. This document is
internal design guidance until the first screens are implemented and reviewed.

## 1. Product statement

The GUI is a **local scan console**, not a job dashboard. It must let a user:

1. see which interfaces exist and which one will carry the scan;
2. enter targets, scan mode, probe, ports, rate, timeout, and output;
3. run a preflight before any packet is sent;
4. explicitly confirm authorization;
5. start a scan and watch records arrive;
6. stop the scan and inspect/export results.

The control plane and job manager remain the execution backend. The user should
not need to know that a “job” exists.

## 2. Layout

Desktop-first, 1280×800 minimum, 1440×900 target, usable at 1024 wide.

```text
┌──────────────┬──────────────────────────────────────────────────────────┐
│ Xtate        │ New scan                          control ●   settings   │
│              ├──────────────────────────────────────────────────────────┤
│  New scan    │  New scan                                                │
│  Live scan   │  ┌──────────────────────────────┐  ┌─────────────────┐  │
│  Results     │  │ Target                       │  │ Preflight       │  │
│  Interfaces  │  │ [ 198.18.0.0/24           ]  │  │ route           │  │
│  Modules     │  │                              │  │ interface       │  │
│  Sessions    │  │ Scan mode   [cards]          │  │ link type       │  │
│              │  │ Probe / Ports / Rate         │  │ targets         │  │
│              │  │ Interface [select]           │  │ warnings        │  │
│              │  │ Advanced parameters          │  │                 │  │
│              │  │ [ ] I am authorized…         │  │ [ Start scan ]  │  │
│              │  └──────────────────────────────┘  └─────────────────┘  │
│ version      │                                                          │
└──────────────┴──────────────────────────────────────────────────────────┘
```

- Left rail: brand, primary navigation, version/control status.
- Top bar: page title, control-plane connection state, settings.
- Main canvas: two-column form + preflight card on “New scan”; full-width table
  on “Live scan” and “Results”.
- “Start scan” is disabled until preflight succeeds and authorization is
  checked.

## 3. Pages and states

### New scan

Sections:

1. **Target** — textarea for IP/CIDR sets; optional target file path; live
   parsed count; no scan starts on parse errors.
2. **Scan mode** — card grid, not a raw select: TCP SYN, TCP state, UDP,
   zbanner, ICMP, ARP/NDP where available. Each card shows a one-line purpose.
3. **Probe** — filtered by scan mode, with short description and dependency
   badge (OpenSSL, ngtcp2, Lua, PCRE2, etc.).
4. **Ports and rate** — port expression, rate, timeout, wait.
5. **Interface** — select with name, description, IPv4, link type, default
   badge; “auto” resolves the route and shows the result.
6. **Advanced** — module parameters rendered from metadata; collapsed by
   default; raw JSON request preview only in an advanced drawer.
7. **Preflight card** — target count, route groups, interface, source IP,
   gateway, link type, unsupported warnings, result path writability.
8. **Authorization** — explicit checkbox plus a short scope summary; server
   still requires `params.authorized=true`.

States: `idle`, `parsing`, `preflight-running`, `preflight-failed`,
`ready`, `starting`, `running`, `completed`, `failed`, `cancelled`.

### Live scan

- Header: target summary, scan mode, probe, interface, elapsed.
- Stat cards: sent, targets, packets/sec, ETA, errors.
- Progress bar based on sent/targets when targets is known.
- Live records table: time, target, port, level, classification, reason.
- Polling: status every 1 s; records incrementally, capped at 200 per request.
- Stop button requires confirmation; final state is shown explicitly.
- When complete, “Open results” becomes the primary action.

### Results

- Table with filter by level, port, protocol, and free text.
- Detail drawer with all fields and copyable raw record.
- Export NDJSON/CSV through the server; never fetch arbitrary local paths.
- Empty state explains whether the scan found nothing or is still running.

### Interfaces

- Cards first, table toggle optional.
- Each card: description, pcap name (truncated with copy), IPv4/IPv6, MAC,
  gateway, link type (`EN10MB`/`RAW`), default badge, state.
- Actions: use for new scan, test route, refresh.
- Unsupported link types are visually disabled with an explanation.

### Modules and help

- Tabs: Scan, Probe, Generate, Output.
- Search and filters; module detail shows description, parameters, defaults,
  dependencies, and examples.
- “Use in new scan” prefills the form.
- Help uses the same metadata as `--help` and the manual.

### Sessions

- Label “Scans in this session”, not “Jobs”.
- Row: target summary, scan mode, state, started, results count.
- Private-mode note: closing the GUI stops the private control plane and its
  scans.
- Advanced drawer reveals job id, result path, manifest path.

### Settings

- Control endpoint and connection state.
- Token present/absent (never display the token value).
- MCP command and Skill install path with copy buttons.
- Language (English/中文), theme (dark/light), reduced motion.
- Version, build options, module counts.

## 4. Visual system

### Direction

Professional instrument panel: calm, dense, precise. Avoid neon cyberpunk,
glassmorphism, oversized gradients, and decorative charts.

### Tokens

```css
--bg:        #0b0f14;
--surface:   #111821;
--surface-2: #16212c;
--line:      #263441;
--text:      #e8eef4;
--muted:     #8fa0b3;
--accent:    #66e3bd;
--accent-2:  #78c8ff;
--warn:      #f0b45c;
--danger:    #ff7d7d;
--ok:        #72d69b;
--radius:    12px;
--rail:      220px;
```

- Type: system UI stack; IPs, ports, protocols, and metrics in a monospace
  stack.
- 8 px spacing grid; page padding 32 px; card padding 20–24 px.
- Borders over shadows; one accent action per screen.
- Tables: sticky header, zebra only on hover, right-aligned numeric columns.
- Motion: 120–180 ms; respect `prefers-reduced-motion`.
- Focus: 2 px accent outline, never removed.
- Color is never the only status signal; pair with text/icon.

### Responsive

- ≥1280: rail + two columns.
- 1024–1279: rail collapses to icons; form and preflight stack.
- <1024: single column; tables become horizontally scrollable.
- No mobile-first requirement for 3.0, but the page must not break at 768.

## 5. Server and API changes

The current GUI only proxies `job.list`, `job.status`, `job.cancel`,
`job.result_manifest`, `job.start` through `/api/rpc`. Add local endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /api/system` | version, endpoint, build capabilities, module counts |
| `GET /api/interfaces` | structured adapters with link type/default |
| `GET /api/modules` | full module catalog with parameters |
| `POST /api/preflight` | target route + config validation |
| `GET /api/results?job_id=&offset=&limit=` | bounded records; server reads the result store |
| `POST /api/rpc` | existing job control methods |

Rules:

- All `/api/*` require `X-Xtate-GUI-Token`; page injection carries the token.
- `Host` must be loopback; reject DNS rebinding.
- Request body ≤64 KiB, response records ≤200 per call.
- No arbitrary path input for result reads; resolve through job metadata.
- No shell execution and no arbitrary control method forwarding.
- `job.start` requires `params.authorized=true` at the server, not only a
  checkbox.

## 6. Frontend implementation

Keep the zero-runtime-dependency approach:

- `web/gui/index.html`, `web/gui/app.js`, `web/gui/styles.css` as source files.
- `tools/build_gui_page.py` inlines CSS and JS into the generated
  `src/util-scan/gui-page.h` so the binary still needs no asset directory.
- Vanilla ES modules and DOM APIs; no CDN, no framework, no build toolchain.
- A small render/store pattern, no ad-hoc innerHTML with untrusted data.
- Escape all scan records and route/interface strings before display.
- Use `Intl.NumberFormat` for counts and rates.

## 7. Acceptance tests

- New scan: parse target, preflight route, select interface, authorize, start.
- Invalid target and unsupported link type never enable Start.
- Live scan: status and records update, stop reaches a terminal state.
- Results: filter and detail show the same record as NDJSON.
- Interfaces: default/link-type badges match `--explain-target`.
- Security: missing token 403, wrong Host 403, unauthorized start 403,
  path traversal rejected, no arbitrary method accepted.
- Visual: screenshots at 1024×768, 1280×800, 1440×900; no overlap or clipped
  controls.
- Windows and Linux.

## 8. First implementation slice

1. Add `/api/system`, `/api/interfaces`, `/api/modules`.
2. Replace the current page shell and build the New scan form with preflight.
3. Add Live scan polling and bounded results.
4. Add Interfaces and Modules pages.
5. Add Results export and Settings.
6. Only then expose remaining Xtate actions.
