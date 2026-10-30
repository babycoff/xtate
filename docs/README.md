# Xtate Documentation

**English** · [中文](zh-CN/README.md)

This directory is the user manual for **Xtate v2.14.2** — a modular all-stack network scanner for Internet-scale surveys.

The [README](../README.md) is the landing page. Start here if you want to use Xtate rather than skim its feature list.

## Where to start

| If you are… | Read |
|---|---|
| New to Xtate | [Getting started](./getting-started.md) |
| Planning a scan | [Targets and ports](./targets-and-ports.md) → [Scanning modes](./scanning-modes.md) |
| Wiring results into a pipeline | [Output](./output.md) |
| Choosing a module | [Modules](./modules.md) |
| Curious how it works | [Architecture](./architecture.md) → [ZBanner](./zbanner.md) / [HLTCP](./hltcp.md) |
| Stuck | [Troubleshooting](./troubleshooting.md) → [Known limitations](./known-limitations.md) |

## Contents

### Using Xtate

- [Getting started](./getting-started.md) — build, permissions, first scan, firewall
- [Targets and ports](./targets-and-ports.md) — IPv4/IPv6 input, files, ASN, excludes, sharding
- [Scanning modes](./scanning-modes.md) — stateless vs stateful, scan/probe pairings, recipes
- [Output](./output.md) — result levels, text/CSV/NDJSON/BSON/MongoDB, escaping
- [Modules](./modules.md) — the four module types and the modules that ship with Xtate

### How it works

- [Architecture](./architecture.md) — threads, queues, the scan pipeline
- [ZBanner](./zbanner.md) — stateless TCP responses and banner grabbing
- [HLTCP](./hltcp.md) — the hybrid-state TCP stack, TLS, and nested probes

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

The docs are written against the v2.14.2 tree. If you are on a newer commit and something differs, trust the binary and please open an issue.

## Planned

These are not written yet:

- Recipes for common surveys (HTTP banners, TLS certificates, IPv6, LAN discovery)
- A module-writing guide (Scan/Probe/Output/Generate in C)
- Generated CLI and per-module reference

A browsable documentation site is planned as a separate step; for now everything is plain Markdown in this directory.
