# Troubleshooting

**English** · [中文](zh-CN/troubleshooting.md)

Most Xtate problems are one of five things: the wrong interface or source address, a packet filter eating the replies, the kernel resetting connections it does not know about, a rate that is too high for the path, or results that are being produced but not printed.

Work through the sections in order; each one gives a command you can run to confirm or eliminate the cause.

## Get more diagnostics first

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 443 -scan tcp-syn -rate 100 -show info -show failed -d
```

- `-d`, `-dd`, `-ddd` raise the log level from the default (errors, warnings, hints) to info, debug and detail. Logs and the live status bar go to **stderr**; results go to **stdout**.
- `--echo` prints the effective configuration (diff from defaults) and exits — useful for checking what actually got parsed.
- `--packet-trace` prints every SENT/RCVD packet (addresses, ports, TCP flags) to **stdout**, interleaved with results. Combine it with `--offline` (do not transmit) and a low `-rate 1` to inspect packet construction without touching a network.
- `--pcap capture.pcap` saves **received** packets (not transmitted ones); open the file in Wireshark.
- `./firewall/check_rules.sh` shows the current `iptables`/`ip6tables` OUTPUT rules.

A quick triage before reading further:

| Symptom | Most likely cause |
|:---|:---|
| No output at all, process exits immediately | Missing module/probe pairing, empty target list, bad interface |
| Some targets answer, others do not | Rate too high, rate limit/firewall on the path, NAT |
| Open ports found, banners never arrive | Kernel RST, missing firewall rules |
| Results in the file but not on screen | Output module selected, level filtered |
| Nothing received, no errors | BPF filter, wrong `-src-ip`/`-src-port`, wrong adapter |

## Nothing comes back at all

Check in this order:

1. **Module pairing.** Xtate refuses to start with `ScanModule <x> needs probe of <type> type.`; `tcp-syn` uses no probe, `zbanner` needs a TCP probe, `udp` a UDP probe, `tcp-state` a STATE probe. Confirm names with `--list-scan` / `--list-probe` and parameters with `--help-scan <module>`.
2. **Targets and ports are non-empty.** No targets gives `target IP address list empty.` No ports gives a warning and a fake `o:0` endpoint, so a TCP scan quietly probes nothing. Always pass `-p`.
3. **Interface and source address.** `sudo ./bin/xtate --list-if` lists adapters; auto-detection picks the first interface with a default gateway. Force one with `-if eth0` (on Windows, adapters also accept the numeric index from `--list-if`, e.g. `-if 3`). A wrong `-src-ip`/`-src-port` makes replies fail the `is_my_ip`/`is_my_port` check and they are dropped silently; source ranges must have a power-of-two size.
4. **Packet filter.** Each scan module installs its own BPF filter; `--bpf-filter` *replaces* it, and a filter that is too narrow hides valid replies. Re-run the same scan with `--no-bpf` — if results appear, the filter (yours or the module's) is the problem. One known case: the built-in `tcp-syn` filter matches a bare RST exactly, so closed ports answered with RST+ACK can be filtered before Xtate sees them; `--no-bpf` confirms it.
5. **Router MAC / ARP.** Startup can fail with `arp timed-out resolving MAC address for router ...`. Use `--router-ip <gw>` if discovery picked the wrong gateway, or bypass ARP with `--router-mac 66-55-44-33-22-11` (a router MAC on a different L2 segment only makes sense with `--lan`).
6. **The path itself.** Check from a normal client whether the target answers at all; then mirror the same ports/rate with `tcpdump` or Xtate's `--pcap`. A firewall or NAT device in front of the target can drop probes while SYN-ACKs never return.

## Open ports but no banner, or the connection dies immediately

This is the classic kernel-RST symptom. The kernel sees replies for a TCP connection it knows nothing about and sends a RST; the server tears the connection down before the payload/banner exchange finishes.

Test and fix:

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http -scan-arg "-banner" -rate 500
./firewall/rm_rules.sh
```

- If the banner now appears, the kernel was the problem. The scripts DROP outgoing TCP RST (IPv4 and IPv6) and ICMP port-unreachable (ICMP 3/3 and ICMPv6 1/4).
- The rules are host-wide: while they are installed, every outgoing RST from the machine is dropped, which breaks unrelated local connections. Never leave them on.
- For UDP scans the same interference exists via ICMP port-unreachable, which is why the scripts drop that too.
- On Windows there is no bundled script; handshake-based banner scans are unreliable there for the same reason.

## Permission, adapter and platform errors

| Message | Cause and fix |
|:---|:---|
| `need to sudo or run as root or administrator` / `can't open adapter` | Raw sockets need privileges; use `sudo` (Linux) or an elevated shell (Windows) |
| `could not determine default interface` | No default gateway visible; pass `-if <name>` |
| `failed to detect IP of interface` | Adapter has no usable IP; set `-src-ip` manually |
| `(libpcap) failed to load` / `couldn't load wpcap.dll` | libpcap missing on Linux; Npcap missing on Windows |
| `no pfring adapter available. Please install pfring or run xtate without the --pfring option.` | You forced `--pfring`; drop the flag to fall back to pcap |
| `(pfring) 'pf_ring' driver module not found!!!` | Informational only, unless `--pfring` was given |

On Linux, `sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate` avoids `sudo` per run; re-apply it after rebuilding the binary.

IPv6 has its own traps: a link-local source address must be given explicitly (`-src-ip fe80::2`), and NDP scans normally need `-fake-router-mac` because there is no IPv6 default gateway to resolve — `-scan ndp-ns -src-ip fe80::2 -fake-router-mac` is the working shape. IPv6 extension headers (other than hop-by-hop) and fragments are not parsed, so such replies are invisible to the scanner.

## Packet capture, PF_RING and Npcap

- `--pcap out.pcap` records **received** frames only; transmitted packets are not in the file. Use `--packet-trace` if you need to see what Xtate sends.
- The capture is still subject to `--max-packet-len` (default 1514). For jumbo frames, VLANs or multi-KB TLS records, raise `--max-packet-len` and `--adapter-snaplen` (default 65535).
- PF_RING is loaded at runtime from `libpfring.so` and selected automatically for DNA-style adapter names. If the library is missing you only get a debug-level message and Xtate falls back to libpcap; an `ERROR` about the `pf_ring` driver module is harmless unless you passed `--pfring`.
- Forcing `--pfring` without a working DNA adapter aborts at startup; remove the flag to fall back to libpcap.
- On Windows, the adapter is opened through Npcap's `wpcap.dll`. If Npcap is missing, scans fail with `(libpcap) failed to load` / `can't open adapter: pcap`. Install Npcap and re-run elevated. Windows receive uses blocking `pcap_next_ex`, so very high rates can lose replies even when transmission keeps up — lower the rate or scan smaller ranges.

## Rate too high, packet loss, or an unhappy network

- The default rate is **100 packets/s**; the total is split across Tx threads. Start at `-rate 1000` for a lab subnet, not `-rate 1000000`.
- Watch the status bar: queue levels and hit rate show whether the Tx/Rx pipeline is saturated. `--print-status queue` makes queue occupancy explicit.
- Too-high rates show up as missing results on every module, not as errors. Halve the rate and compare; also test with a single host and a single port to remove scope effects.
- For late replies, `--wait <seconds>` (default 10) keeps receive/handle threads alive after transmission ends.
- Linux can use `--raw-socket --sendmmsg` for high packet rates (sendmmsg batches by default 64). Do not enable sendmmsg for slow, stateful scans — the added latency hurts connection-based modules.
- On Windows, `--send-queue` raises transmit throughput substantially but adds latency; keep it off for `zbanner`/`tcp-state`.

## Results exist, but you cannot see them

1. **Levels are filtered.** By default only `success` results are printed. `tcp-syn` marks closed ports as `failed`; `zbanner` and `udp` report port open/closed results at `info` level by default — promote them with the module's own parameters (e.g. `-scan-arg "-port-failure"` for `udp`, `-port-success`/`-port-failure` for `zbanner`). Add `-show failed` and/or `-show info`; use `--no-show-output success` to hide successes.
2. **Output module vs stdout.** With no `-output`, results only go to stdout. With `-output csv -o results.csv`, they only go to the file — add `--output-screen` to also see them, or use `-o -` where the module supports stdout.
3. **Deduplication.** Duplicate SYN-ACK/RST/banner packets are dropped by default. Try `--no-dedup`, raise `-dedup-win`, or for `zbanner` allow repeats explicitly: `-scan-arg "-repeat-banner"` (likewise `-repeat-synack`, `-repeat-ack`, `-repeat-rst`).
4. **Module-level `no_output`.** `zbanner` suppresses repeated packets before any output, and failed regex matches are `failed` level. If you scan with `-probe http -probe-arg "--regex <pattern>"`, non-matching banners will not appear without `-show failed`.
5. **Stateful scans do not report closed ports.** `tcp-state` only creates output for connections it could establish (see the next section).

## Behaviour that looks wrong but is expected

- **`tcp-state` never reports closed ports.** A RST for an unknown connection has no TCB and is dropped; only open, handshake-completing targets produce results.
- **`tcp-state` loses targets silently.** SYN is sent once with no retransmission; a lost SYN means no result for that target. Re-run the range (e.g. with `--repeat 1`) or lower the rate.
- **`tcp-state` latency and packet counts look odd.** HLTCP uses a fixed 1-second RTO and the default TCP window is 1024 bytes, producing many small packets. `-tcp-win 8192` (plus a matching `--max-packet-len`) is usually faster.
- **`zbanner` classifies zero-window SYN-ACKs as `fake-open`** (`because "zerowin"`) and does not send the probe payload. This is a SYN-backlog/firewall signal, not necessarily a closed port.
- **`zbanner` grabs only the first banner segment** by default and then sends RST. Long banners, multi-segment TLS ServerHellos or large HTTP headers need `-scan-arg "-all-banner"` (optionally bounded with `-all-banner-limit <n>` inside the same string).
- **TLS probes appear to return nothing.** `tls-state` reports a failed handshake at `info` level, and it sends no SNI or ALPN, so virtual hosts/CDNs may answer with their default certificate/site. Add `-show info`, or promote failures to `failed` with `-probe-arg "-fail-handshake"`; treat stateful TLS evidence as the default virtual host, not as the requested hostname.

These are design trade-offs in v2.14.1, not bugs; the full list with workarounds is in [Known limitations](./known-limitations.md).

## Modules are missing or refuse to start

- Compile-time optional dependencies remove modules entirely: without OpenSSL there is no `tls-state`/`jarm`, without PCRE2 no `recog`/`nmap`, without libbson/libmongoc no `bson`/`mongodb` output. Check `--list-probe` / `--list-out` against the dependency table in [Getting started](./getting-started.md), install the dev packages and rebuild.
- Lua probes are always listed but fail at startup when the runtime library is absent: `(liblua) failed to load Lua shared library` / `you must install Lua library`. Install Lua 5.3 or 5.4 (`liblua5.3`/`liblua5.4` on Debian/Ubuntu) or use a non-Lua probe.
- `--version` prints the build type, compiler and build date — include it in any bug report.

## JSON or CSV output is corrupt

- Text values (banners, HTTP bodies, TLS fields) are escaped as `\xNN` by default, which is **not** valid JSON escaping. Add `--no-escape-char` to get JSON-compatible strings.
- Do not use `--no-escape-char` with BSON/MongoDB output; those modules handle binary/escaping themselves.
- `classification` and `reason` are printed verbatim by the CSV/NDJSON writers; a quote or newline coming from a probe can break a record. If that happens, switch to BSON or filter the data downstream.
- A broken JSON record is often a truncation problem, not an escaping one: check `--max-packet-len` and `--tcp-win` before blaming the writer.

## What to collect for a bug report

Command line (start from `--echo` output), `--version`, the log at `-d`/`-dd`, a `--pcap` capture of the received traffic, and the exact target/port that misbehaved. Do not include unrelated production captures.
