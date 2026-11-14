# 09 · Troubleshooting

This chapter is a diagnostic order, not a list of random tips. Xtate failures
cluster into five causes, and checking them in the right order finds most
problems in a few minutes:

1. the wrong interface or source address;
2. a packet filter eating the replies;
3. the kernel resetting connections it does not know about;
4. a rate the path cannot carry;
5. results that exist but are filtered out of the display.

Work top to bottom, and collect evidence with the commands below before
changing anything. Two things stay true for every section: raw scans need
`sudo`/Administrator, and Linux scanners doing handshake-based scans need the
firewall rules installed.

## Collect evidence first

| Tool | What it shows |
|:---|:---|
| `-d`, `-dd`, `-ddd` | Higher log levels. Logs and the live status bar go to stderr; results to stdout. Default level shows errors, warnings and hints. |
| `--echo` | Prints the effective configuration, including values that differ from defaults, then exits. Start a bug report from this output. |
| `--packet-trace` | Prints every SENT and RCVD packet (addresses, ports, TCP flags) to stdout. Combine with `--offline` and `-rate 1` to inspect packet construction without a network. |
| `--pcap capture.pcap` | Saves the packets Xtate received (received only, not transmitted) for Wireshark. |
| `./firewall/check_rules.sh` | Shows whether the Linux OUTPUT DROP rules are installed. |
| `--explain-target=<target> --check` | Shows the selected interface, source address, gateway, link type and route groups before scanning. |
| `xtate --version` | Build type, compiler and build date; include this in every report. |

A useful first command on Linux is therefore:

```bash
sudo xtate -ip 198.51.100.10 -p 80 -scan zbanner -probe http \
  -d -dd --pcap /tmp/xtate.pcap --explain-target=198.51.100.10 --check
```

## Quick triage

| Symptom | Likely cause | First action |
|:---|:---|:---|
| No output at all, process exits immediately | Module/probe pairing error, empty target list, bad interface | Read stderr; check `--list-scan`/`--list-probe` |
| Some targets answer, others do not | Rate too high, rate limit/firewall/NAT on the path | Halve `-rate`; test one host |
| Ports show `open` but no banner/TLS result | Kernel RST, missing firewall rules | `./firewall/check_rules.sh`, install rules |
| Results in the file but not on the screen | Output module selected, level filtered | `--output-screen` or `-o -`; `-show info`/`-show failed` |
| Nothing received, no errors | BPF filter, wrong `-src-ip`/`-src-port`, wrong adapter | `--no-bpf`; `--explain-target`; `--list-if` |
| Everything open, including hosts that should be down | Fake-IP/TUN adapter, or a middlebox answering for everything | `--explain-target`; resolve real addresses |

## 1. Linux firewall rules (check this first for stateful scans)

If `zbanner`, `tcp-state`, `tls-state`, `http-state`, the H2/HTTP3 probes or any
state sub-probe returns `open` and nothing else, the most common cause is the
missing RST/ICMP suppression rules. The Linux kernel does not know about the
handshake Xtate performed in user space, so it answers the peer's packets with
its own RST and the connection dies before the banner, TLS handshake or
protocol response arrives.

```bash
sudo ./firewall/add_rules.sh
sudo ./firewall/check_rules.sh
# ... run the scan ...
sudo ./firewall/rm_rules.sh
```

The rules are host-wide: they drop outgoing TCP RSTs (IPv4 and IPv6) and ICMP
port-unreachable during the scan. Never leave them installed on a shared host —
they change unrelated connections' behavior. Xtate warns at startup when a scan
that needs the rules runs without them:

```text
[WRN] firewall RST/ICMP suppression rules are missing
[HIN] run: sudo ./firewall/add_rules.sh   (Linux scanner host; never leave it installed)
```

`tcp-syn` and stateless TCP port scans do not need these rules. UDP scans do not
need TCP RST suppression, though the ICMP rule avoids useless retransmissions.
On Windows there is no bundled script: do not run the Linux script there, and
remember that handshake-based banner scans depend on the Windows stack not
resetting those connections.

## 2. Module and probe pairing

Xtate refuses to start with a mismatched pair rather than guessing:

```text
ScanModule zbanner needs probe of tcp type.
```

The rules are:

- `tcp-syn` takes no probe;
- `zbanner` takes a probe of type `tcp` (for example `http`, `hello`,
  `tls-hello`, `h2c`);
- `udp` takes a probe of type `udp` (for example `dns`, `echo`, `snmp`);
- `tcp-state` takes a probe of type `state` (for example `tls-state`,
  `http-state`, `hello-state`, `h2`, `dot`, `doh`, `doh-h2`).

Check the registry and the module's help:

```bash
xtate --list-probe
xtate --list-scan
xtate --help-probe tls-state
xtate --help-scan tcp-state
```

Probe arguments are one quoted string: `-probe-arg "--sni example.com -alpn h2"`.
State probes are composed through `tls-state`, which has no usable default
sub-probe — always pass `-subprobe` (or `-sub-probe-module`) with a state-type
probe.

## 3. Targets and ports are not empty

Two startup messages are easy to miss:

- `target IP address list empty.` — no targets were parsed. Check the target
  syntax, the `-ip` value, and any file/list expansion.
- a warning that no ports were given, followed by a fake `o:0` endpoint. A TCP
  scan with no `-p` quietly probes nothing; YARRP topology scans treat the port
  field as TTL, so `o:0` still sends a TTL-0 packet.

Ports also carry protocol prefixes: `U:` for UDP, `S:` for SCTP, `O:` for
non-port slots. A UDP scan pointed at `443` (without `U:`) matches no ports and
sends nothing for that port.

## 4. Interface and source address

The two fields that silently drop replies are `is_my_ip` and `is_my_port`: if
the reply's destination does not match the configured source address/port, the
packet is discarded without a message.

```bash
xtate --list-if
xtate --explain-target=198.51.100.10 --check
```

- Auto-detection picks the first interface with a default gateway. On a
  multi-homed host, force the adapter: `-if eth0`, or the numeric index printed
  by `--list-if` on Windows (`-if 3`).
- Wrong `-src-ip` or `-src-port` silently loses every reply.
- Source address/port ranges must have a power-of-two size.
- On Windows, tunnels and VPN adapters often appear as a separate adapter; make
  sure the scan leaves through the interface you think it does.
- **Linux loopback is not a raw-scan target.** `127.0.0.1` resolves to `lo`,
  which has no Ethernet MAC; startup stops with `failed to detect MAC address
  of interface: "lo"`. Use an on-link gateway/host or a non-loopback address,
  and do not try to force `--interface lo` for raw modules.

## 5. Packet filter (BPF)

Each scan module installs its own BPF filter. A filter that is too narrow hides
valid replies, which looks exactly like "the target is down". Check with:

```bash
sudo xtate ... --no-bpf
```

If results appear with `--no-bpf`, the module's filter is the problem; a custom
`--bpf-filter` replaces it, so keep it broad. One known case: the built-in
`tcp-syn` filter matches a bare RST exactly, so closed ports answered with
`RST+ACK` can be filtered out on unusual networks.

## 6. Router MAC and ARP

Xtate resolves the gateway MAC before sending. If that fails, startup stops
with:

```text
arp timed-out resolving MAC address for router ...
```

Use `--router-ip <gateway>` if discovery picked the wrong gateway, or bypass
ARP with `--router-mac 66-55-44-33-22-11`. `--lan` sets the destination MAC to
broadcast for LAN scans; it does not resolve per-target MACs.

## 7. The path itself

Once local configuration is excluded, check the path: run the same request from
a normal client, mirror the traffic with `tcpdump`, or use `--pcap` on both
ends. If a middlebox rewrites or drops the traffic, no scanner setting fixes it.

## Open ports but no banner

The classic sequence is: the port reports `open` (the SYN-ACK arrived), but the
banner/TLS/protocol result never appears. On Linux this is almost always the
kernel RST problem from section 1. It affects `zbanner`, `tcp-state`,
`tls-state`, `http-state`, the H2/H3 compositions and every state sub-probe.

Second most common: the probe is stateless and the server needs more of the
conversation than one segment (`http` sees one segment; long banners and
multi-segment TLS records need `--all-banner` in ZBanner or a stateful probe).

Third: the server answered with a zero-window SYN-ACK. ZBanner classifies that
as `fake-open` (reason contains `zerowin`) and does not send the probe payload —
that is a SYN-backlog/firewall signal, not a bug.

## TUN, VPN, fake-IP and RAW link types

TUN/VPN adapters (Clash, Meta, Surge and similar) often publish
`198.18.0.0/15` and answer DNS with fake addresses. Xtate scans whatever
address it is given, so you can end up scanning the tunnel or a dead range.

```bash
# resolve the real address outside the tunnel first, then scan it
dig +short example.com @1.1.1.1
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe tls-hello -show info
xtate --explain-target=203.0.113.10 --check
```

`--explain-target` prints the route-selected interface and the pcap link type:

```text
Route group 1:
  Interface:  \Device\NPF_{...}
  Link type:  RAW (12)
  Source IPv4: 198.18.0.1
  Gateway:    198.18.0.2
```

Supported link types are Ethernet (`EN10MB`), `NULL` and `RAW`. `RAW` has no
Ethernet header, so no MAC and no ARP; some tunnel drivers also rewrite or drop
packets. If the link type is `UNSUPPORTED`, choose the physical Ethernet/Wi-Fi
adapter with `-if`: startup rejects unsupported link types, and `RAW` is
accepted but may not carry the scan.

## Permissions and adapter errors

| Error text | Meaning | Fix |
|:---|:---|:---|
| `need to sudo or run as root or administrator` | No raw-socket privilege | `sudo` / elevated shell |
| `can't open adapter` | Adapter inaccessible | Check Npcap/libpcap, privileges, `-if` |
| `could not determine default interface` | No default route found | `-if <name>` |
| `failed to detect IP of interface` | Source address discovery failed | `-src-ip <addr>` |
| `(libpcap) failed to load` | libpcap missing on Linux | Install libpcap |
| `couldn't load wpcap.dll` | Npcap missing on Windows | Install Npcap (WinPcap API mode) |
| `no pfring adapter available...` | PF_RING not installed | Ignore unless you used `--pfring` |
| `(pfring) 'pf_ring' driver module not found!!!` | PF_RING kernel module absent | Informational unless `--pfring`; forcing it aborts |

On Linux you can avoid `sudo` per run with a capability grant, but re-apply it
after every rebuild:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate
```

IPv6 notes: a link-local source must be explicit (`-src-ip fe80::2`), and NDP
scans normally need `-fake-router-mac` (there is no IPv6 default gateway to
resolve). IPv6 extension chains (Hop-by-Hop, Routing, Destination Options, AH)
are parsed up to eight headers; replies containing Fragment, ESP or No Next
Header are not visible to the scanner.

## Rate too high and packet loss

`-rate` is a wire-packet rate, not a targets-per-second rate: every packet the
transmitter flushes counts, including follow-up packets the receive path
creates. There is no universal "targets per second = rate / N" formula.

- Default is 100 packets/s, split across transmit threads.
- On a lab subnet start at `-rate 1000`, not `-rate 1000000`.
- Too-high rates show up as missing results on every module, not as errors.
  Halve the rate and compare.
- Watch the live status bar's queue levels and hit rate, or use
  `--print-status queue`.
- `--wait <seconds>` (default 10) keeps the receive/handle threads alive after
  transmission; a scan that stops too early looks lossy.
- Linux: `--raw-socket --sendmmsg` (batch 64 by default) raises throughput;
  do not use it for slow stateful scans.
- Windows: `--send-queue` raises transmit throughput but adds latency; keep it
  off for `zbanner`/`tcp-state`.

## Results exist but are not visible

Work through these in order:

1. **Level filter.** The default shows only `success`. `tcp-syn` reports closed
   ports as `failed`; `zbanner` and `udp` report port open/closed at `info`.
   Add `-show failed` or `-show info`, or promote with module parameters
   (`--port-failure` for UDP, `--port-success`/`--port-failure` for ZBanner).
2. **Output module.** With `-output-module csv -o results.csv` results go to the
   file only. Add `--output-screen` or write to `-o -` where supported.
3. **Deduplication.** Duplicate SYN-ACK/RST/banner packets are dropped by
   default. `--no-dedup`, a larger `-dedup-win`, or ZBanner's repeat flags
   (`-scan-arg "--repeat-banner"`, `--repeat-synack`, `--repeat-ack`,
   `--repeat-rst`) make repeats visible.
4. **Module-level suppression.** ZBanner suppresses repeated packets before
   output; regex-based probes mark non-matching banners as `failed`.
5. **Stateful scans never report closed ports.** A RST for an unknown
   connection has no TCB and is dropped — by design.

## Expected behavior that looks wrong

- **`tcp-state` loses targets silently.** It sends SYN once and does not
  retransmit. Re-run with `--repeat 1` or lower the rate.
- **`tcp-state` latency and packet counts look odd.** HLTCP uses a fixed
  one-second RTO and a 1024-byte default window, so large transfers become many
  small packets. `--tcp-win 8192` (with a matching `--max-packet-len`) is faster.
- **ZBanner grabs only the first banner segment** and then sends RST. Long
  banners, multi-segment TLS ServerHellos and large HTTP headers need
  `-scan-arg "--all-banner"` (optionally `--all-banner-limit <n>`).
- **TLS probes appear empty.** `tls-state` reports a failed handshake at `info`;
  it sends no SNI and no ALPN by default, so virtual hosts and CDNs may answer
  with a default certificate/site. Use `-show info`, `-probe-arg "-sni host
  -alpn h2,http/1.1"`, and `-probe-arg "-fail-handshake"` if you want
  handshake failures promoted. Without SNI, treat the evidence as the default
  virtual host, not the requested hostname.
- **Guessing HTTP/3 from a QUIC handshake.** `quic handshake` is not HTTP/3
  success; only an `http3` result from `http3-state` is an HTTP/3 claim.

## Missing modules and optional dependencies

Optional libraries are compile-time decisions; a missing library removes the
module instead of failing at runtime:

| Missing dependency | Modules absent |
|:---|:---|
| OpenSSL | `tls-state`, `jarm`, `ssh-kex`, `quic` |
| PCRE2 | `hello-udp`, `recog`, `recog-udp`, `recog-state`, `nmap`, `nmap-udp` |
| libngtcp2 + GnuTLS | `quic-state`, `http3-state` |
| libbson / libmongoc | `bson`, `mongodb` output |
| Lua | Lua probes are listed but fail at startup |

Check `--list-probe`/`--list-out` against the dependency table in
[Getting started](../getting-started.md), install the development package and
rebuild. Lua probes fail with:

```text
(liblua) failed to load Lua shared library
you must install Lua library
```

Install Lua 5.3 or 5.4 (`liblua5.3`/`liblua5.4` on Debian/Ubuntu).

## HTTP/3 and QUIC specifics

`quic-state` and `http3-state` exist only in builds where ngtcp2 and GnuTLS
were found. If the module is missing, that is the expected Windows result, not
a packaging bug:

```bash
xtate --list-capabilities      # http3 / quic_transport / http3_reason
xtate --list-scan              # quic-state appears only with ngtcp2/GnuTLS
```

- On Linux: install `libngtcp2-dev`, `libngtcp2-crypto-gnutls-dev` and
  `libgnutls28-dev`, then rebuild (the option is `WITH_NGTCP2`, default `ON`;
  `-DWITH_NGTCP2=OFF` removes the modules deliberately).
- On Windows: `http3` is `false` with the reason
  `"HTTP/3 requires ngtcp2/GnuTLS; not built for Windows"`. There is no
  supported native MSVC build path yet; do not try to "fix" it by copying DLLs.
- A QUIC scan that yields only `open` is usually the same Linux firewall
  problem as TCP: install the RST/ICMP rules.
- `http3_qpack_partial: 1` means the response needed dynamic QPACK table
  updates, which the client does not implement; the decoded fields are partial
  by design.
- Certificate fields from QUIC are evidence only (verification is disabled).

## Corrupt JSON/CSV output

Text values (banners, HTTP bodies, TLS fields) are escaped as `\xNN` by
default. That is not valid JSON escaping; add `--no-escape-char` when a
downstream consumer needs JSON-compatible strings. Do **not** combine
`--no-escape-char` with BSON/MongoDB output — those modules handle binary and
escaping themselves.

`classification` and `reason` are printed verbatim by the CSV/NDJSON writers,
so a quote or newline coming from a probe can break a record. If that matters,
use BSON or filter downstream.

A broken final record is often truncation, not escaping: check
`--max-packet-len` (default 1514) and `--tcp-win` before blaming the writer.

## Windows notes

- Install **Npcap**; run elevated for raw scans.
- There is no `add_rules.sh` step. Never run the Linux firewall script on
  Windows.
- The PowerShell 7.6.7 crash reporting `totalWidth ('-17')` comes from a
  PowerShell/Windows Terminal update-notification bug, not from Xtate. Disable
  the update check and reopen every PowerShell window:

  ```powershell
  setx POWERSHELL_UPDATECHECK Off
  ```

- `--lang zh` does not change the console code page; Xtate writes Unicode help
  through `WriteConsoleW`.

## Reporting a bug

Include, in this order:

1. the command line, starting from the `--echo` output (not a paraphrase);
2. `xtate --version` (build type, compiler, date);
3. the log at `-d` or `-dd`;
4. the `--pcap` capture of received traffic, if packets are involved;
5. the exact target/port and the observed classification/reason;
6. `--explain-target` output for routing/interface/fake-IP problems.

Do not include unrelated production captures, tokens or credentials. If the
issue involves the control plane, include the request/response lines (minus the
token) and the job status.

See also:

- [Scanning modes](../scanning-modes.md) for what each engine is supposed to do
- [Firewall](../firewall.md), [TUN/VPN and link types](../platform-support.md)
- [Known limitations](../known-limitations.md)
- [07 · Protocols and HTTP/3](./07-protocols-and-http3.md) for probe-level limits
- [08 · Architecture and security](./08-architecture-and-security.md) for the
  token, authorization and daemon boundaries
