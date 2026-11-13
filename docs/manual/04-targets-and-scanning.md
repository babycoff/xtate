# 04 · Targets and scanning

A scan is defined by a target space and an engine. The target space is a set of
addresses multiplied by a set of ports; the engine decides which packets are
sent and how responses are classified. This chapter covers the address and
port syntax, the target count, and the practical choice of scan engine.

For the module catalog see [05 · Modules and parameters](./05-modules-and-parameters.md);
for job execution see [03 · CLI and jobs](./03-cli-and-jobs.md).

## The target space

Targets are supplied with `-ip` (alias `--target-ip`) and ports with `-p`
(alias `--port`). Both understand several forms.

| Form | Example | Addresses |
|:---|:---|:---:|
| Single address | `-ip 203.0.113.10` | 1 |
| CIDR | `-ip 198.18.0.0/24` | 256 |
| Inclusive range | `-ip 203.0.113.10-203.0.113.40` | 31 |
| Component range | `-ip 192.168.0-3.1-20` | 80 |
| Comma list | `-ip 10.0.0.1,10.0.0.4-10.0.0.8` | 6 |
| IPv6 | `-ip 2001:db8::/64` | 2^64 |

```bash
xtate -ip 198.18.0.0/24,203.0.113.10-203.0.113.40 -p 80,443 -scan tcp-syn \
  --list-target
```

`--list-target` prints the parsed `address port` pairs without sending a
packet, which is the quickest way to verify a target expression. Use the
bracketed form `--list-target[order]` (or `[norandom]`) for a deterministic,
sorted listing.

### Component ranges

A component range varies up to four dot-separated components in one token.
`192.168.0-3.1-20` means `192.168.[0..3].[1..20]`, a sparse rectangle rather
than a contiguous range. Internally the components are expanded as a
Cartesian product, with two limits:

- at most **4** variable components per token;
- at most **1,048,576** addresses in that product.

A single CIDR or dashed range is not subject to the product limit; `0.0.0.0/0`
is stored as one range, not as four billion entries. IPv6 component ranges are
supported by the same expansion logic.

Other limits: a target token is at most 128 bytes, and a line in an include
file is at most 65,535 bytes. Anything longer is rejected with an error.

### Repeated options replace

`-ip` sets the address list; it does not append. `-ip A -ip B` scans only B.
To combine targets, use commas or an include file:

```bash
xtate -ip 10.0.0.0/24,10.0.1.2 -p 22 -scan tcp-syn
```

The same replacement rule applies to `-p`, `-iL` and `--exclude` (see the
warning below).

## Include files and stdin

```bash
xtate -iL targets.txt -p 80,443 -scan tcp-syn
cat targets.txt | xtate -iL - -p 443 -scan tcp-syn
```

`-iL` (`--include-file`) reads the same syntax as `-ip`, one or more entries per
line. `#` starts a comment, a blank line is ignored, and `-` reads stdin. A bad
line is reported with its file and line number and stops startup; targets are
parsed and sorted before any packet is sent. The file replaces any earlier
address list, so do not combine `-ip` and `-iL` expecting a union.

## Excludes

```bash
xtate -ip 10.0.0.0/24 -p 22,80 --exclude 10.0.0.0/28 --exclude-port 80
xtate -ip 10.0.0.0/24 -p 22 --exclude-file skip.txt
```

Excludes are applied after all targets and ports are parsed, to both the
address and port dimensions. Three forms exist: `--exclude` (same syntax as
`-ip`), `--exclude-file` and `--exclude-port`.

**Each `--exclude` option replaces the previous exclusion list.** This is the
opposite of what most people expect:

```bash
# Wrong: only the second exclusion is applied
xtate -ip 10.0.0.0/24 -p 22 --exclude 10.0.0.0/28 --exclude 10.0.0.128/28

# Right: combine them in one option, or use a file
xtate -ip 10.0.0.0/24 -p 22 --exclude 10.0.0.0/28,10.0.0.128/28
xtate -ip 10.0.0.0/24 -p 22 --exclude-file skip.txt
```

Blackrock refuses to start with more than one billion IPv4 addresses and no
IPv4 exclusion, as a guard against accidental internet-wide scans. Add a
harmless exclusion such as `--exclude 255.255.255.255` if you really mean it.

## ASN targets

With an ip2asn table loaded, targets can be selected by autonomous system:

```bash
xtate --ip2asn-v4 ip2asn-v4.tsv --asn-v4 13335 -p 443 -scan tcp-syn
xtate --ip2asn-v6 ip2asn-v6.tsv --asn-v6 15169 -p 443 -scan tcp-syn
```

`--asn-v4`/`--asn-v6` add an ASN's prefixes; `--exclude-asn-v4/v6` remove
them. The ip2asn file is required: without it, ASN selection fails at startup.
`--output-as-info` annotates results with ASN, country and description.

## Ports

| Syntax | Meaning |
|:---|:---|
| `80` | TCP 80 |
| `80,443` | TCP 80 and 443 |
| `8000-8100` | TCP range, inclusive |
| `u:161` | UDP 161 |
| `s:38412` | SCTP 38412 |
| `o:1-20` | "other" space, used for TTL/offset values |
| `80,u:161,162` | TCP 80, UDP 161 and 162 |

The protocol prefix persists until the next prefix, so `u:161,162` is two UDP
ports. Prefixes are case-insensitive. Internally TCP, UDP, SCTP and "other"
each have their own 0–65535 space; `u:53` and `53` are different ports.

`-p` clears the port list first. `--top-port N` appends the first N ports from
the built-in TCP popularity list, and `--udp-top-port N` does the same for UDP.
Because they append, put `-p` before them:

```bash
xtate -ip 203.0.113.10 -p 8080 --top-port 100 -scan tcp-syn
```

Portless engines ignore `-p`: `icmp-echo`, `icmp-time`, `arp-req` and
`ndp-ns`. The `yarrp-*` engines use the "other" space, so `-p o:1-20` is
required. With blackrock and no ports at all, Xtate warns and inserts a fake
`o:0` target; most engines simply ignore it.

## IPv6 notes

- Link-local targets need an explicit link-local source, for example
  `-src-ip fe80::1%eth0`.
- NDP scanning uses `--fake-router-mac` so Xtate does not ask the OS to resolve
  a gateway for non-link-local targets, and `--bypass-os` to answer neighbour
  discovery itself.
- Blackrock's target space is limited to 63 bits (addresses × ports), so a /64
  with several ports exceeds it. Scan a subrange or use a list generator.
- IPv6 component ranges and CIDR behave like IPv4, but remember that a /64 is
  2^64 addresses: use `--list-target` before launching.

## Scanning modes at a glance

| Engine | Probe type | State | Packets per target | Firewall rules |
|:---|:---|:---|:---|:---|
| `tcp-syn` | none | stateless | 1 SYN (+ RST with `--send-rst`) | not needed |
| `zbanner` | tcp | stateless handshake | ≈3 (SYN, ACK+payload, RST) | needed |
| `tcp-state` | state | stateful TCB | conversation-dependent | needed |
| `udp` | udp | stateless | 1 datagram | needed |
| `quic-state` | state | stateful QUIC | handshake | UDP guidance |
| `icmp-echo` | none | stateless | 1 echo | not needed |
| `icmp-time` | none | stateless | 1 timestamp | not needed |
| `sctp-init` | none | stateless | 1 INIT | not needed |
| `arp-req` | none | stateless | 1 request | not needed |
| `ndp-ns` | none | stateless | 1 solicitation | not needed |
| `yarrp-echo` | none | stateless | 1 per TTL | not needed |
| `yarrp-udp` | none | stateless | 1 per TTL | not needed |

The probe type must match: `zbanner` needs a `tcp` probe, `tcp-state` needs a
`state` probe, `udp` needs a `udp` probe. Xtate validates this at startup and
exits with an error instead of silently sending the wrong packet:

```bash
# Error: tls-state is a state probe, but tcp-syn has no probe support
xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -probe tls-state
```

## Choosing an engine

- **Port reachability, fast and simple** — `tcp-syn`. No firewall rules, one
  packet per target. Closed ports appear as failures; add `-show failed` if you
  need them.
- **Banner or protocol evidence without state** — `zbanner` with a `tcp`
  probe. It completes the handshake in user space with SipHash cookies and is
  the most common choice for version detection.
- **Anything that needs a real connection** — `tcp-state` with a `state`
  probe (`tls-state`, `http-state`, `get-state`, …). It keeps TCBs, so budget
  `--tcb-mem` and `--conn-expire`.
- **UDP services** — `udp` with a UDP probe; UDP replies are `responsed`,
  ICMP unreachable is `closed`/`port unreachable`.
- **Host liveness** — `icmp-echo` or `icmp-time`.
- **Local link discovery** — `arp-req` (IPv4) or `ndp-ns` (IPv6).
- **Path tracing** — `yarrp-echo`/`yarrp-udp`, one probe per TTL.

## Rate, timeout and completion

`-rate` is the outbound packet rate in packets per second, not targets per
second. The default is 100. Fractional values are accepted:

```bash
xtate -ip 10.0.0.0/24 -p 22 -scan tcp-syn -rate 250.5
```

Attempts per second depend on the engine: `tcp-syn` and `udp` send about one
packet per attempt, so attempts/s ≈ rate; default `zbanner` sends about three
packets per target, so attempts/s is roughly rate/3; `tcp-state` varies with the
conversation. Generated follow-up packets (RST, ACK) also consume the rate.

Scan requests sent through the control plane cap `rate` at 1–10000. The CLI
accepts any positive floating-point value.

`--wait` is the number of seconds Xtate keeps receiving after the last packet
is sent; the default is 10. A total wall-clock timeout belongs to the job
layer (`timeout_sec` in a scan request, 1–86400 seconds, or `--job-timeout` on
the CLI).

## Sharding, resuming and seeds

```bash
# Two shards of the same scan; both must use the same seed
xtate -ip 10.0.0.0/16 -p 80 -scan tcp-syn -seed 0x1234 -shard 1/2
xtate -ip 10.0.0.0/16 -p 80 -scan tcp-syn -seed 0x1234 -shard 2/2
```

`-shard k/n` sends every n-th packet, starting at offset k-1. Shards must share
the same `-seed`; otherwise their shuffled orders differ and they overlap.
Xtate warns when you shard without an explicit seed.

`--resume-index N` restarts from position N in the shuffled sequence. An
interrupted scan normally leaves `resume.conf`, which you can feed back with
`--conf resume.conf`; `--no-resume-file` disables that file. `-seed time`
re-seeds from the clock; without `-seed`, Xtate derives a seed from entropy.

## Recipes

```bash
# Open TCP ports, including closed ones as failures
xtate -ip 203.0.113.10 -p 1-1024 -scan tcp-syn -show failed

# HTTP and TLS evidence
xtate -ip 203.0.113.0/24 -p 80,443 -scan zbanner -probe http -show info
xtate -ip 203.0.113.0/24 -p 443 -scan zbanner -probe tls-hello -show info

# HTTP inside TLS, with certificate details
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -subprobe-arg '--url / --all-banner' --dump-cert-details" \
  -show info

# UDP service discovery
xtate -ip 203.0.113.10 -p u:53,u:123,u:161 -scan udp -probe echo -show all

# Local ARP and NDP
xtate -ip 192.168.1.0/24 -scan arp-req --lan-mode -show info
xtate -ip fe80::/64 -scan ndp-ns -src-ip fe80::1%eth0 --fake-router-mac -show info

# TTL-limited path discovery
xtate -ip 203.0.113.10 -p o:1-20 -scan yarrp-echo -gen blackrock -show info
```

## Firewall rules

The `zbanner`, `tcp-state` and `udp` engines need the operating system to stay
quiet while they work: outgoing TCP RSTs and ICMP port-unreachable messages
must be suppressed, or the host will answer scans itself. Xtate ships
`firewall/add_rules.sh` and `firewall/rm_rules.sh`; the rules are host-wide and
should be removed as soon as the scan ends. `tcp-syn` and the ICMP/ARP/NDP/
yarrp engines do not need them. Windows has no equivalent script — use
`--send-rst` for `tcp-syn` and account for the local stack in `zbanner`/`udp`.

## Limits

| Limit | Value |
|:---|:---|
| Variable components per token | 4 |
| Addresses per component-range token | 1,048,576 |
| Target token length | 128 bytes |
| Include-file line length | 65,535 bytes |
| Blackrock target space | 63 bits (addresses × ports) |
| `-rate` | > 0, floating point |
| Control-plane `rate` | 1–10000 |
| Control-plane `timeout_sec` | 1–86400 seconds |
| `--wait` default | 10 seconds |

## See also

- [05 · Modules and parameters](./05-modules-and-parameters.md) — engine and
  probe options
- [Targets and ports](../targets-and-ports.md) — exhaustive target reference
- [Scanning modes](../scanning-modes.md) — engine comparison and probe slots
- [Firewall](../firewall.md) — rules and platform behaviour
- [03 · CLI and jobs](./03-cli-and-jobs.md) — control-plane and job execution
