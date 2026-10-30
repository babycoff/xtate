# Scanning modes

**English** · [中文](zh-CN/scanning-modes.md)

A scan in Xtate is a **pair**: a ScanModule chosen with `-scan` and, when needed, a
ProbeModule chosen with `-probe`. The scan module owns the packet and the receive validation;
the probe module owns the payload and its parser. The probe *type* must match exactly what the
scanner declares, or the scan refuses to start.

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

`-scan` is mandatory; `-probe` is optional only for modules that declare "no probe". Module
parameters go through `-scan-arg` and `-probe-arg`, one quoted string each (`--help-scan <module>`, `--help-probe <module>`).

> Documented against Xtate v2.17.0. The CLI is authoritative: `--help`, `--help-scan`,
> `--help-probe`.

## Choosing a scan module

| Scan module | Probe type | Typical probe | What you get | Kernel RST rules |
|:---|:---|:---|:---|:---:|
| `tcp-syn` | none | - | open/closed, no payload | no |
| `zbanner` | `tcp` | `http`, `hello`, `tls-hello`, `lzr` | real TCP handshake + first banner | **yes** |
| `tcp-state` | `state` | `tls-state`, `http-state`, `hello-state` | full TCP conversation, TLS, HTTP | **yes** |
| `udp` | `udp` | `echo`, `dns`, `snmp`, `hello-udp` | UDP response or ICMP port-unreachable | **yes** |
| `icmp-echo` | none | - | alive hosts | no |
| `icmp-time` | none | - | alive hosts, IPv4 only | no |
| `sctp-init` | none | - | open/closed SCTP ports | no |
| `arp-req` | none | - | MAC address of IPv4 hosts on the LAN | no |
| `ndp-ns` | none | - | MAC address of IPv6 hosts on the LAN | no |
| `yarrp-echo` | none | - | stateless ICMP traceroute hops | no |
| `yarrp-udp` | none | - | stateless UDP traceroute hops | no |

"Kernel RST rules" means the host needs the iptables/ip6tables rules from
`./firewall/add_rules.sh`. They drop outgoing TCP RSTs and ICMP port-unreachable messages so
the local kernel cannot tear down connections it does not know about. The probe column is
also a constraint: a `none`-probe module takes no `-probe` at all, `zbanner` takes a `tcp`
probe, `udp` a `udp` probe and `tcp-state` a `state` probe - anything else is a startup error.

## Stateless versus stateful

- **Stateless** (`tcp-syn`, `udp`, the ICMP/SCTP/ARP/NDP/Yarrp modules): one request, one
  reply, no per-target table. Scale is limited by the network and the rate, not by memory.
- **ZBanner** (`zbanner`) is stateless in the same sense, yet it completes a TCP handshake:
  the connection state lives at the peer, and a SipHash cookie in the sequence number proves
  that a reply belongs to us. See [ZBanner](./zbanner.md).
- **Hybrid-state** (`tcp-state`) allocates a small TCB per established connection in
  user-space. That buys TLS handshakes, certificates and HTTP over TLS, and costs orders of
  magnitude in throughput. See [HLTCP](./hltcp.md).

Rule of thumb: `tcp-syn` for port inventory, `zbanner` for Internet-scale banners, `udp` for
UDP services, ICMP/ARP/NDP for host discovery, `tcp-state` for short lists of hosts.

## Recipes

### SYN scan - no probe, no firewall

Open ports are `success` (`"open" because "syn-ack"`); closed ports are `failure`
(`"closed" because "rst"`) and are hidden until you add `-show failed`. `--send-rst` answers
the SYN-ACK with a RST instead of leaving the half-open connection to the target.

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000 -show failed
```

### ZBanner + HTTP - real banners

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,8080 -scan zbanner -probe http \
  -rate 1000 -show info
./firewall/rm_rules.sh
```

Port state is emitted at `info` level by `zbanner`, so `-show info` is required to see the
`open` / `closed` / `fake-open` lines; the probe's banner result is `success`. Promote port
state with `-scan-arg "--port-success --port-failure"` if you want it in the default stream.

### ZBanner + TLS ClientHello - no full handshake

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 10.0.0.0/24 -p 443 -scan zbanner -probe tls-hello \
  -rate 1000 -show info
./firewall/rm_rules.sh
```

`tls-hello` reads the ServerHello (protocol, version hints, HTTPS keyword) without completing
a handshake, so on TLS 1.3-only servers it reports less than `tls-state` would.

### tcp-state + tls-state + http-state - HTTPS evidence

`tls-state` is a middle layer and has no usable default subprobe: always pass `-subprobe`
with a `state`-type probe. The nested value is quoted as one argument for `-probe-arg`.

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -version -subject -cert" \
  -rate 100 -wait 30 -show info
./firewall/rm_rules.sh
```

Give the subprobe its own parameters with `-subprobe-arg`, quoted one level deeper:
`-probe-arg "-subprobe http-state -subprobe-arg '-url /admin -user-agent xtate' -version"`.
`tcp-state` reports a RST for an unknown TCB as `closed` at `info` level; add `-show info`
to see those rows. Repeated RSTs are deduplicated by the receive-side table.

### UDP + echo

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p u:7,u:19 -scan udp -probe echo \
  -rate 1000 -show info
```

`echo` sends four bytes derived from the connection cookie and accepts a reply containing
them. A UDP response means `responsed`; an ICMP port-unreachable means `closed`
(`failure` level only with `-scan-arg "--port-failure"`). The firewall rules matter because
the kernel would otherwise emit its own unreachable for replies to ports no process owns.

### Host discovery with ICMP

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -scan icmp-echo -rate 1000
sudo ./bin/xtate -ip 192.168.1.0/24 -scan icmp-time -rate 1000   # IPv4 only
```

These are not port scans: do not pass `-p`. They emit `success` results with
`"alive"` / `"echo reply"` (or `"timestamp reply"`).

### LAN discovery - ARP and NDP

ARP is layer 2 and only works on the local segment; `-lan-mode` sets the destination MAC to
broadcast, and `arp-req` is IPv4-only and reads no port.

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -scan arp-req -lan-mode -rate 1000
```

`-lan-mode` only changes the router/destination MAC to the broadcast address; it does **not**
resolve a per-target MAC. Use it for ARP/NDP and other deliberate L2/broadcast scans. For
normal TCP/UDP scans leave it off first: the gateway/unicast path is usually correct, and a
broadcast destination can fail across routed, Docker/bridge or filtered segments.

IPv6 neighbours use NDP with a link-local source on the same link; `--fake-router-mac` stops
Xtate from resolving a gateway for a non-link-local target.

```bash
sudo ./bin/xtate -ip fe80::1/120 -scan ndp-ns -src-ip fe80::2 -fake-router-mac
```

`--bypass-os` goes further: Xtate answers ARP/NDP for the (possibly spoofed) source address
itself, so no firewall rules are needed - but the OS stack can then no longer send RSTs or
ICMP unreachables for you.

### Yarrp - stateless topology

Yarrp encodes the TTL in the packet and reconstructs paths offline. The TTL range goes
through the `o:` port namespace (`-p o:1-20`), never a normal port list.

```bash
# ICMP echo: hop distance 1..20; UDP: destination port carries TTL from 33434
sudo ./bin/xtate -ip 198.51.100.7 -p o:1-20 -scan yarrp-echo -rate 100
sudo ./bin/xtate -ip 198.51.100.7 -p o:1-20 -scan yarrp-udp \
  -scan-arg "-init-target-port 33434" -rate 100
```

Both produce `path` (TTL exceeded) and `destination` results with a `distance` field; paths
are rebuilt from `(target, distance)` in post-processing.

## Multi-probe modes

Some probes send several payloads per target (JARM needs 10 ClientHellos). The mode is a
property of the probe, not a switch: `Multi_Null` (one payload, most probes), `Multi_Direct`
(all slots before any reply), `Multi_IfOpen` (remaining slots after a SYN-ACK),
`Multi_AfterHandle` (after the first reply, as `jarm` does) and `Multi_DynamicNext` (the next
slot after each reply, as `lzr` does).

Slots are distinguished by **source port**: slot `i` uses `source_port_start + i`, and the
slot number is recovered from the reply's destination port. The range must be wide enough for
the probe's `multi_num`: the default span is 256 ports, and an explicit `-src-port` range must
contain a power-of-two number of ports. More slots than the range loses replies silently.

## Firewall rules

The same three rules cover every handshake-based mode: DROP outgoing TCP RST (v4 and v6) and
DROP outgoing ICMP port-unreachable (ICMP 3/3, ICMPv6 1/4).

```bash
./firewall/add_rules.sh     # append the rules
# ... run zbanner / tcp-state / udp scans ...
./firewall/rm_rules.sh      # remove them immediately afterwards
```

They are host-wide: while installed, every outgoing RST from the machine is dropped, including
those of unrelated SSH or browser sessions. Never leave them installed. There is no bundled
equivalent on Windows; SYN and ICMP scans work normally there, but handshake modes depend on the Windows stack not resetting the connections.

## See also

- [Targets and ports](./targets-and-ports.md) - building the address and port space
- [Output](./output.md) - result levels and formats
- [Modules](./modules.md) - the full module inventory
- [ZBanner](./zbanner.md) and [HLTCP](./hltcp.md) - how the two engines work
