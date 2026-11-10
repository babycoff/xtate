# Linux firewall prerequisite

**English** · [中文](zh-CN/firewall.md)

Xtate's `zbanner`, `tcp-state`, `tls-state`, `http-state`, H2/H3 and every
state sub-probe complete TCP handshakes with raw packets. The Linux kernel does
not know about those connections and will send its own RST, killing the flow
before the banner/TLS/probe response arrives.

## Operating systems

### Linux

Use `firewall/add_rules.sh`. The rule is host-wide; remove it after the scan.
This applies only to the stateful scans listed below.

### Windows

There is no firewall step and `add_rules.sh` must **not** be run on Windows.
UDP/DNS scans do not need any local firewall rule. Xtate does not print a
Linux-firewall warning on Windows; for `tcp-syn` it prints one hint:

```text
Windows: tcp-syn can add -scan-arg "--send-rst" ...
```

That option closes the half-open connection explicitly. Use Npcap with
Administrator privileges for any raw scan.

## Who needs it

Required:

```text
zbanner
tcp-state (and every tls-state/state sub-probe)
```

Not required:

```text
tcp-syn
stateless TCP port scans
```

UDP DNS is different: it does not need TCP RST suppression, but the ICMP
port-unreachable rule avoids useless retransmissions. Other stateless scans do
not need these rules.

## Required

On the **scanner host** (not the target), while scanning:

```bash
sudo ./firewall/add_rules.sh
```

It installs OUTPUT DROP rules for:

```text
TCP RST       IPv4 + IPv6
ICMP 3/3      IPv4
ICMPv6 1/4    IPv6
```

Check and remove:

```bash
sudo ./firewall/check_rules.sh
sudo ./firewall/rm_rules.sh
```

## Symptoms when missing

```text
open because syn-ack
no banner
no TLS output
no state sub-probe output
DoT/DoH "open" but no dot/doh result
```

This is the first thing to check for any "open but no application data" result.

## Runtime reminder

Xtate now checks Linux iptables only for the scans that need it and prints:

```text
[WRN] firewall RST/ICMP suppression rules are not fully installed
[HIN] run: sudo ./firewall/add_rules.sh
```

`--check --explain-target <ip>` prints a `Firewall:` line.

## Agent / operator checklist

- Linux scanner: install rules before stateful scans, remove after. `tcp-syn` and
  other stateless scans do not need them.
- Docker/GitHub Actions scanner container: install `iptables`, strip `sudo`
  from the script, normalize CRLF, run it, and verify the rule exists.
- Target containers do not need the rules.
- Windows has no firewall step; UDP/DNS needs no local rule, and raw scans use
  Npcap/Administrator. Never run the Linux `add_rules.sh` there.
- Never leave the rules installed on a shared host: they drop all outgoing RSTs.
