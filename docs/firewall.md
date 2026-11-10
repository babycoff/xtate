# Linux firewall prerequisite

**English** · [中文](zh-CN/firewall.md)

Xtate's `zbanner`, `tcp-state`, `tls-state`, `http-state`, H2/H3 and every
state sub-probe complete TCP handshakes with raw packets. The Linux kernel does
not know about those connections and will send its own RST, killing the flow
before the banner/TLS/probe response arrives.

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

Xtate now checks Linux iptables at startup and prints:

```text
[WRN] firewall RST/ICMP suppression rules are not fully installed
[HIN] run: sudo ./firewall/add_rules.sh
```

`--check --explain-target <ip>` prints a `Firewall:` line.

## Agent / operator checklist

- Linux scanner: install rules before scans, remove after.
- Docker/GitHub Actions scanner container: install `iptables`, strip `sudo`
  from the script, normalize CRLF, run it, and verify the rule exists.
- Target containers do not need the rules.
- Windows has no equivalent script; use the normal Npcap/Administrator setup
  and do not assume host-stack RST behavior.
- Never leave the rules installed on a shared host: they drop all outgoing RSTs.
