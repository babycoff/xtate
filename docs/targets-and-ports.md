# Targets and ports

**English** · [中文](zh-CN/targets-and-ports.md)

Xtate scans a **product space**: every target address is crossed with every target port.
`-ip` supplies the addresses, `-p` supplies the ports, and the *GenerateModule* decides the
order in which the resulting `(address, port)` pairs are visited. The default generator is
`blackrock`, which permutes that space in a stateless, evenly dispersed way.

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

> Documented against Xtate v2.14.0. The CLI is authoritative: `--help`,
> `--help-scan <module>` and `--help-probe <module>` show the exact flags of your build.

## Address targets

`-ip` is the short form of `--target-ip` (aliases: `--range`, `--dst-ip`). Four forms are
accepted, and they can be mixed in one comma-separated value:

| Form | Example |
|:---|:---|
| Single address | `192.168.1.10` |
| Inclusive range | `10.0.0.1-10.0.0.100` |
| CIDR block | `10.0.0.0/24` |
| List | `10.0.0.0/24,192.168.1.5,2001:db8::1` |

IPv6 uses the same forms; ranges take a full IPv6 address on both sides.

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn
sudo ./bin/xtate -ip 10.0.0.10-10.0.0.20 -p 22 -scan tcp-syn
sudo ./bin/xtate -ip 2001:db8::/126 -p 443 -scan tcp-syn
sudo ./bin/xtate -ip 2001:db8::1-2001:db8::ff -p 443 -scan tcp-syn
```

Each `-ip` **replaces** the address list rather than appending to it, so supply one option
with a comma-separated list instead of repeating `-ip`. At least one target is required:
`blackrock` refuses to start when the address list is empty. For IPv6 targets in link-local
scope you must set the source address explicitly with `-src-ip` (`--source-ip`);
global-scope source addresses are discovered from the adapter.

## Target files

`-iL` (`--include-file`) reads a list from a file instead of the command line. The file uses
the same formats as `-ip`, one or more entries per line; `#` starts a comment; `-` reads from
stdin.

```bash
# ranges.txt:
#   10.0.0.0/24      # datacenter
#   192.168.1.0/24   # lab
#   2001:db8::/64    # IPv6 test allocation
sudo ./bin/xtate -iL ranges.txt -p 80,443 -scan tcp-syn
cat ranges.txt | sudo ./bin/xtate -iL - -p 80,443 -scan tcp-syn
```

Like `-ip`, `-iL` replaces the address list it is given, and it can hold millions of ranges.
The list is parsed and sorted before the scan starts, so a bad line fails the run early.

## Excluding targets

Three options remove work from the target space. Excludes are applied **after** all target
and port inputs are parsed, so the order of `-ip` / `--exclude` on the command line does not
matter.

| Option | Removes |
|:---|:---|
| `--exclude` | Addresses, ranges or CIDR blocks (same syntax as `-ip`) |
| `--exclude-file` | The same, read from a file |
| `--exclude-port` | Ports or port ranges (same syntax as `-p`) |

```bash
# Scan a /8 but not the RFC1918 hole in it, and skip two ports
sudo ./bin/xtate -ip 10.0.0.0/8 --exclude 10.10.0.0/16,10.20.1.1 \
  --exclude-port 80,443 -p 80,443,8080 -scan tcp-syn

# Or read both lists from files
sudo ./bin/xtate -ip 10.0.0.0/8 --exclude-file excludes.txt -p 80,443 -scan tcp-syn
```

`--exclude` resets the exclude table on each use, which means a second `--exclude` replaces
the first. Put all excluded ranges in a single option, or use `--exclude-file`. A guard: if
the requested space contains more than one billion IP addresses and no IPv4 `--exclude` is
present, `blackrock` refuses to start; add a harmless `--exclude 255.255.255.255` as the
explicit confirmation.

## Targets from ASNs

Instead of enumerating addresses, you can ask for every prefix announced by an AS. The
mapping comes from an `ip2asn` TSV file, loaded with `--ip2asn-v4` / `--ip2asn-v6` (primary
names `--ip2asn-v4-file` / `--ip2asn-v6-file`). `--asn-v4` (`--target-asn-v4`) and
`--asn-v6` (`--target-asn-v6`) add the addresses; `--exclude-asn-v4` / `--exclude-asn-v6`
remove them. ASNs are comma-separated (whitespace separates them too). Without a loaded
ip2asn file the scan stops with an error rather than silently scanning nothing.

```bash
sudo ./bin/xtate --ip2asn-v4 /path/to/ip2asn-v4.tsv \
  --asn-v4 13335,15169 --exclude-asn-v4 16509 \
  -p 443 -scan tcp-syn -rate 5000
```

## Ports

`-p` is the short form of `--port`. Its grammar is nmap-like:

| Spec | Meaning |
|:---|:---|
| `80` | One port |
| `80,443` | A list |
| `8000-8100` | An inclusive range |
| `u:161` | UDP port 161 |
| `s:38412` | SCTP port 38412 |
| `o:1-20` | "Other protocol" numbers 1..20, used by modules such as `yarrp-echo` |

A protocol prefix applies to everything after it until the next prefix, so
`-p 80,u:161,162` scans TCP 80, then UDP 161 and UDP 162. Prefixes are case-insensitive
(`U:`, `u:`, `T:`, `S:`, `O:`). Internally each transport keeps its own 0..65535 space, so
TCP 53 and UDP 53 are different ports.

```bash
# TCP 80 and 443, plus UDP 161 and the UDP range 1024-1100
sudo ./bin/xtate -ip 10.0.0.0/24 -p 80,443,u:161,u:1024-1100 -scan udp -probe echo
```

Every target address is crossed with the whole port list. Portable scans should always pass
`-p`; if no port survives, `blackrock` warns and substitutes the fake endpoint `o:0`, which
most scan modules ignore - a TCP scan then has nothing useful to send.

### Top ports

`--top-port N` adds the first `N` entries of a built-in TCP port list to the port table;
`--udp-top-port N` does the same with the UDP list. They **add** to the ports instead of
replacing them:

```bash
sudo ./bin/xtate -ip 10.0.0.0/24 -p 8443 --top-port 100 -scan tcp-syn
```

`-p` clears the port table first, so place it **before** `--top-port` / `--udp-top-port`; a
`-p` after them would remove the ports they added.

### Ports that modules do not use

`icmp-echo`, `icmp-time`, `arp-req` and `ndp-ns` read no port, and their documentation says
not to specify one. `yarrp-echo` and `yarrp-udp` abuse the port list to carry the TTL range
(`-p o:1-20`), so an `o:` spec is mandatory there. See
[Scanning modes](./scanning-modes.md) for the per-mode requirements.

## Sharding, resuming and seeds

`--shard k/n` splits one logical scan across `n` instances: instance `k` sends every `n`-th
packet, starting at offset `k-1`. This is how you scan one target space from several hosts
without overlap.

```bash
# Host 1 of 4, host 2 of 4, ... - all with the same seed
sudo ./bin/xtate -ip 10.0.0.0/8 -p 80,443 -scan tcp-syn -seed 1234 --shard 1/4
sudo ./bin/xtate -ip 10.0.0.0/8 -p 80,443 -scan tcp-syn -seed 1234 --shard 2/4
```

All shards **must use the same `-seed`**; otherwise each instance produces a different
permutation and the shards overlap. Xtate warns when sharding is used without an explicit
seed. The seed also derives the TCP/UDP cookies, so keep it stable across shards and runs.
`-seed time` explicitly reseeds from the local clock; without `-seed`, Xtate draws entropy.

`--resume-index N` starts the permutation at index `N` instead of 0. It is normally not typed
by hand: on the first `Ctrl-C`, Xtate writes the current position into `resume.conf` along
with the rest of the configuration, and you continue with
`sudo ./bin/xtate --conf resume.conf`. Resume only makes sense when the target set, port
list, generator and seed are unchanged; they are part of the flattened index space.
`--no-resume-file` suppresses writing `resume.conf` (useful when a huge target list makes
saving slow).

## Inspecting the space before you scan

Listing modes accept the same target and port options as a scan but send nothing:

```bash
# Every unique ip:port in scan order
sudo ./bin/xtate -ip 10.0.0.0/24 -p 80,443 -scan tcp-syn --list-target

# The target addresses as CIDR blocks
sudo ./bin/xtate -ip 10.0.0.0/24,192.168.1.5 -scan tcp-syn --list-cidr
```

`--list-target` prints the shuffled product space; add `--output-as-info` with a loaded
ip2asn file to annotate each address with its AS. `blackrock` supports at most a 63-bit target
space, and the count is addresses x ports - keep that in mind for IPv6 searches.

The options above feed the default `blackrock` generator. The `ip-list`, `addr-list`,
`ip-stream` and `addr-stream` generators read targets from a file or stdin and use their
**own** sub-parameters instead (`-gen-arg "-ip-file list.txt"`); only one transmit thread is
supported with them. Details are in [Modules](./modules.md).

## See also

- [Scanning modes](./scanning-modes.md) - which module consumes which ports and payloads
- [Output](./output.md) - saving the results
- [Getting started](./getting-started.md) - build, permissions, first scan
- [README](../README.md) - feature overview and papers
