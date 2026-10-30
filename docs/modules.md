# Modules

**English** · [中文](zh-CN/modules.md)

Xtate is assembled from four kinds of module. Each is a C struct plus one line in a
`NULL`-terminated registry; there is no runtime plugin loading. A full build registers
**11 Scan + 60 Probe + 7 Output + 5 Generate** modules, and modules whose optional library
is missing simply disappear from the build (and from `--list-*`).

| Kind | Responsibility | Parameter | Registry |
|:---|:---|:---|:---|
| Scan | L3/L4 packets, receive validation, follow-up packets | `-scan` / `--scan-module` | `src/scan-modules/scan-modules.c` |
| Probe | L5+ payloads and response parsers, nested sub-probes | `-probe` / `--probe-module` | `src/probe-modules/probe-modules.c` |
| Output | formatting and destination of results | `-output-module` | `src/output-modules/output-modules.c` |
| Generate | enumeration and permutation of `(target, port)` pairs | `-generate-module` | `src/generate-modules/generate-modules.c` |

The Scan module is mandatory, the Generate module defaults to `blackrock`, and a Probe
module is required (and type-checked) only when the Scan module declares one. Module
sub-parameters travel as one quoted string through `-scan-arg`, `-probe-arg`,
`-output-arg` and `-gen-arg` (primary names `-scan-module-args`, `-probe-module-args`,
`-output-module-args`, `-generate-module-args`).

```bash
xtate --list-scan      # 11 scan modules
xtate --list-probe     # 60 probe modules
xtate --list-out       # 7 output modules
xtate --list-gen       # 5 generate modules

xtate --help-scan zbanner
xtate --help-probe tls-state
xtate --help-output mongodb
xtate --help-gen blackrock
```

## Scan modules (11)

| Module | Probe | What it does |
|:---|:---:|:---|
| `tcp-syn` | - | SYN scan; SYN-ACK is open, RST is closed. Optional `--send-rst`, `--fail-zerowin`. |
| `zbanner` | tcp | Stateless TCP handshake; payload rides on the third ACK; first banner is parsed by the probe. |
| `tcp-state` | state | HLTCP user-space TCP; full conversations for TLS/HTTP state probes. |
| `udp` | udp | Single-packet UDP scan with a probe payload; ICMP port-unreachable means closed. |
| `icmp-echo` | - | ICMP echo host discovery; can record TTL and IPID. |
| `icmp-time` | - | ICMP timestamp discovery, IPv4 only. |
| `sctp-init` | - | SCTP INIT scan; INIT-ACK is open, ABORT is closed. |
| `arp-req` | - | Layer-2 ARP sweep in LAN mode; reports the MAC address. IPv4 only. |
| `ndp-ns` | - | IPv6 neighbour solicitation; reports the MAC address. |
| `yarrp-echo` | - | Stateless traceroute with ICMP echo; TTL range via `o:` ports. |
| `yarrp-udp` | - | Stateless traceroute with UDP and ICMP errors; TTL carried in ports. |

Every scan module exposes `--help-scan <name>` with its own options (record TTL/IPID/window,
repeat/dedup switches, TTL overrides, ...). Which mode to pick, and which of them needs
firewall rules, is covered in [Scanning modes](./scanning-modes.md).

## Probe modules (60)

A probe declares a **type** that must match the scan module: `tcp` for `zbanner`, `udp` for
`udp`, `state` for `tcp-state`. It also declares a multi-probe mode and count; see
[Scanning modes](./scanning-modes.md#multi-probe-modes).

### General (11)

| Probe | Type | What it does |
|:---|:---:|:---|
| `http` | tcp | User-specified HTTP request over a stateless TCP conversation. |
| `http-state` | state | The same over HLTCP, including over TLS. |
| `hello` | tcp | User payload (string, base64, nmap-string, file) plus optional regex. |
| `hello-udp` | udp | The same for UDP. |
| `hello-state` | state | The same over a stateful TCP connection. |
| `tls-hello` | tcp | Fixed ClientHello; reads ServerHello version/record hints without completing a handshake. |
| `tls-state` | state | OpenSSL-backed TLS handshake, certificate/cipher/version dump, sub-probe over TLS. |
| `jarm` | tcp | JARM fingerprinting via 10 ClientHello variants. |
| `dns` | udp | DNS record request with configurable name/type/recursion. |
| `snmp` | udp | SNMP (v1/v2c) request and MIB-guided host info extraction. |
| `echo` | udp | Four cookie-derived bytes; accepts a reply containing them. |

### Fingerprinting (44)

| Probe | Type | What it does |
|:---|:---:|:---|
| `recog` | tcp | Match Recog XML fingerprints against the banner. |
| `recog-udp` | udp | The same for UDP. |
| `recog-state` | state | The same over stateful TCP. |
| `nmap` | tcp | Run an `nmap-service-probes` probe and parse its matches. |
| `nmap-udp` | udp | The same for UDP. |
| `lzr` | tcp | LZR-style service identifier: sends configured handshakes, matches every known one. |

The LZR family is one aggregator (`lzr`) plus **38 handshake modules**. Each handshake can
also be used on its own as `lzr-<name>`; as an `lzr` sub-probe the prefix is omitted, e.g.
`-probe-arg "-handshake http,tls"`. The 38 are:

```text
http tls ftp pop3 imap smtp ssh socks5 telnet fix smb mqtt amqp mysql mongodb
redis postgres mssql oracle rdp x11 vnc k8s rtsp modbus siemens bgp pptp dns
ipmi dnp3 fox memcached_ascii memcached_binary ipp wait newlines newlines50
```

All are registered as `lzr-<name>`, so the two Memcached handshakes are spelled
`lzr-memcached_ascii` and `lzr-memcached_binary` (underscore, not hyphen). Each handshake
sends a protocol-specific payload and identifies the service from the reply; `wait` sends
nothing, and `newlines` / `newlines50` send 2 / 50 newlines to elicit a greeting.

### Scriptable (2)

| Probe | Type | What it does |
|:---|:---:|:---|
| `lua-tcp` | tcp | Load a Lua script that implements `Make_payload` / `Get_payload_length` / `Handle_response`. |
| `lua-udp` | udp | The same for UDP. |

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe lua-tcp \
  -probe-arg "-script lua-probes/tcp-example.lua" -show info
```

Lua is loaded at runtime; if no Lua shared library is available the probes are still listed but fail at startup with a load error (install Lua 5.3 or 5.4).
The example scripts in `lua-probes/` declare `ProbeName`, `ProbeType`, `MultiMode` and
`MultiNum` in the script header.

### Plumbing (3)

| Probe | Type | What it does |
|:---|:---:|:---|
| `null` | tcp | Sends no payload; any received data is reported as a banner. |
| `get-state` | state | Debug probe that issues an HTTP GET over a stateful connection. |
| `close-state` | state | Sends nothing and closes the connection immediately. |

`null` is useful when a scan module requires a probe but you only want the server's
greeting. State probes only work with `-scan tcp-state`; `tls-state` additionally needs a
`state` sub-probe (`-subprobe`), because TLS is a middle layer, not a leaf.

## Output modules (7)

| Module | Needs `-output-file` | Notes |
|:---|:---:|:---|
| `text` | yes | stdout-style lines in a file |
| `ndjson` | yes | one JSON object per line |
| `bson` | yes | binary BSON stream; requires libbson |
| `csv` | yes | header plus one row per result |
| `list` | yes | `ip` and optional `port` |
| `mongodb` | yes | the "file" is a MongoDB URI; requires libmongoc |
| `null` | no | discards results |

Formats, level filtering and escaping are documented in [Output](./output.md).

## Generate modules (5)

| Module | Input | Notes |
|:---|:---|:---|
| `blackrock` | `-ip` / `-iL` + `-p` | Default. Stateless permutation of the address x port space; 63-bit limit. |
| `ip-list` | file/stdin, one IP or range per line | Uses `-gen-arg "-ip-file list.txt -default-port 80"`; one tx thread only. |
| `addr-list` | file/stdin, `IP PORT` per line | Uses `-gen-arg "-address-file targets.txt"`; the default splitter is a space; one tx thread only. |
| `ip-stream` | streaming file/stdin, one IP or range per line | Like `ip-list` but keeps reading during the scan; blocking reads disturb rate shaping. |
| `addr-stream` | streaming file/stdin, `IP PORT` per line | Like `addr-list`, streaming. |

`blackrock` takes the targets from the global options described in
[Targets and ports](./targets-and-ports.md); the list and stream generators take their input
from their own sub-parameters and use the global target options only where noted. Both
`ip-list`/`addr-list` and the streaming variants require `-tx-thread-count 1`.

## Finding the right module

- Name matching is forgiving: case and `-`, `_`, `.` are ignored, so `tls_state` selects
  `tls-state`. `--search-module <text>` fuzzy-searches all four registries.
- `--list-scan`, `--list-probe`, `--list-out`, `--list-gen` print the registry in order with
  a one-line description; `--help-<kind> <name>` prints type, multi-probe mode, count and
  the module's own parameter table.
- Optional dependencies change the inventory. A build without OpenSSL has no `jarm` or
  `tls-state`; without PCRE2 there is no `hello-udp`, `recog*` or `nmap*`; without libbson /
  libmongoc there is no `bson` / `mongodb` output; a Lua-backed build still lists
  `lua-tcp` / `lua-udp`, but they fail at startup if the shared library is missing. Recog
  also needs libxml2 to load fingerprint files.

## See also

- [Scanning modes](./scanning-modes.md) - which scan/probe pairing produces what, and why
- [Output](./output.md) - result levels and formats
- [Targets and ports](./targets-and-ports.md) - the input side of BlackRock
- [Architecture](./architecture.md) - how the four kinds fit into the pipeline
- [README](../README.md) - feature overview and the module registry
