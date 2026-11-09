# Modules

**English** · [中文](zh-CN/modules.md)

Xtate is assembled from four kinds of module. Each is a C struct plus one line in a
`NULL`-terminated registry; there is no runtime plugin loading. A full build registers
**11 base Scan + 55 Probe + 7 Output + 5 Generate** modules, plus optional
`quic-state` and `http3-state` when ngtcp2/GnuTLS is available. Modules whose optional library is missing simply disappear
from the build (and from `--list-*`).

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
xtate --list-scan      # 11, or 12 with quic-state
xtate --list-probe     # 27 probe modules
xtate --list-out       # 7 output modules
xtate --list-gen       # 5 generate modules

xtate --help-scan zbanner
xtate --help-probe tls-state
xtate --help-output mongodb
xtate --help-gen blackrock
```

## Scan modules (11, plus optional `quic-state`)

| Module | Probe | What it does |
|:---|:---:|:---|
| `tcp-syn` | - | SYN scan; SYN-ACK is open, RST is closed. Optional `--send-rst`, `--fail-zerowin`. |
| `zbanner` | tcp | Stateless TCP handshake; payload rides on the third ACK; first banner is parsed by the probe. |
| `tcp-state` | state | HLTCP user-space TCP; full conversations for TLS/HTTP state probes. |
| `udp` | udp | Single-packet UDP scan with a probe payload; ICMP port-unreachable means closed. |
| `quic-state` | state | Raw-UDP stateful QUIC handshake with ngtcp2/GnuTLS; reports version, TLS/ALPN and certificate fields, then runs a state sub-probe. Optional build. |
| `http3-state` | state | HTTP/3 request over `quic-state`; methods/headers/body, Huffman QPACK strings, full static table, structured response headers. Optional build. |
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

## Probe modules (27, plus optional `http3-state`)

A probe declares a **type** that must match the scan module: `tcp` for `zbanner`, `udp` for
`udp`, `state` for `tcp-state`. It may declare a `ProbeSlotPlan` (JARM and the `slot-test` examples); see
[Scanning modes](./scanning-modes.md#probe-slots).

### ProbeSlotPlan (multi-slot probes)

Most probes are single-flow and omit the slot plan. A probe that needs several
independent pseudo-flows declares a `ProbeSlotPlan` in `Probe`:

```c
typedef struct ProbeSlotPlan {
    unsigned             count;       /* 0 or 1 = single; JARM uses 10 */
    ProbeSlotTrigger     trigger;     /* None, Always, AfterFirstReply */
    probe_slots_continue continue_cb; /* optional */
} ProbeSlotPlan;
```

- The engine maps slot `i` to `source_port_start + i`; `ProbeTarget.index` is
  the zero-based slot.
- `Always`: every slot is sent from the first scan iteration.
- `AfterFirstReply`: slot 0 is sent normally; the remaining slots are sent
  only after the first accepted response. In ZBanner this specifically means
  the first banner/data segment: an ACK-only or RST first response does not
  trigger fan-out. This is intentional ZBanner semantics, not a generic
  connection-local workflow.
- The source-port range must be at least the plan's `count`; startup rejects
  a smaller range.
- The engine keeps **no group state** and does not aggregate. Every slot emits
  its own `OutItem`. JARM emits `jarm_slot`, `jarm_slots` and `jarm_part`;
  `tools/jarm_aggregate.py` joins them after the scan.
- Same-connection multi-step work does not belong here; use HLTCP/state probes.

JARM is the only probe shipped with a multi-slot plan today, but the plan is
not JARM-specific: `Always` covers parallel variants, and
`AfterFirstReply` covers conditional fan-out. A future protocol-version or
challenge-response probe can reuse the same engine path without a new mode.

### JARM transmission order

`jarm` sends ten Salesforce JARM 1.0 probes. The default first request is
**standard probe 1** (TLS 1.2, all ciphers forward, all ALPN, supported_versions
TLS 1.2, reverse extension order). After the first accepted TLS reply, the
remaining nine slots are transmitted as a burst without waiting for individual
replies; replies may arrive in any order.

```bash
# Default: 1,2,3,4,5,6,7,8,9,10 (slot 1 waits for its reply)
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe jarm

# First request is 7; total order is 7,8,9,10,1,2,3,4,5,6.
# The burst after probe 7's reply is 8,9,10,1,2,3,4,5,6.
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe jarm \
  -probe-arg "--first-probe 7"
```

- `--first-probe N` rotates which standard probe gets the first SYN. All ten
  probes are still sent.
- `jarm_slot` always records the standard probe id, not the transmission
  position, so aggregation is order-independent.
- `--probe-index N` sends only one probe; this is a debugging aid and cannot
  produce a complete JARM fingerprint.

### QUIC capability probe

`quic` is a **transport capability** UDP probe. It builds one valid QUIC v1
Initial datagram (at least 1200 bytes) with a TLS 1.3 ClientHello and ALPN
`h3`, then classifies the first long-header response:

```bash
xtate -ip 203.0.113.10 -p U:4433 -scan udp -probe quic --show info
```

Output fields:

```text
quic_response          initial | handshake | retry | version-negotiation
quic_version           32-bit QUIC version
quic_dcid / quic_scid  hex connection IDs
quic_token_len         Retry/Initial token length
quic_payload_len       long-header payload length
quic_versions_count    Version Negotiation count
quic_version_<n>       each Version Negotiation version
quic_raw               optional --record-raw bytes
```

The probe matches responses by a client SCID derived from the stateless UDP
cookie; it does not keep per-target state. A successful result proves QUIC
transport bytes, **not** a completed TLS handshake and **not** HTTP/3. Do not
label `quic_response: initial` as `http3`.

### TLS evidence, certificate details and STARTTLS

`tls-state` is an HLTCP middle layer and requires a `state` sub-probe. See [TLS composition](./tls-composition.md) for `--after-tls` and implicit/STARTTLS examples. Certificate
and TLS fields are emitted after a successful handshake, independent of what the
sub-probe does afterwards.

```bash
# Direct TLS, certificate-only
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe close-state --dump-cert-details" -show info

# SMTP STARTTLS, certificate-only
xtate -ip 203.0.113.10 -p 25 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe close-state --starttls smtp --dump-cert-details" -show info

# HTTPS inside TLS
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -subprobe-arg '--all-banner'" -show info
```

`--starttls` values and plaintext flows:

| Value | Greeting | Upgrade command | Success |
|:---|:---|:---|:---|
| `smtp` | `220` | `EHLO`, then `STARTTLS` | `250` then `220` |
| `imap` | `* OK` | `a001 STARTTLS` | `a001 OK` |
| `pop3` | `+OK` | `STLS` | `+OK` |
| `ftp` | `220` | `AUTH TLS` | `234` |

Sub-probe lifecycle:

```text
STARTTLS plaintext negotiation
-> TLS handshake
-> certificate/cipher/version output
-> subprobe conn_init
-> subprobe runs inside TLS
```

The sub-probe never sees the plaintext STARTTLS exchange. If the plaintext
negotiation or TLS handshake fails, the sub-probe is not initialized; failed
STARTTLS is emitted as `starttls error`. `--dump-cert-details` outputs
`cert_subject`, `cert_issuer`, `cert_not_before`, `cert_not_after`,
`cert_serial`, `cert_signature_algorithm`, `cert_public_key`,
`cert_public_key_bits`, `cert_san`, `tls_version`, `tls_cipher` and `tls_alpn`.

### General (21)

| Probe | Type | What it does |
|:---|:---:|:---|
| `http` | tcp | User-specified HTTP request over a stateless TCP conversation. |
| `http-state` | state | The same over HLTCP, including over TLS. |
| `hello` | tcp | User payload (string, base64, nmap-string, file) plus optional regex. |
| `hello-udp` | udp | The same for UDP. |
| `hello-state` | state | The same over a stateful TCP connection. |
| `tls-hello` | tcp | Fixed ClientHello; reads ServerHello version/record hints without completing a handshake. |
| `tls-state` | state | OpenSSL-backed TLS handshake; `--starttls smtp|imap|pop3|ftp` upgrades first; certificate/cipher/version dump; `--dump-cert-details` adds structured X.509/SAN/public-key/validity/ALPN; sub-probe over TLS. |
| `ssh` | tcp | Configurable SSH banner plus KEX/host-key and cipher/MAC/compression lists. |
| `h2c` | tcp | Cleartext h2c preface, configurable SETTINGS/PING fingerprint, frame/settings parsing. Not HTTP/2 over TLS. |
| `h2` | state | TLS/ALPN h2 HTTP/2 via HLTCP; preface, SETTINGS, minimal HPACK request, frames/HEADERS/DATA. |
| `redis` | tcp | Read-only `INFO server` Redis identification and structured version/mode/os/role. |
| `memcached` | tcp | `version` command and version-line parse. |
| `ntp` | udp | NTP v4 mode-3 request, cookie validation, leap/stratum/refid/root fields. |
| `mqtt` | tcp | MQTT 3.1.1 CONNECT and CONNACK return-code parse. |
| `socks5` | state | SOCKS5 greeting and method selection. |
| `telnet` | state | Initial Telnet banner and IAC option parse. |
| `quic` | udp | QUIC v1 Initial capability probe; classifies Version Negotiation/Retry/Initial/Handshake; no QUIC handshake or HTTP/3 claim. |
| `jarm` | tcp | JARM via 10 ClientHello slots; emits `jarm_part`, aggregated by `tools/jarm_aggregate.py`. |
| `dns` | udp | DNS record request with configurable name/type/recursion. |
| `snmp` | udp | SNMP (v1/v2c) request and MIB-guided host info extraction. |
| `echo` | udp | Four cookie-derived bytes; accepts a reply containing them. |

### Batch B protocols (15)

| Probe | Type | What it does |
|:---|:---:|:---|
| `mysql` | tcp | Read MySQL server greeting; protocol/version/capabilities/auth plugin. |
| `mysql-state` | state | Same greeting over tcp-state; no authentication. `--after-tls` is a lab-only COM_PING wake-up, not a standard handshake. |
| `postgres` | tcp | PostgreSQL SSLRequest capability check. |
| `postgres-state` | state | SSLRequest + auth-boundary StartupMessage. |
| `mongodb` | tcp | OP_MSG `hello` and BSON identification. |
| `smtp` | tcp | Read SMTP 220 banner. |
| `smtp-state` | state | SMTP greeting + EHLO capabilities/STARTTLS. |
| `imap` | tcp | Read IMAP greeting. |
| `imap-state` | state | IMAP CAPABILITY/STARTTLS. |
| `pop3` | tcp | Read POP3 +OK banner. |
| `pop3-state` | state | POP3 CAPA/STLS. |
| `ftp` | tcp | Read FTP 220 banner. |
| `ftp-state` | state | FTP FEAT/AUTH TLS. |
| `managesieve` | tcp | Read ManageSieve capability greeting. |
| `managesieve-state` | state | ManageSieve capability/STARTTLS/SASL. `--after-tls` is a lab-only NOOP wake-up. |

### Batch C first wave (6)

| Probe | Type | What it does |
|:---|:---:|:---|
| `ipp` | tcp | IPP Get-Printer-Attributes over HTTP. |
| `ipp-state` | state | IPP over tcp-state/TLS. |
| `amqp` | tcp | AMQP 0-9-1 protocol header/Connection.Start. |
| `amqp-state` | state | AMQP over tcp-state/TLS. |
| `pptp` | tcp | PPTP Start-Control-Connection-Request/Reply. |
| `pptp-state` | state | PPTP control connection over tcp-state. |

### Fingerprinting (5)

| Probe | Type | What it does |
|:---|:---:|:---|
| `recog` | tcp | Match Recog XML fingerprints against the banner. |
| `recog-udp` | udp | The same for UDP. |
| `recog-state` | state | The same over stateful TCP. |
| `nmap` | tcp | Run an `nmap-service-probes` probe and parse its matches. |
| `nmap-udp` | udp | The same for UDP. |

### Scriptable (2)

| Probe | Type | What it does |
|:---|:---:|:---|
| `lua-tcp` | tcp | Load a Lua script that implements `Make_payload` / `Get_payload_length` / `Handle_response`. |
| `lua-udp` | udp | The same for UDP. |

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe lua-tcp \
  -probe-arg "-script lua-probes/tcp-example.lua" -show info
```

Lua is loaded at runtime; if no Lua shared library is available the probes are still listed but fail at startup with a load error (install Lua 5.3 or 5.4). Lua probes use separate tx/rx/handler Lua states; selecting `lua-tcp`/`lua-udp` currently forces `--tx-thread-count 1` and `--rx-handler-count 1`.
The example scripts in `lua-probes/` declare `ProbeName`, `ProbeType` and
`ProbeDesc` in the script header.

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
  a one-line description; `--help-<kind> <name>` prints type, slot plan and
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
