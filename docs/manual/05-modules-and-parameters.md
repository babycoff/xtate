# 05 · Modules and parameters

Xtate is assembled from four kinds of modules. A scan chooses exactly one scan
module, optionally one probe module, one output module and one target
generator.

| Kind | Count (full build) | Selector | Role |
|:---|:---:|:---|:---|
| Scan | 12 | `-scan` | Sends packets and classifies responses |
| Probe | 60 | `-probe` | Optional deeper parsing on top of a scan |
| Output | 7 | `-output-module` | Writes result records |
| Generate | 5 | `-gen` | Produces the target/port stream |

Builds without ngtcp2 (and a TLS provider it can use) do not register
`quic-state` and one probe, giving 11 / 59 / 7 / 5. Everything in this chapter
describes a full build; omitted modules simply do not appear in the lists.

## Finding modules and their parameters

```bash
xtate --list-scan
xtate --list-probe
xtate --list-out
xtate --list-gen

xtate --help-scan=tcp-syn
xtate --help-probe=tls-state
xtate --help-output=mongodb
xtate --help-gen=ip-stream
```

`--list-modules-json` prints the same registry as JSON with names, kinds,
probe types and parameter tables, which is useful for tooling. `--search-module`
uses fuzzy name matching (edit distance 2), so a typo such as
`--search-module zbannr` still finds `zbanner`:

```bash
xtate --search-module banner
```

Module names are stable identifiers. They are case-sensitive and use hyphens,
for example `tcp-syn`, `tcp-state`, `tls-state` and `http-state`.

The 3.0 GUI uses the same registry and the same four categories: **Scan
modules**, **Probe modules**, **Output modules** and **Generate modules**.
Clicking a module card expands its full description and parameter table, so you
can inspect names, types, descriptions and aliases before selecting it. The
console also has a controlled **Global parameters** list: 23 safe scan-wide
options are exposed there and sent as `global_args`. Process/file/script
options, control-plane or job internals, and fields already represented by the
form (targets, ports, rate, interface, module names) are deliberately excluded.

## Passing arguments

Module options are not global flags. They travel in one quoted string per
module:

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-syn \
  -scan-arg "--record-ttl --record-win"

xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe tls-hello \
  -probe-arg "--support-tls13"
```

- `-scan-arg` (`--scan-module-args`, `--scan-module-arg`, `--scanner-arg`)
  applies to the scan module.
- `-probe-arg` (`--probe-module-args`, `--probe-module-arg`, `--probe-args`)
  applies to the probe module.
- `-output-arg` (`--output-module-args`, `--output-module-arg`, `--out-arg`)
  applies to the output module.
- `-gen-arg` (`--generate-module-args`, `--generate-module-arg`,
  `--generator-arg`) applies to the generator.

Each string is split by Xtate, not by your shell, so the whole argument list
must be quoted once. Do not add a second layer of quoting around individual
options; the inner quotes become literal characters. If an option value
contains spaces, quote it inside the argument string, for example
`-probe-arg "-user-agent 'Mozilla/5.0 (compatible)'"`.

Stateful probes nest one more level. `tls-state` needs a concrete state
subprobe, passed through `-subprobe`:

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -subprobe-arg '--url /admin --all-banner'" \
  -show info
```

The nested single quotes are consumed by Xtate's own argument splitter.
Nested quoting is the most common source of `subprobe` errors; a single token
such as `-subprobe-arg --path=/h2` avoids the problem entirely.

## Scan modules

A scan module's required probe type must match the selected probe, otherwise
Xtate refuses to start. `none` means "no probe module".

| Scan module | Probe type | Use |
|:---|:---|:---|
| `tcp-syn` | none | Stateless SYN scan; open/closed |
| `zbanner` | tcp | Stateless handshake plus banner capture |
| `tcp-state` | state | Stateful TCP with a real TCB (HLTCP) |
| `udp` | udp | Single-packet UDP scan |
| `quic-state` | state | Stateful QUIC handshake (optional build) |
| `icmp-echo` | none | ICMP echo reachability |
| `icmp-time` | none | ICMP timestamp reachability |
| `sctp-init` | none | SCTP INIT open/closed |
| `arp-req` | none | ARP on the local link (IPv4) |
| `ndp-ns` | none | NDP neighbour solicitation (IPv6) |
| `yarrp-echo` | none | Stateless ICMP traceroute |
| `yarrp-udp` | none | Stateless UDP traceroute |

Common conventions:

- `--record-*` options add evidence to `scan report`: `--record-ttl`,
  `--record-ipid`, `--record-win`, `--record-mss`, `--record-seqno`,
  `--record-ackno`, `--record-data`, `--record-data-len`, `--record-utf8`.
- `-ttl` options control outgoing TTLs, for example `--syn-ttl` and
  `--rst-ttl` for `tcp-syn`, `--probe-ttl` and `--ack-banner-ttl` for
  `zbanner`.
- Deduplication and retransmission are engine-local:
  `--no-dedup-synack`, `--no-dedup-rst`, `--repeat-synack` and
  `--repeat-rst` for `tcp-syn`; `--no-dedup-*` and `--repeat-*` for
  `zbanner`.
- Port state levels are configurable so results show up under `--show
  info`/`--show failed`: `--port-success`, `--port-failure` (`udp`,
  `zbanner`), `--ack-success` (`zbanner`).

### tcp-syn

```bash
xtate -ip 203.0.113.10 -p 80,443,8000-8100 -scan tcp-syn \
  -scan-arg "--send-rst --record-ttl --record-win"
```

| Option | Meaning |
|:---|:---|
| `--send-rst` | Send RST for open ports (needed on Windows to avoid OS resets) |
| `--fail-zerowin` | Report a SYN-ACK with zero window as failure |
| `--synack-limit N` / `--synack-floor N` | Suppress or cap repeated SYN-ACKs |
| `--record-ipid` | Report IP ID (IPv4 only) |
| `--syn-ttl`, `--rst-ttl` | Outgoing TTL for SYN and RST |

`tcp-syn` sends one SYN per target. Its classification is `open`/`syn-ack` or
`closed`/`rst`; closed results are failures and hidden until `-show failed`.

### zbanner

```bash
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe tls-hello \
  -probe-arg "--support-tls13" \
  -scan-arg "--with-ack --record-banner --record-ttl"
```

`zbanner` completes the handshake without a TCB. Typical options:
`--with-ack`, `--no-rst`, `--probe-zerowin`, `--all-banner`,
`--all-banner-limit`, `--all-banner-floor`, and the `--record-*` family.
Banner bytes are stored in `probe report`/`scan report` and can be printed as
text with `--record-utf8`. Open ports are informational by default; add
`--port-success` if you want them in the default success stream. The
`--all-banner` mode records every banner seen on a connection and warns if the
TCP window or snapshot buffers are too small for multi-banner capture; check
its help before relying on it.

### tcp-state

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state --dump-cert-details" -show info
```

`tcp-state` builds a real TCP state machine per handler thread. Memory is
bounded per thread:

| Option | Default | Meaning |
|:---|:---:|:---|
| `--tcb-mem MiB` (`--tcb-memory`) | 128 | TCB memory budget, split across handler tables |
| `--conn-expire SEC` | 30 | Idle connection expiry |
| `--port-success` | off | Report open as success instead of info |
| `--record-all-ttl/ipid/win/seqno/ackno/len` | off | Record fields from every segment |

`tcp-state` is the only scan module that works with state probes such as
`tls-state`, `http-state` or `get-state`. Choose it whenever you need a
protocol conversation, not just a port verdict.

### udp

```bash
xtate -ip 203.0.113.10 -p u:53,u:123 -scan udp -probe echo \
  -scan-arg "--record-ttl --record-icmp-id"
```

UDP results are `responsed` when a UDP reply arrives and `closed`/`port
unreachable` when an ICMP error says so. Options include
`--no-port-unreachable` (hide ICMP-derived closes), `--port-failure`,
`--no-pre-validate`, `--repeat-packets`, `--packet-limit` and
`--packet-floor`.

### icmp-echo, icmp-time, sctp-init, arp-req, ndp-ns

These engines do not use ports for targeting:

```bash
xtate -ip 203.0.113.0/24 -scan icmp-echo -scan-arg "--record-ttl"
xtate -ip 2001:db8::/64 -scan ndp-ns -scan-arg "--record-ttl"
xtate -ip 203.0.113.10 -scan sctp-init -p s:38412
```

`arp-req` needs `--lan-mode` and an IPv4 on-link target; `ndp-ns` wants an
IPv6 link-local `-src-ip` and `--fake-router-mac` for routed targets. Both
are local-link tools, not internet scanners. `sctp-init` uses `-p s:PORT`.

### yarrp-echo and yarrp-udp

```bash
xtate -ip 203.0.113.10 -scan yarrp-echo -p o:1-20 -gen blackrock
xtate -ip 203.0.113.10 -p o:1-20 -scan yarrp-udp \
  -scan-arg "--init-target-port 33434"
```

`yarrp-*` encode the TTL or port offset in the `o:` port space, so `-p o:1-20`
is required. Results carry `path`, `destination` and `distance`. They only work
with `-gen blackrock`.

### quic-state (optional)

Built with ngtcp2/GnuTLS. It performs a real QUIC handshake and reports
version, ALPN and optionally the certificate:

| Option | Meaning |
|:---|:---|
| `--alpn` | ALPN list (default `h3`) |
| `--sni` | TLS server name |
| `--max-flows`, `--flow-timeout` | Flow table size and idle removal |
| `--max-udp-payload` | Advertised max UDP payload (1200–65527) |
| `--no-cert` | Skip certificate extraction |
| `--handshake-timeout`, `--idle-timeout` | QUIC timers |

## Probe modules

Probes are only useful with a compatible scan module. A `tcp` probe works with
`zbanner`; a `state` probe works with `tcp-state`; a `udp` probe works with
`udp`. The probe type is printed by `--list-probe` and `--help-probe`.

Probe groups (base list, 59 probes; a build with ngtcp2 adds an HTTP/3 probe
for 60):

- 25 general-purpose probes (HTTP, TLS, SSH, DNS, mail and other common
  protocols).
- 16 + 6 application/protocol probes in two batches (database, VoIP, file
  transfer, tunnelling and similar handshakes).
- 5 fingerprinting probes (nmap/recog matching, JARM, TLS ClientHello
  fingerprinting, SSH key exchange).
- 2 scriptable probes (`lua-tcp`, `lua-udp`).
- 2 developer probes (raw hello exchange, TCP and UDP variants).
- 3 plumbing probes (null, echo, connection close).

### http

The default request is `GET / HTTP/1.0` with an Xtate `User-Agent` and
`Accept: */*`.

```bash
xtate -ip 203.0.113.10 -p 80 -scan zbanner -probe http \
  -probe-arg "--url /admin --method GET --record-body --max-body 8192" \
  -show info
```

Options: `--no-record-status`, `--no-record-headers`, `--record-body`,
`--max-body` (default 4096), `--method`, `--url`, `--version`, `--host`,
`--dynamic-host`, `--user-agent`, `--payload`, `--cookie`, `--header`,
`--remove`, `--keyword`, `--regex`, `--match-scope all|headers|body`,
`--case-insensitive`, `--include-newlines`.

### tls-state

Requires a state subprobe, OpenSSL and a stateful scan:

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-state -probe tls-state \
  -probe-arg "-subprobe http-state -subprobe-arg '--url / --all-banner'" \
  -show info
```

| Option | Meaning |
|:---|:---|
| `--subprobe NAME` | State probe to run inside TLS (required) |
| `--subprobe-arg "..."` | Arguments for that subprobe |
| `--starttls smtp, imap, pop3, ftp, managesieve` | Plaintext upgrade before TLS |
| `--sni`, `--alpn` | TLS handshake parameters |
| `--dump-version`, `--dump-cipher`, `--dump-cert-details`, `--dump-subject` | Evidence |
| `--dump-cert`, `--fail-handshake`, `--graceful-tls-close` | Certificate/behaviour controls |

`--starttls` performs the greeting/upgrade exchange and starts TLS on the same
connection; the subprobe never sees the plaintext phase.

### jarm

`jarm` has ten slots and the trigger `after first reply`: the first ClientHello
is sent normally, and once a TLS-looking reply arrives the other nine are sent
as a burst.

```bash
xtate -ip 203.0.113.10 -p 443 -scan zbanner -probe jarm -show info
python3 tools/jarm_aggregate.py scan.ndjson --complete-out jarm.jsonl
```

`--first-probe N` changes which probe goes first; the remaining nine still
follow, in rotated order. `--probe-index N` sends only probe N and produces an
incomplete fingerprint (debugging only). Every slot emits `jarm_part` and
`jarm_slot`; aggregate them with the tool to get a JARM hash.

### Other fingerprinting and scripting probes

```bash
# nmap service probes
xtate -ip 203.0.113.10 -p 22 -scan zbanner -probe nmap \
  -probe-arg "--probe-file nmap-service-probes"

# recog fingerprints
xtate -ip 203.0.113.10 -p 80 -scan zbanner -probe recog \
  -probe-arg "--file recog-fingerprints.txt --unprefix"

# scripted probe
xtate -ip 203.0.113.10 -p 8080 -scan zbanner -probe lua-tcp \
  -probe-arg "--script myscript.lua"
```

- `nmap` accepts `--probe-file`, `--probe-name`, `--softmatch`; it needs PCRE2.
- `recog` accepts `--string`, `--base64-string`, `--nmap-string`, `--file`,
  `--recog-xml`, `--unprefix`, `--unsuffix`; it needs PCRE2 and libxml2.
- `lua-tcp`/`lua-udp` accept `--script`; if Lua support was not built, the
  probe fails at startup rather than silently skipping the scan.
- `hello`/`hello-udp` are developer probes: `--string`, `--base64-string`,
  `--nmap-string`, `--file`, `--regex`, `--case-insensitive`,
  `--include-newlines`.
- `tls-hello` is a single ClientHello with `--support-tls13`, `--regex`,
  `--case-insensitive`, `--include-newlines`; it does not perform a handshake.

### Multi-slot probes

Most probes use one slot. Probes may declare a slot plan:

- `Always`: each target sends one packet per slot immediately. Used by
  ZBanner/TCP and UDP engines.
- `AfterFirstReply`: the first slot is sent, and the remaining slots fan out
  only after an acceptable first reply. `jarm` is the notable user.

Slot `i` uses source port `src_port_start + i`, so the configured source port
range must be at least as large as the slot count. Each slot produces its own
result record (`jarm_part`); there is no group state and no cross-slot
aggregation inside Xtate.

## Output modules

| Module | Destination | Notable options |
|:---|:---|:---|
| `text` | file (or `-` for stdout) | none |
| `ndjson` | file (or `-`) | none |
| `csv` | file (or `-`) | none |
| `list` | file (or `-`) | `--no-port` |
| `bson` | binary file | `--compact-mode` |
| `mongodb` | MongoDB URI via `-o` | `--database-name`, `--collection-name`, `--insert-bulk`, `--bulk-size`, `--retry-count`, `--retry-delay` |
| `null` | discards | none |

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -show all \
  -output-module ndjson -o out.ndjson

xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -show all \
  -output-module list -output-arg "--no-port" -o addresses.txt

xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -show all \
  -output-module mongodb -o "mongodb://127.0.0.1:27017" \
  -output-arg "--database-name scans --collection-name run1"
```

Format details and escaping are covered in
[06 · Results and files](./06-results-and-files.md).

## Generate modules

| Generator | Input | Use |
|:---|:---|:---|
| `blackrock` | `-ip`, `-p` | Default; randomises the address × port space |
| `ip-list` | file/stdin | One address per line, fixed ports |
| `addr-list` | file/stdin | Address/port pairs per line |
| `ip-stream` | file/stdin | Streaming addresses, fixed ports |
| `addr-stream` | file/stdin | Streaming address/port pairs |

```bash
xtate -gen ip-list -gen-arg "--ip-file hosts.txt --default-port 443" \
  -tx-thread-count 1 -scan tcp-syn -show all

xtate -gen addr-list -gen-arg "--address-file targets.txt --splitter ','" \
  -tx-thread-count 1 -scan tcp-syn
```

Generator options:

- `blackrock`: `--rounds N` (default 14), `--no-random` (natural order).
- `ip-list`, `ip-stream`: `--ip-file FILE` (default stdin), `--default-port`
  (or `--port`), `--rounds`, `--no-random`.
- `addr-list`, `addr-stream`: `--address-file FILE` (default stdin),
  `--splitter STRING` (default a single space).
- All four line/stream generators share `--strict-errors`, `--max-errors` and
  `--max-error-rate`; see [03 · CLI and jobs](./03-cli-and-jobs.md).

The four line/stream generators require a single transmission thread:
`-tx-thread-count 1`. They block the transmit thread while waiting for input,
so they deliberately relax the rate guarantee (they never exceed the
configured rate).

## Dependencies and limits

| Feature | Requires |
|:---|:---|
| `tls-state`, `jarm`, TLS handshakes, SSH key exchange | OpenSSL |
| `quic-state`, QUIC probes, HTTP/3 | ngtcp2 + GnuTLS |
| `http` regex, `hello` regex, `nmap`, `recog` | PCRE2 |
| `recog` XML parsing | libxml2 |
| BSON output | libbson |
| MongoDB output | libmongoc |
| Compressed result chunks | zstd |
| `lua-*` probes | Lua support in the build |

Limits worth remembering:

- One scan module, at most one probe, one output module and one generator.
- A probe's type must match the scan module's required type.
- Argument strings are parsed by Xtate, not your shell; nested quoting must
  survive two levels for `tls-state` subprobes.
- Probe and scan parameters are recorded in help; `--help-*` is authoritative
  for names, aliases and defaults.
- Module names are stable API: tooling may rely on `tcp-syn`, `zbanner`,
  `tls-state` and the other listed identifiers.

## See also

- [04 · Targets and scanning](./04-targets-and-scanning.md) — target syntax,
  engines and rate semantics
- [Modules](../modules.md) — full registry and descriptions
- [TLS composition](../tls-composition.md) — deeper `tls-state` recipes
- [Scanning modes](../scanning-modes.md) — which engine to pick
- [Output](../output.md) — output formats
- [JSON contracts](../json-contracts.md) — module schema for tooling
