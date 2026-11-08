# Protocol coverage plan

**English** · [中文](zh-CN/protocol-coverage.md)

This is a follow-up plan, not a promise to implement every protocol. The
reference list is the zgrab2 module table
(<https://github.com/zmap/zgrab2>). Xtate should use zgrab2 as a behavior and
test reference, not copy its code or promise output compatibility.

## Current Xtate coverage

| Protocol | Xtate status | Notes |
|:---|:---|:---|
| HTTP | `http`, `http-state` | HTTP/1 work is frozen at the structured response parser pass. |
| JARM | `jarm` | Salesforce 1.0 hash, official-reference comparison, `--first-probe`. |
| SSH | `ssh` | Banner/software and KEXINIT lists; real KEX exchange is future work. |
| TLS | `tls-state`, `tls-hello` | Certificates/details, ALPN, SNI and JARM; STARTTLS adapters exist. |
| Redis | `redis` | Read-only INFO server identification. |
| Memcached | `memcached` | Version-line identification. |
| NTP | `ntp` | Mode-3 request with structured fields. |
| MQTT | `mqtt` | CONNECT/CONNACK. |
| SOCKS5 | `socks5` | Greeting/method selection. |
| Telnet | `telnet` | Banner and initial IAC options. |
| SMTP | STARTTLS only | `tls-state --starttls smtp`; no full SMTP command probe yet. |
| IMAP | STARTTLS only | `tls-state --starttls imap`; no full IMAP probe yet. |
| POP3 | STARTTLS only | `tls-state --starttls pop3`; no full POP3 probe yet. |
| FTP | STARTTLS only | `tls-state --starttls ftp`; no full FTP probe yet. |
| MongoDB | `mongodb` | OP_MSG hello/BSON identification. |
| MySQL | `mysql`, `mysql-state` | Greeting identification; no auth. |
| PostgreSQL | `postgres`, `postgres-state` | SSLRequest and auth-boundary probe. |
| SMTP | `smtp`, `smtp-state` | Banner / EHLO capabilities. |
| IMAP | `imap`, `imap-state` | Banner / CAPABILITY. |
| POP3 | `pop3`, `pop3-state` | Banner / CAPA. |
| FTP | `ftp`, `ftp-state` | Banner / FEAT. |
| ManageSieve | `managesieve`, `managesieve-state` | Capability greeting. |
| IPP | `ipp`, `ipp-state` | Get-Printer-Attributes. |
| AMQP | `amqp`, `amqp-state` | Protocol header/Connection.Start. |
| PPTP | `pptp`, `pptp-state` | Start-Control-Connection. |
| Banner | `null` / `hello` | Generic capture, not protocol-aware. |
| Everything else | absent | See the matrix below. |

## zgrab2 reference matrix

**Tier 1** = single request or short exchange, low risk, best first batch.
**Tier 2** = stateful/multi-step or binary handshake.
**Tier 3** = OT/industrial, highest parsing and safety review cost.

| Protocol | zgrab2 module | Xtate status | Planned tier | Suggested engine |
|:---|:---:|:---|:---:|:---|
| AMQP | yes | `amqp`/`amqp-state` | 1/2 | tcp/state |
| BACnet | yes | absent | 3 | UDP/state |
| Banner | yes | generic only | 1 | tcp/udp |
| DNP3 | yes | absent | 3 | state |
| Fox | yes | absent | 3 | state |
| FTP | yes | `ftp`/`ftp-state` | 1/2 | tcp/state |
| HTTP | yes | partial/frozen | - | tcp/state |
| IMAP | yes | `imap`/`imap-state` | 1/2 | tcp/state |
| IPP | yes | `ipp`/`ipp-state` | 1/2 | tcp/state |
| JARM | yes | done | - | tcp slots |
| ManageSieve | yes | `managesieve`/`managesieve-state` | 1/2 | tcp/state |
| Memcached | yes | `memcached` | 1 | tcp |
| Modbus | yes | absent | 3 | state |
| MongoDB | yes | `mongodb` | 1 | tcp |
| MQTT | yes | `mqtt` | 1 | tcp |
| MSSQL | yes | absent | 2 | state |
| MySQL | yes | `mysql`/`mysql-state` | 1/2 | tcp/state |
| NTP | yes | `ntp` | 1 | UDP |
| Oracle | yes | absent | 2 | state |
| POP3 | yes | `pop3`/`pop3-state` | 1/2 | tcp/state |
| PostgreSQL | yes | `postgres`/`postgres-state` | 1/2 | tcp/state |
| PPTP | yes | `pptp`/`pptp-state` | 1/2 | tcp/state |
| Redis | yes | `redis` | 1 | tcp |
| Siemens S7 | yes | absent | 3 | state |
| SMB | yes | absent | 2 | state |
| SMTP | yes | `smtp`/`smtp-state` | 1/2 | tcp/state |
| SOCKS5 | yes | `socks5` | 1 | state |
| SSH | yes | partial | 2 | state |
| Telnet | yes | `telnet` | 1 | state |
| TLS | yes | done/partial | - | state/tcp |

## Implementation rules

- A probe emits **structured fields**, not only a banner: protocol version,
  selected method/algorithm, server identity and bounded error reason.
- Single-packet protocols use `tcp`/`udp`; multi-step handshakes use `state`
  probes on `tcp-state`. Do not add per-target state to ZBanner.
- Reuse the existing TLS layer for implicit TLS and the four STARTTLS adapters
  where the protocol supports an upgrade.
- Every payload is bounded; no unbounded reads, regex backtracking or
  decompression.
- Optional protocol libraries stay optional and must not change the default
  build.
- Each new probe gets a local deterministic fake server and lab case. A public
  Internet target is not a test fixture.

## Suggested batches

### Batch A — high-value, low complexity

Redis, Memcached, MQTT, Telnet, SOCKS5, NTP, and protocol-aware banner probes.
These mostly need one request/response plus a small structured parser.

### Batch B — database and mail handshakes

MySQL, PostgreSQL, MSSQL, MongoDB, SMTP, IMAP, POP3, FTP, ManageSieve.
These need stateful reads, multi-line parsing, TLS/STARTTLS composition and
careful authentication-off defaults.

### Batch C — enterprise/file services

AMQP, IPP, SMB, Oracle, PPTP. Binary structures and negotiation paths are larger;
test fixtures and bounded parsers are mandatory.

### Batch D — OT/industrial

Modbus, DNP3, BACnet, Siemens S7, Fox. Treat this as a separate safety-reviewed
workstream; never send write/control requests by default.

## Non-goals

- zgrab2 output compatibility;
- copying zgrab2 code without license review;
- credential guessing, authentication bypass or default-password spraying;
- unbounded protocol fuzzing in the scanner hot path.

## Acceptance for a batch

- at least one local fixture per protocol;
- deterministic success and malformed-response cases;
- fields documented in English and Chinese;
- `--help-probe` describes the request and safety boundary;
- Linux and Windows builds unaffected when optional dependencies are absent.
