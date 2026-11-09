# TLS and STARTTLS composition

**English** · [中文](zh-CN/tls-composition.md)

`tls-state` is not an application probe. It is a TLS middle layer inside HLTCP:

```text
tcp-state -> tls-state -> state sub-probe inside TLS
```

The sub-probe never sees the plaintext STARTTLS exchange. That separation is the
reason `--after-tls` exists.

## The two composition modes

### Implicit TLS

The server speaks TLS immediately, for example:

```text
SMTPS          465
IMAPS          993
POP3S          995
FTPS implicit  990
MySQL TLS      3306
PostgreSQL TLS 5432
MongoDB TLS    27017
```

`tls-state` performs the handshake, then starts the state sub-probe inside TLS.

### STARTTLS

The connection starts in plaintext, negotiates an upgrade, then switches to TLS:

```text
SMTP      220 -> EHLO -> STARTTLS -> 220 -> TLS
IMAP      * OK -> a001 STARTTLS -> a001 OK -> TLS
POP3      +OK -> STLS -> +OK -> TLS
FTP       220 -> AUTH TLS -> 234 -> TLS
ManageSieve greeting -> STARTTLS -> "OK" -> TLS
```

`tls-state` consumes the plaintext greeting and the upgrade response. The
sub-probe starts **after** the TLS handshake and must not wait for that greeting
again.

## What `--after-tls` means

`--after-tls` does **not** enable TLS. It only changes the sub-probe state machine:

> "The plaintext greeting/SSLRequest phase already happened, or I am already
> inside TLS. Skip that phase and run the post-TLS flow."

It is a parameter of the **sub-probe**, passed through `-subprobe-arg`, not a
parameter of `tls-state` itself.

## Per-protocol behavior

| Probe | Default (plaintext) | `--after-tls` |
|:---|:---|:---|
| `smtp-state` | wait `220`, send `EHLO` | skip `220`, send `EHLO` |
| `imap-state` | wait `* OK`, send `CAPABILITY` | skip `* OK`, send `CAPABILITY` |
| `pop3-state` | wait `+OK`, send `CAPA` | skip `+OK`, send `CAPA` |
| `ftp-state` | wait `220`, send `FEAT` | skip `220`, send `FEAT` |
| `postgres-state` | send `SSLRequest`, then `StartupMessage` | skip `SSLRequest`, send `StartupMessage` |
| `mongodb-state` | send `OP_MSG hello` | no flag needed; client-first |
| `mysql-state` | wait server greeting | lab-only COM_PING wake-up |
| `managesieve-state` | wait capability greeting | lab-only NOOP wake-up |

## Examples

### STARTTLS SMTP

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 25 -scan tcp-state -probe tls-state   -probe-arg "-subprobe smtp-state --starttls smtp \
              -subprobe-arg --after-tls \
              -sni mail.example -alpn h2 --dump-cert-details"
```

### Implicit TLS SMTP

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 465 -scan tcp-state -probe tls-state   -probe-arg "-subprobe smtp-state -subprobe-arg --after-tls \
              -sni mail.example --dump-cert-details"
```

### Implicit TLS PostgreSQL

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 5432 -scan tcp-state -probe tls-state   -probe-arg "-subprobe postgres-state -subprobe-arg --after-tls"
```

### Implicit TLS MongoDB

```bash
sudo ./bin/xtate -ip 203.0.113.10 -p 27017 -scan tcp-state -probe tls-state   -probe-arg "-subprobe mongodb-state"
```

## When not to use it

Do not use `--after-tls` for a **plaintext direct scan**:

```bash
# correct: default state probe
-scan tcp-state -probe smtp-state

# wrong: skips a real 220 greeting
-scan tcp-state -probe smtp-state -probe-arg --after-tls
```

`--after-tls` is for the TLS/STARTTLS composition only.

## MySQL and ManageSieve caveat

`mysql-state --after-tls` and `managesieve-state --after-tls` are **lab and
compatibility wake-ups**, not standard handshakes:

- `mysql-state` sends a MySQL COM_PING packet before authentication. Strict or
  real MySQL servers may reject it.
- `managesieve-state` sends NOOP before the capability greeting. It is not a
  replacement for a normal ManageSieve handshake and may be rejected.

They exist to make the server-first TLS timing deterministic in the composition
matrix. Do not treat them as a production guarantee for arbitrary servers.

## Why not automatic?

A sub-probe cannot know:

- whether `tls-state` already consumed the greeting;
- whether the mode is implicit TLS or STARTTLS;
- whether the server will send the greeting again inside TLS.

The explicit flag avoids guessing and makes the state machine reviewable.

## Troubleshooting

| Symptom | Likely cause |
|:---|:---|
| only `open`, no TLS output | Linux firewall rules missing; run `./firewall/add_rules.sh` |
| TLS info, no application result | `--after-tls` missing for a STARTTLS probe; greeting already consumed |
| `--after-tls` used on plaintext scan | real greeting skipped; remove it |
| MySQL/ManageSieve rejected | lab wake-up sent before normal greeting; use only for lab |
