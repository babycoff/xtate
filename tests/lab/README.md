# Local ZBanner / HLTCP lab

This is an isolated regression lab for ZBanner and HLTCP. It does **not** scan the
Internet: both targets are Docker containers on a dedicated bridge network.

## Requirements

- Docker
- A Linux `xtate` binary, default `./bin/xtate`; override with `XTATE_BIN`
- A Ubuntu 24.04 image with `python3`, `openssl`, `iptables`, and the Xtate
  runtime libraries (`libxml2`, libbson, libmongoc, libpcap), default
  `xtate-builder:24.04`; override with `XTATE_LAB_IMAGE`.

For an offline/repeatable lab, build the small target image once (it uses the
mainland mirror on purpose):

```bash
docker build -t xtate-lab-target:24.04 tests/lab
XTATE_LAB_IMAGE=xtate-lab-target:24.04 bash tests/lab/run.sh
```

If `docker build` cannot reach the mirror, the existing
`xtate-builder:24.04` fallback still works when the host has network.

On Windows, run it through Git Bash (Docker Desktop must be running).

```powershell
$env:XTATE_BIN = "C:\path\to\xtate-linux"
$env:XTATE_LAB_IMAGE = "xtate-builder:24.04"
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /c/path/to/xtate && bash tests/lab/run.sh"
```

## What it checks

- ZBanner default: HTTP open + `responsed` + closed port.
- ZBanner `--record-ack`: **closed port is still reported** (regression for the
  RST-vs-ACK ordering fix).
- HLTCP `http-state`: local HTTP target receives a request and the scan succeeds.
- HLTCP `tls-state`: local TLS 1.3 target, version/cipher/certificate output, merged
  `--ssl-keylog` diagnostics, and `--graceful-tls-close` (the scanner still exits cleanly;
  `close_notify` delivery is additionally spot-checked manually).
- SSH banner: the `ssh` probe reads `SSH-2.0-OpenSSH_9.9` and a coalesced
  KEXINIT from a local fake SSH target; it reports `ssh_banner`,
  `ssh_protocol`, `ssh_kex_algorithms` and `ssh_host_key_algorithms`.
- h2c: the `h2c` probe sends the cleartext HTTP/2 preface and reports SETTINGS/
  frames from a local fake cleartext h2c target. This does not test HTTP/2 over TLS.
- h2: `tcp-state + tls-state --alpn h2 -subprobe h2` against a local TLS ALPN h2
  target; reports `h2_status`, HEADERS and DATA.
- TCP `ProbeSlot_Always`: `slot-test` sends three slots to the HTTP target and
  reports `slot_test_slot` 1..3.
- UDP `ProbeSlot_Always`: `slot-test-udp` sends three datagrams to the UDP echo
  target and reports `slot_test_slot` 1..3.
- QUIC: a local `aioquic` server receives a real v1 Initial; the probe reports
  `quic_response: initial`. A second server runs with Retry enabled and must
  produce `retry` with a token. This is capability only, not HTTP/3.
- ZBanner JARM: ten slots against a dedicated local TLS target on port 9443;
  output contains `jarm_slot`, `jarm_slots` and `jarm_part`. The lab compares
  the aggregated hash with the vendored Salesforce `tests/reference/jarm.py`
  on the same target. A second run uses `--first-probe 7` and verifies that the
  standard slot id is preserved while the burst is rotated. The output-side
  `tools/jarm_aggregate.py` is tested separately because it is not a scanner
  hot-path component.
- HLTCP `tls-state -> http-state`: the sub-probe initializes after the TLS handshake and
  completes an HTTP exchange inside the tunnel.
- HLTCP SNI/ALPN: the TLS target uses `openssl s_server -tlsextdebug`; the
  scanner output asserts negotiated `tls_alpn` (`-sni example.test -alpn h2,http/1.1`).

The scanner runs at 100 pps. Firewall RST suppression is installed only inside
the throwaway scanner container. Containers, network and rules are removed by a
trap on exit.

## QUIC

The lab starts a local **aioquic** QUIC server. The `udp` + `quic` probe
must build a valid v1 Initial and classify the response. A second server uses
`retry=True` so the probe must report a Retry with a token. Neither test claims
HTTP/3.

## STARTTLS

The lab starts a local Python target with SMTP, IMAP, POP3 and FTP STARTTLS
listeners. `tls-state --starttls <proto> --dump-cert-details` must complete the
plaintext upgrade and report the certificate subject.

## Notes

- The script normalizes `firewall/*.sh` line endings before running, so a
  Windows checkout with CRLF does not break the container command.
- The TLS target uses a self-signed certificate generated inside its container.
- `--lan` is intentionally not part of the main regression: its broadcast path
  is environment-dependent and should be tested separately on a real LAN.

## Focused CI scripts

For release/nightly jobs that only need encrypted-protocol coverage:

```bash
XTATE_BIN=./bin/xtate \
XTATE_LAB_IMAGE=xtate-builder:24.04 \
XTATE_LAB_TARGET_IMAGE=xtate-lab-target:24.04 \
bash tests/lab/ci-h2.sh

XTATE_BIN=./bin/xtate \
XTATE_LAB_IMAGE=xtate-builder:24.04 \
XTATE_LAB_TARGET_IMAGE=xtate-lab-target:24.04 \
bash tests/lab/ci-quic.sh
```

`ci-h2.sh` starts a local TLS HTTP/2 target and checks status, headers and body.
`ci-quic.sh` starts a local aioquic HTTP/3 target and checks status, body and
body-scope matching; it skips cleanly when `quic-state` was not built.

Both scripts are Docker-only local/nightly tests. They are deliberately not in
the fast pull-request CI matrix because they need a target image with Python,
OpenSSL, aioquic and the optional ngtcp2 runtime.
