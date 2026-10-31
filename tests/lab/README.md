# Local ZBanner / HLTCP lab

This is an isolated regression lab for ZBanner and HLTCP. It does **not** scan the
Internet: both targets are Docker containers on a dedicated bridge network.

## Requirements

- Docker
- A Linux `xtate` binary, default `./bin/xtate`; override with `XTATE_BIN`
- A Ubuntu 24.04 image with build tools, default `xtate-builder:24.04`; override
  with `XTATE_LAB_IMAGE`

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
- HLTCP `tls-state -> http-state`: the sub-probe initializes after the TLS handshake and
  completes an HTTP exchange inside the tunnel.
- HLTCP SNI/ALPN: target uses `openssl s_server -tlsextdebug`; the lab asserts that the
  `server name` and `application layer protocol negotiation` extensions arrived
  (`-sni example.test -alpn h2,http/1.1`).

The scanner runs at 100 pps. Firewall RST suppression is installed only inside
the throwaway scanner container. Containers, network and rules are removed by a
trap on exit.

## Notes

- The script normalizes `firewall/*.sh` line endings before running, so a
  Windows checkout with CRLF does not break the container command.
- The TLS target uses a self-signed certificate generated inside its container.
- `--lan` is intentionally not part of the main regression: its broadcast path
  is environment-dependent and should be tested separately on a real LAN.
