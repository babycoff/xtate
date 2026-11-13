# 01 · Install and quick start

This chapter takes you from a source checkout to a verified binary, a first
command-line scan and a first session in the 3.0 console. It assumes a shell,
`sudo` on Linux, and an elevated PowerShell on Windows.

Use only on networks you own or have written permission to test. Xtate sends
real packets; there is no harmless "test mode" for a real scan.

## What you need

| Item | Requirement |
|:---|:---|
| OS | Linux (Ubuntu 22.04/24.04 reference) or Windows 10/11 |
| CPU | 64-bit little-endian only; the build stops early otherwise |
| Packet I/O | libpcap (Linux) or Npcap in WinPcap-compatible mode (Windows) |
| Privileges | root or `CAP_NET_RAW`+`CAP_NET_ADMIN` on Linux; Administrator on Windows |
| Build | CMake ≥ 3.13 and a C99 compiler (GCC, Clang, MSVC or MinGW-w64) |

## Verify or build the binary

A prebuilt `bin/xtate.exe` (Windows) or `bin/xtate` (Linux) may already exist in
the checkout. Verify it first:

```bash
./bin/xtate --version
./bin/xtate --selftest
```

`--version` prints the release, compiler, OS and the optional libraries it
found (OpenSSL, PCRE2, LibXml2, libbson, libmongoc). `--selftest` runs the
built-in regression suite and exits non-zero if a test fails.

### Build on Linux

```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libpcap-dev \
  libssl-dev libpcre2-dev libxml2-dev libbson-dev libmongoc-dev \
  libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev

./build.sh --compiler gcc --config release
./bin/xtate --version
./bin/xtate --selftest
```

`./build.sh` with no arguments asks for a compiler and configuration. A manual
CMake build works too:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 8
./build/xtate --version
```

### Build on Windows

1. Install Visual Studio 2022 or 2026 with **Desktop development with C++**.
2. Install CMake ≥ 3.13 and Npcap (WinPcap-compatible mode).
3. Install OpenSSL: `scoop install openssl-lts`.
4. Optional: install the vcpkg dependencies for the full module set and zstd
   result compression:

   ```powershell
   scoop install vcpkg
   vcpkg install pcre2 libxml2 mongo-c-driver zstd --triplet x64-windows
   ```

   `scripts\build-windows.ps1` finds `VCPKG_ROOT` and passes the toolchain
   automatically. For the manual CMake command below, also pass
   `-DCMAKE_TOOLCHAIN_FILE="$env:USERPROFILE\scoop\apps\vcpkg\current\scripts\buildsystems\vcpkg.cmake"`.

5. Build from a normal PowerShell (scans still need an elevated shell):

```powershell
cmake -S . -B build-msvc -G "Visual Studio 17 2022" -A x64 `
  -DOPENSSL_ROOT_DIR="$env:USERPROFILE\scoop\apps\openssl-lts\current"
cmake --build build-msvc --config Release -j 8
.\build-msvc\Release\xtate.exe --version
.\build-msvc\Release\xtate.exe --selftest
```

Or let the build script choose the toolchain and verify the result:

```powershell
pwsh -File .\scripts\build-windows.ps1 -Toolchain msvc -Config Release -Yes
```

A complete build has 12 scans, 60 probes, 7 output modules and 5 generate
modules. Without ngtcp2/GnuTLS (the default on Windows) expect 11 scans and 59
probes; missing PCRE2 or OpenSSL removes more probes. Fewer modules is not a
build failure — it means an optional library was not found. Without zstd,
`--result-compress=zstd` falls back to uncompressed chunks and
`--list-capabilities` reports `zstd:false`. See
[Getting started](../getting-started.md) for the full dependency matrix.

### Permissions

Raw sockets need privileges. On Linux, grant the binary capabilities once per
build instead of using `sudo` every time:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/xtate
```

On Windows, run scans from an elevated shell with Npcap installed.

## Your first scan

A stateless TCP SYN scan needs no firewall changes:

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 1000
```

What you should see:

- One result line per host/port on **stdout**, for example
  `[+] host: 192.168.1.10 port: 80 in tcp is "open" because "syn-ack"`.
- Only `success`-level results by default. Add `-show failed` to see closed
  ports, `-show info` for informational records, or `-show all` for everything.
- A live status bar on **stderr**, so `> results.txt` keeps the file clean.
  `--no-status` disables it.
- `Ctrl-C` stops transmission; late replies are collected for `--wait` seconds
  (default 10). A second `Ctrl-C` aborts immediately.

Ports are required for port-scoped scans (`tcp-syn`, `zbanner`, `tcp-state`,
`udp`, `sctp-init`, `yarrp-udp`). Without `-p`, Xtate warns and substitutes a
fake `o:0` endpoint. Most engines ignore it, but YARRP topology scans use the
port field as a TTL; for those, `o:0` still builds a packet with TTL 0 — pass a
real TTL instead.

### Check the route before scanning

```bash
./bin/xtate --list-if
./bin/xtate --explain-target 192.168.1.0/24
./bin/xtate --check --explain-target 192.168.1.0/24
```

`--list-if` lists adapters with IPv4, MAC, gateway and state. `--explain-target`
is a read-only route summary for a target set. `--check` adds a read-only check
of the interface, link type and raw-IP capability; it exits non-zero if the link
cannot carry raw IP. Linux firewall rules are a separate step, covered in
[Linux firewall](../firewall.md).

If several default interfaces exist and `-if` is omitted, Xtate fails closed
with an ambiguity error instead of guessing. Pin one with `-if 3` or a unique
description substring, for example `-if "Intel(R) Wi-Fi"`.

## Stateful scans need firewall rules on Linux

`zbanner`, `tcp-state`, `tls-state`, `http-state` and every state sub-probe
complete a real TCP handshake with raw packets. The Linux kernel does not know
about those connections and answers the peer with a RST, killing the flow. For
the duration of such a scan, suppress outgoing RSTs:

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe http \
  -scan-arg "-banner" -rate 1000 -show info
./firewall/rm_rules.sh
```

These rules are host-wide and affect unrelated traffic while installed. Add
them before the scan and remove them immediately afterwards. On Windows there
is no bundled equivalent; read the Windows notes in
[Getting started](../getting-started.md) and
[Known limitations](../known-limitations.md) before running stateful scans.

## Your first GUI session

The console starts its own private control plane when you do not attach it to
an existing one:

```bash
sudo ./bin/xtate --gui
```

The process prints the listening URL, the control endpoint and a per-session
token. It does **not** launch a browser; open the printed address yourself. The
default address is `http://127.0.0.1:8787/`; `--gui-listen=127.0.0.1:0` picks a
free port. Loopback is the default; a non-loopback bind requires the explicit
`XTATE_GUI_ALLOW_REMOTE=1` container opt-in.

In the browser:

1. On **New scan**, keep or edit the target scope. **Use sample** fills a
   documentation range that is safe to type but is not a real target.
2. Pick a scan card, ports (default `80,443`), an optional probe, rate and
   timeout.
3. Leave **Interface** on *Auto (from route)* unless the route is ambiguous or
   you are scanning through a TUN/VPN adapter.
4. Wait for **Preflight** to pass. It checks the catalog, ports, targets and
   route without sending packets.
5. Tick the authorization checkbox. **Start scan** becomes enabled only when
   preflight passed and authorization is confirmed.

The scan opens on **Live scan**. You can leave the page; the daemon keeps
running it. Jobs started through a private GUI stop when the GUI process exits;
use `--control-connect` to attach to a daemon that outlives the console (see
[02 · GUI console](./02-gui-console.md)).

## Next steps

| Goal | Read |
|:---|:---|
| Tour every console page and field | [02 · GUI console](./02-gui-console.md) |
| Scan/probe examples, control plane, managed jobs | [03 · CLI and jobs](./03-cli-and-jobs.md) |
| Target and port syntax | [Targets and ports](../targets-and-ports.md) |
| Choose scan engines and probes | [Scanning modes](../scanning-modes.md) |
| Save, chunk or convert results | [Output](../output.md) |
| Fix empty or surprising results | [Troubleshooting](../troubleshooting.md) |
| Windows specifics | [Windows quick start](../windows-quickstart.md) |
| Firewall rules in detail | [Firewall](../firewall.md) |
