# Full-feature Ubuntu 24.04 Docker build

**English** · [中文](zh-CN/docker-build.md)

The repository ships a reproducible Ubuntu 24.04 image definition that builds
Xtate with every optional dependency available from the distribution:

- OpenSSL (TLS),
- PCRE2 (banner matching),
- libxml2 (XML probes),
- libbson / libmongoc (MongoDB output),
- ngtcp2 + GnuTLS (HTTP/3 and QUIC transport),
- zstd (compressed result chunks),
- libpcap runtime for capture and interface inspection,
- Lua 5.3 runtime for Lua probes.

This image is the reference Linux build for 3.0. It is intentionally larger
than a runtime-only image; it is a build environment plus a ready-to-run binary.

## Build

From the repository root:

```bash
docker build -f docker/ubuntu24-build/Dockerfile \
  -t xtate:ubuntu24-full .
```

Or use the helper:

```bash
docker/ubuntu24-build/build.sh
```

Build-time knobs:

| Option | Default | Notes |
|---|---|---|
| `--base-image` | `ubuntu:24.04` | Use a registry mirror for mainland China, e.g. `docker.m.daocloud.io/library/ubuntu:24.04` |
| `--mirror` | `official` | `official`, `tuna`, `ustc`, `aliyun`, `huawei`; rewrites Ubuntu archive/security URLs |
| `--tag` | `xtate:ubuntu24-full` | Image tag |
| `--no-cache` | off | Rebuild all layers |

Examples:

```bash
# Mainland China: mirror the base image and apt packages
docker/ubuntu24-build/build.sh \
  --base-image docker.m.daocloud.io/library/ubuntu:24.04 \
  --mirror tuna

# Direct docker build equivalent
docker build -f docker/ubuntu24-build/Dockerfile \
  --build-arg BASE_IMAGE=docker.m.daocloud.io/library/ubuntu:24.04 \
  --build-arg APT_MIRROR=aliyun \
  -t xtate:ubuntu24-full .
```

The build runs `--selftest` and refuses to produce the image unless the
capability probe reports `http3`, `quic_transport`, `zstd` and `raw_sockets` as
true, with 12 scan modules.

## Verify

```bash
docker run --rm xtate:ubuntu24-full --version
docker run --rm xtate:ubuntu24-full --list-capabilities
```

Expected capability highlights on this image:

```json
{"platform":"linux","raw_sockets":true,"http3":true,
 "quic_transport":true,"zstd":true,
 "modules":{"scan":12,"probe":60,"output":7,"generate":5}}
```

## GUI from the Docker host

The GUI is loopback-only by default. Publishing a container port requires the
explicit `XTATE_GUI_ALLOW_REMOTE=1` acknowledgement. The server still validates
the HTTP `Host` header against loopback, and the port must be published on host
loopback only.

```bash
docker run --rm \
  -p 127.0.0.1:8787:8787 \
  -e XTATE_GUI_ALLOW_REMOTE=1 \
  -e XTATE_GUI_PUBLIC_URL=http://127.0.0.1:8787/ \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$PWD/xtate-data:/data" \
  xtate:ubuntu24-full \
  --gui --gui-listen=0.0.0.0:8787
```

If the host publishes a different port (for example
`-p 127.0.0.1:8790:8787`), set `XTATE_GUI_PUBLIC_URL` to the host address so the
container log prints the right URL:

```bash
-p 127.0.0.1:8790:8787 \
-e XTATE_GUI_PUBLIC_URL=http://127.0.0.1:8790/
```

Then:

1. Read the printed URL and `GUI session token` from the container log
   (`docker logs <container>`).
2. Open `http://127.0.0.1:8787/` in the host browser.
3. Do not expose the published port on `0.0.0.0` or a LAN address. The GUI token
   is a per-run capability, not a substitute for network isolation.

The compose example does the same:

```bash
docker compose -f docker/ubuntu24-build/compose.yaml up
```

`/data` is the managed Xtate state directory (`XTATE_STATE_DIR=/data` in the
image). Mount it to keep results across container restarts.

### Docker Desktop notes

On Linux, `--network host` is the simplest alternative: the GUI binds
`127.0.0.1` in the host namespace. Docker Desktop for Windows/macOS does not
provide true host networking; use the published-loopback form above.

## Raw scans inside the container

Raw sockets need the kernel capabilities:

```bash
docker run --rm -it \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  xtate:ubuntu24-full \
  --scan-module=tcp-syn --target-ip=127.0.0.1 -p 80 --rate=10 --wait=1
```

For `zbanner`, `tcp-state`, `tls-state`, HTTP/2/3 or any state probe on Linux,
install the firewall rules for the duration of the scan. The image includes
`/usr/local/share/xtate/firewall`:

```bash
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN \
  xtate:ubuntu24-full bash -lc \
  '/usr/local/share/xtate/firewall/add_rules.sh; xtate --scan-module=zbanner --target-ip=127.0.0.1 -p 80 --rate=10 --wait=1'
```

Never run the firewall script as a permanent host change.

For link-layer scans on a Linux host, add `--network host` so the container
sees the host interfaces; otherwise Docker's NAT namespace cannot reach the
host LAN at layer 2. Docker Desktop on Windows/macOS does not support this mode;
use the published-port GUI workflow and scan from the container's routed
network instead.

## MCP inside the container

MCP is a stdio protocol; there is no TCP listener to connect to. The agent host
starts the container with `-i` and speaks JSON-RPC over the attached stdin/stdout.
The image starts a private control plane when `--mcp` has no
`--control-connect`:

```bash
docker run --rm -i --name xtate-mcp \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$PWD/xtate-data:/data" \
  xtate:ubuntu24-full --mcp
```

An MCP client configuration on the host therefore uses `docker` as the command:

```json
{
  "command": "docker",
  "args": ["run", "--rm", "-i", "--cap-add=NET_RAW",
           "--cap-add=NET_ADMIN", "-v",
           "/absolute/xtate-data:/data", "xtate:ubuntu24-full", "--mcp"]
}
```

Send `initialize` and then normal MCP JSON-RPC messages; for example, pipe a
single request into the container:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"host","version":"1"}}}' \
  | docker run --rm -i xtate:ubuntu24-full --mcp
```

The server prints the response on stdout; logs go to stderr. Do not add `-t`
when an agent is driving stdio.

### Shared control plane for MCP and GUI

To run one scanner container and attach both clients, start a named container
with a control-plane socket in the mounted state directory and with the GUI port
published at container start:

```bash
docker run -d --name xtate-core \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e XTATE_CONTROL_TOKEN=change-me \
  -e XTATE_GUI_ALLOW_REMOTE=1 \
  -e XTATE_GUI_PUBLIC_URL=http://127.0.0.1:8787/ \
  -p 127.0.0.1:8787:8787 \
  -v "$PWD/xtate-data:/data" \
  xtate:ubuntu24-full --control-plane=/data/control.sock
```

Attach MCP over stdio from the host:

```bash
docker exec -i xtate-core xtate --mcp --control-connect=/data/control.sock
```

Attach the GUI in the same container; the published port already exists. Docker
does not copy `docker exec` output into `docker logs`, so write the GUI log to
the mounted state directory:

```bash
docker exec -d xtate-core sh -lc \
  'xtate --gui --gui-listen=0.0.0.0:8787 --gui-no-open \
   --control-connect=/data/control.sock > /data/gui.log 2>&1'
docker exec xtate-core cat /data/gui.log
```

Read the `GUI http://...?...token=...` line from `/data/gui.log`, then open the
`127.0.0.1:8787` URL on the host with that query token. `XTATE_CONTROL_TOKEN`
is inherited by `docker exec`, so MCP and GUI authenticate to the same control
plane. Jobs, results and logs stay under `/data`.

## Known limitations

- `/api/open` starts a host application; inside the container it cannot open a
  file on the Docker host. Use the mounted `/data` path or the Results page.
- The optional dependency versions are Ubuntu 24.04's packages. A feature that
  requires a newer ngtcp2 API must be built in a custom image.
- GUI port publishing is deliberately limited to host loopback. See
  [GUI](gui.md) for the token/Host security model.
