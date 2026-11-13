# Ubuntu 24.04 全功能 Docker 构建

**中文** · [English](../docker-build.md)

仓库提供可复现的 Ubuntu 24.04 镜像定义，用发行版中可用的全部可选依赖构建
Xtate：

- OpenSSL（TLS），
- PCRE2（banner 匹配），
- libxml2（XML 探测），
- libbson / libmongoc（MongoDB 输出），
- ngtcp2 + GnuTLS（HTTP/3 与 QUIC 传输），
- zstd（结果分块压缩），
- libpcap 运行时（抓包与网卡检查），
- Lua 5.3 运行时（Lua 探测）。

该镜像是 3.0 的参考 Linux 构建环境。它比仅运行镜像更大，因为它同时包含构建
工具和可直接运行的二进制。

## 构建

在仓库根目录执行：

```bash
docker build -f docker/ubuntu24-build/Dockerfile \
  -t xtate:ubuntu24-full .
```

或使用脚本：

```bash
docker/ubuntu24-build/build.sh
```

构建参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--base-image` | `ubuntu:24.04` | 中国大陆可换用镜像仓库，如 `docker.m.daocloud.io/library/ubuntu:24.04` |
| `--mirror` | `official` | `official`、`tuna`、`ustc`、`aliyun`、`huawei`，会改写 Ubuntu archive/security 地址 |
| `--tag` | `xtate:ubuntu24-full` | 镜像标签 |
| `--no-cache` | 关闭 | 重建全部层 |

示例：

```bash
# 中国大陆：基础镜像和 apt 都走镜像
docker/ubuntu24-build/build.sh \
  --base-image docker.m.daocloud.io/library/ubuntu:24.04 \
  --mirror tuna

# 等价的 docker build
docker build -f docker/ubuntu24-build/Dockerfile \
  --build-arg BASE_IMAGE=docker.m.daocloud.io/library/ubuntu:24.04 \
  --build-arg APT_MIRROR=aliyun \
  -t xtate:ubuntu24-full .
```

构建过程中会运行 `--selftest`；如果能力探测不是
`http3/quic_transport/zstd/raw_sockets` 全为 true 且 scan 模块为 12 个，镜像
构建会失败。

## 验证

```bash
docker run --rm xtate:ubuntu24-full --version
docker run --rm xtate:ubuntu24-full --list-capabilities
```

预期能力：

```json
{"platform":"linux","raw_sockets":true,"http3":true,
 "quic_transport":true,"zstd":true,
 "modules":{"scan":12,"probe":60,"output":7,"generate":5}}
```

## 从 Docker 宿主机访问 GUI

GUI 默认只监听 loopback。发布容器端口必须显式设置
`XTATE_GUI_ALLOW_REMOTE=1`；服务端仍会校验 HTTP `Host` 为 loopback，且端口
只应发布在宿主机 127.0.0.1 上。

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

如果宿主机映射到其他端口（例如 `-p 127.0.0.1:8790:8787`），把
`XTATE_GUI_PUBLIC_URL` 改成对应地址，日志会打印这个地址：

```bash
-p 127.0.0.1:8790:8787 \
-e XTATE_GUI_PUBLIC_URL=http://127.0.0.1:8790/
```

然后：

1. 从容器日志读取 URL 和 `GUI session token`（`docker logs <container>`）。
2. 在宿主机浏览器打开 `http://127.0.0.1:8787/`。
3. 不要把端口发布到 `0.0.0.0` 或局域网地址。GUI token 是单次运行的凭据，
   不能替代网络隔离。

Compose 示例等价：

```bash
docker compose -f docker/ubuntu24-build/compose.yaml up
```

`/data` 是镜像内的受管状态目录（`XTATE_STATE_DIR=/data`），挂载后可跨容器
保留结果。

### Docker Desktop 注意

Linux 上最简单的是 `--network host`：GUI 直接监听宿主网络命名空间的
`127.0.0.1`。Windows/macOS 的 Docker Desktop 不支持真正的 host 网络，请使用
上面的 loopback 端口发布方式。

## 容器内原始扫描

原始套接字需要内核能力：

```bash
docker run --rm -it \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  xtate:ubuntu24-full \
  --scan-module=tcp-syn --target-ip=127.0.0.1 -p 80 --rate=10 --wait=1
```

Linux 上的 `zbanner`、`tcp-state`、`tls-state`、HTTP/2/3 或任何 state 探针
需要扫描期间临时安装防火墙规则。镜像包含
`/usr/local/share/xtate/firewall`：

```bash
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN \
  xtate:ubuntu24-full bash -lc \
  '/usr/local/share/xtate/firewall/add_rules.sh; xtate --scan-module=zbanner --target-ip=127.0.0.1 -p 80 --rate=10 --wait=1'
```

不要把防火墙脚本作为永久主机改动。

## 容器内 MCP

Stdio MCP 可直接使用；省略 `--control-connect` 时镜像会启动私有控制面：

```bash
docker run --rm -i xtate:ubuntu24-full --mcp
```

Agent 宿主需要保持容器 stdin/stdout 连接；若宿主设置了
`XTATE_CONTROL_TOKEN`，容器也要传同一个值。镜像把 docs/schemas 放在
`/usr/local/share/xtate`，并设置 `XTATE_MCP_DOCS_DIR`。

## 已知限制

- `/api/open` 会启动宿主机应用；容器内无法打开 Docker 宿主机上的文件，请使用
  挂载的 `/data` 路径或 Results 页面。
- 可选依赖版本跟随 Ubuntu 24.04 软件包；需要更新 ngtcp2 API 时应自建镜像。
- GUI 端口发布只应绑定宿主机 loopback；安全模型见 [GUI](./gui.md)。
