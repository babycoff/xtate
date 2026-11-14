# 03 · CLI 与 job

[English](../../manual/03-cli-and-jobs.md) · **中文**

CLI 是参考接口：GUI 和 MCP 都驱动同一个扫描引擎和同一个 job 管理器。本章介绍扫描命令、输出、本地控制面和托管 job。

下面的示例中，`xtate` 在 Linux/macOS 上指 `./bin/xtate`，在 Windows 上指 `.\bin\xtate.exe`。原始套接字扫描需要 `sudo` 或提权的 shell。

## 命令行基础

一条扫描命令由目标集合、端口集合、扫描引擎、可选探测和速率组成：

```bash
xtate -ip <targets> -p <ports> -scan <engine> [-probe <probe>] -rate <pps>
```

| 选项 | 含义 |
|:---|:---|
| `-ip`, `--target-ip` | 目标：单个 IP、CIDR、显式区间或逗号列表 |
| `-p`, `--port` | 端口或区间；`U:` 前缀表示 UDP，`S:` 表示 SCTP，`O:` 表示非端口 slot |
| `-scan`, `--scan-module` | 扫描引擎，例如 `tcp-syn`、`zbanner`、`udp`、`tcp-state` |
| `-probe`, `--probe-module` | 给需要探测的引擎用的探测，例如 `http`、`dns`、`tls-state` |
| `-rate` | 各发送线程合计的包/秒 |
| `-if`, `--adapter` | 按索引或唯一描述固定网卡 |
| `-show`, `--show-output` | 额外结果等级：`failed`、`info`、`all` |
| `-scan-arg`, `-probe-arg` | 带引号的模块专用参数 |
| `-output-module`, `-o` | 输出模块与输出文件 |
| `--wait` | 发送结束后继续接收的秒数（默认 10） |
| `--no-status` | 关闭 stderr 上的实时状态栏 |

内置帮助：

```bash
xtate --usage                 # one-screen synopsis with examples
xtate --help                  # every global parameter
xtate --intro                 # workflow overview
xtate --list-scan             # scan engines
xtate --list-probe            # probes and their types
xtate --list-out              # output modules
xtate --list-gen              # target generators
xtate --list-modules-json     # machine-readable catalog
xtate --help-scan zbanner     # per-module parameters
xtate --help-probe http
```

模块名、参数名和结果值保持英文。面向人的帮助可以用 `--lang zh` 或 `XTATE_LANG=zh` 切换成中文。

## 目标与端口

目标接受 `192.168.1.10`、`10.0.0.0/8`、`10.0.0.1-10.0.0.100`、`2001:db8::/64` 以及逗号列表。`--exclude` 从集合中移除区间；排除优先于包含。目标文件与生成器见[目标与端口](../targets-and-ports.md)。

端口接受 `80`、`20-25`、`80,20-25`、`U:161`、`U:1024-1100` 和 `S:36412`。对于端口型引擎（`tcp-syn`、`zbanner`、`tcp-state`、`udp`、`sctp-init`、`yarrp-udp`），始终要传 `-p`：不传时 Xtate 会警告，并塞入一个假的 `o:0` 端点，因此不会发送任何报文。

## 扫描与探测配对

| 引擎 | 探测 | 典型用途 |
|:---|:---|:---|
| `tcp-syn` | 无 | 快速无状态端口发现 |
| `zbanner` | TCP 探测（`http`、`echo`、`ssh`、`ftp` 等） | banner 与协议问候 |
| `tcp-state` | state 探测（`tls-state`、`http-state`、`smtp-state` 等） | 完成握手后再探测 |
| `udp` | UDP 探测（`dns`、`snmp`、`ntp`、`echo` 等） | 无状态 UDP 请求/应答 |
| `icmp-echo` | 无 | 主机发现，无端口 |
| `arp-req`, `ndp-ns` | 无 | 本地 LAN 发现（ARP 用 `-lan`） |
| `yarrp-echo`, `yarrp-udp` | 无 / UDP | TTL 受限测量 |
| `quic-state` | `http3-state` | 可选，仅 Linux + ngtcp2 |

选择与引擎类型不匹配的探测是校验错误；GUI 预检和 job worker 都会拒绝。

## 示例扫描

### 无状态 SYN 扫描

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn -rate 100
```

结果流向 stdout，每个回包一行：

```text
[+] host: 192.168.1.10 port: 80 in tcp is "open" because "syn-ack"
```

默认只显示 `success` 结果；关闭的端口是 `failed`：

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn \
  -rate 100 -show failed
```

状态栏画在 stderr 上。因此把 stdout 重定向到文件时文件保持干净，而 `--no-status` 会彻底去掉状态栏。

### UDP 探测

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p U:53 -scan udp -probe dns \
  -rate 500 -show info
```

### 无端口的主机发现

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -scan icmp-echo -rate 500
```

### Banner 抓取与有状态探测（Linux）

有状态引擎需要在扫描期间抑制出向 RST。这些规则是主机全局的；扫描结束后立即移除：

```bash
./firewall/add_rules.sh
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe http \
  -scan-arg "-banner" -rate 100 -show info
sudo ./bin/xtate -ip 192.168.1.0/24 -p 443 -scan tcp-state -probe tls-state \
  -rate 200 -show info
./firewall/rm_rules.sh
```

`-scan-arg` 和 `-probe-arg` 以一个带引号的字符串接收模块自己的选项，例如 `-scan-arg "-banner -ttl"`。逐模块帮助（`--help-scan`、`--help-probe`）会列出它们。Windows 上没有随附的防火墙脚本；运行有状态扫描前，请先阅读[快速上手](../getting-started.md)中的 Windows 说明。

### 网卡与路由

```bash
./bin/xtate --list-if
./bin/xtate --explain-target 192.168.1.0/24
./bin/xtate --check --explain-target 192.168.1.0/24
sudo ./bin/xtate -ip 192.168.1.0/24 -p 443 -scan tcp-syn -if 3
```

`--explain-target` 是只读的，按网卡/源地址/网关对目标分组，并在目标集合跨越多条路由时告警。`--check` 额外做预检，失败时以非零码退出。如果省略 `-if` 而路由有歧义，Xtate 会失败关闭，而不是猜测。

## 输出

默认结果是 stdout 上的文本行，实时状态栏在 stderr 上。要写结构化输出，选择一个输出模块：

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan tcp-syn \
  -output-module ndjson -o results.ndjson
```

`-o` 是所选模块的输出文件；`--output-screen` 让模块写文件的同时也把结果打印出来。`bson`、`csv`、`list` 和 `mongodb` 是其他输出模块；它们的选项来自 `--help-out <module>`。后处理（JARM 聚合、事件聚合、BSON 解析）见[输出](../output.md)和[聚合](../aggregation.md)。

停止：`Ctrl-C` 停止发送并在 `--wait` 秒内继续收集回包（默认 10）。再按一次 `Ctrl-C` 立即中止。正常扫描的退出状态为零；启动/校验失败、`--selftest` 失败和 `--check` 预检失败时为非零。

## 托管 job

长时间扫描应当做成 job：由本地守护进程拥有的子进程，带有超时、取消和结果文件。同一个 job 管理器支撑 MCP 和 GUI。

### 运行一个 job 并等待

```bash
./bin/xtate --job-run=request.json --job-result=out.ndjson --job-timeout=30
```

`request.json` 是一个扫描请求：

```json
{
  "scan": "tcp-syn",
  "targets": ["192.168.1.0/24"],
  "ports": [80, 443],
  "rate": 100,
  "timeout_sec": 300
}
```

worker 以 `--show all` 运行，把 NDJSON 写入结果文件。命令等待完成，并打印一行 JSON：

```json
{"job":{"id":"job-1","state":"completed","exit_code":0,"result":"out.ndjson"}}
```

只有 `--job-run` 的 worker 会写心跳文件（`<result>.heartbeat`）。普通 CLI 扫描不会创建它，行为也不变。`--job-heartbeat-timeout`（默认 30 秒）会让心跳停止更新的 job 失败；`--job-stall-timeout` 会让心跳仍在但输出没有进展的 job 失败。

### 本地控制面

守护进程在一个本地端点上每行收发一个 JSON 对象：Linux 上是 Unix socket，Windows 上是命名管道。它从不监听 TCP，也从不执行 shell。

启动服务器：

```bash
xtate --control-plane=/tmp/xtate-ctl.sock
```

从另一个进程（或另一个终端）发送请求：

```bash
xtate --control-connect=/tmp/xtate-ctl.sock \
  --control-request='{"id":1,"method":"ping"}'
```

如果服务器设置了 `XTATE_CONTROL_TOKEN`，每个请求都必须带同样的 `"token"` 字段；缺失或错误会返回 `UNAUTHORIZED`。没有 token 时，任何能到达该端点的本地进程都会被接受，因此在共享机器上要设置一个。

方法：

| 方法 | 参数 | 结果 |
|:---|:---|:---|
| `ping` | 无 | `{"pong":true}` |
| `job.start` | `params` 扫描请求，或 `request_path` | `{"job_id":"…"}` |
| `job.list` | `offset`、`limit`（默认 100，最大 1000） | `jobs`、`total`、`next_offset`、`truncated` |
| `job.status` | `job_id` | 状态、计数器、路径、stderr 尾部 |
| `job.result_manifest` | `job_id` | 结果路径、manifest 路径、字节数、完整性 |
| `job.results` | `job_id` | manifest 元数据；`offset`/`limit` 保留但被忽略 |
| `job.cancel` | `job_id` | `cancelled` 布尔值 |

启动一个 job：

```bash
xtate --control-connect=/tmp/xtate-ctl.sock --control-request='{
  "id":2,"method":"job.start",
  "params":{"scan":"tcp-syn","targets":["192.168.1.0/24"],
            "ports":[80,443],"rate":100,"timeout_sec":300}
}'
```

`job.start` 还接受顶层的 `result_path`、`timeout_sec`、`chunk_size`、`compression`、`index`、`quota_bytes` 和 `interface`。请求由 worker 校验，因此无效请求会异步失败，并出现在 `job.status` 中。

轮询与取消：

```bash
xtate --control-connect=/tmp/xtate-ctl.sock \
  --control-request='{"id":3,"method":"job.status","job_id":"job-1"}'
xtate --control-connect=/tmp/xtate-ctl.sock \
  --control-request='{"id":4,"method":"job.cancel","job_id":"job-1"}'
```

状态有 `queued`、`running`、`completed`、`failed`、`cancelled`、`timed_out` 和 `stalled`。没有 `job.events` 方法，也没有服务器推送：客户端轮询。没有持久化；守护进程重启会终止它的 job。

### 结果文件与分片

job 拥有自己的结果路径；控制响应从不携带结果字节。对于大结果，可在 job 启动请求中要求分片、可选压缩的输出：

```json
{
  "id": 2,
  "method": "job.start",
  "params": {"scan": "tcp-syn", "targets": ["192.168.1.0/24"],
             "ports": [80, 443], "rate": 100, "timeout_sec": 300},
  "chunk_size": 67108864,
  "index": true,
  "compression": "none"
}
```

完成的结果会变成 `<result>.<id>.ndjson` 分片，加上 `<result>.manifest.json` 和可选索引；`job.result_manifest` 返回 manifest 路径。压缩默认是 `none`；当构建包含 zstd 时 `--result-compress=zstd` 生效（否则回退到不压缩）。`--result-quota` 在完成后检查，并以警告形式报告；它不会停止正在运行的扫描。已完成 job 的保留与清理由 job 管理器执行。

### 接入其他客户端

任何客户端都可以接入运行中的守护进程。控制台用：

```bash
xtate --control-connect=/tmp/xtate-ctl.sock --gui
```

MCP 是自动化接口，把同一套 job 生命周期暴露为工具；见 [MCP server](../mcp-server.md)和 [Agent Skill](../agent-skill.md)。由于所有客户端共享一个守护进程，GUI 启动的 job 可以被控制面请求取消，也可以被 MCP 列出。

## 故障排查

| 症状 | 可能原因与修复 |
|:---|:---|
| `no ports` 警告且没有报文 | 端口型引擎没传 `-p`。传入端口，或改用 `icmp-echo` |
| `open` 但没有 banner 或 TLS 证据 | 内核 RST；为有状态扫描安装 Linux 防火墙规则 |
| 网卡歧义错误 | 多条默认路由。用 `--list-if` / `--explain-target`，再用 `-if` |
| `JOB_NOT_FOUND` | job id 错误，或守护进程重启过（job 不持久化） |
| `JOB_LIMIT_REACHED` | 管理器的 job 上限已满；等待 job 完成或清理已完成的 |
| `SCAN_TIMEOUT` / `SCAN_STALLED` | job 超过总超时，或停止取得进展 |
| 控制面 `UNAUTHORIZED` | 客户端与服务器设置相同的 `XTATE_CONTROL_TOKEN`，或把它的值作为 `"token"` 加入 |
| `AUTHORIZATION_REQUIRED` | 从 MCP 或 GUI 发起的 `job.start` 需要 `authorized: true` |

参数无效、预检失败（`--check`）、`--selftest` 失败和 job 启动被拒绝时，退出码为非零。确切的码不属于契约；请改看 stderr 和 JSON 错误对象。

## 相关文档

- [02 · GUI 控制台](./02-gui-console.md)
- [控制面](../control-plane.md)与 [job 模型](../job-model.md)
- [输出](../output.md)、[聚合](../aggregation.md)、
  [JSON 契约](../json-contracts.md)、[错误码](../error-codes.md)
- [扫描模式](../scanning-modes.md)、[模块](../modules.md)、
  [目标与端口](../targets-and-ports.md)
- [MCP server](../mcp-server.md)、[Agent Skill](../agent-skill.md)
- [故障排查](../troubleshooting.md)
