# 08 · 架构与安全

[English](../../manual/08-architecture-and-security.md) · **中文**

本章描述运行中的 Xtate 如何组装，以及安全边界在哪里。在改动扫描器部署、把控制台暴露给另一个人，或把扫描控制权交给自动化客户端之前，这是你需要的地图。

两个想法组织了其余一切：

1. **一条流水线，由模块结构体实现。** 目标变成报文，报文变成回复，回复变成记录。每个阶段都是可插拔的模块类型；运行时什么都不加载。
2. **一个特权本地守护进程，加一层薄本地客户端。** 扫描引擎、job 管理器与控制面运行在一个进程里。GUI、TUI 和 MCP 是该进程的客户端，不是替代的扫描器。

## 流水线

扫描单向流动：

1. **生成**产生下一个目标 —— 目标/源 IP、端口与协议的元组，由目标集展平并打乱。
2. **扫描**为该目标构建报文并交给原始套接字层。
3. **探测**贡献应用层载荷并解释响应。
4. **输出**把每条结果格式化为 `OutItem` 并写到你要求的地方。

四类模块注册为 NULL 结尾的 C 数组中的静态结构体。缺少可选库的构建把对应模块编译掉，而不是运行时失败；这就是模块可能从 `--list-*` 缺席而二进制仍能启动的原因。没有插件 ABI，也没有动态发现。

| 类型 | 拥有 | 调用方 |
|:---|:---|:---|
| 生成 | 目标序列与排列状态 | tx 线程 |
| 扫描 | 报文构建与扫描级状态机 | tx（`transmit`）、rx（`validate`）、handle（`handle`、`poll`） |
| 探测 | 载荷字节、响应解析、可选的每连接会话 | tx 或 handle（`make_payload`）、rx（`get_payload_length`）、handle（`handle_response`、状态回调） |
| 输出 | 结果格式化与投递 | handle 线程，由一把锁串行化 |

扫描模块最多三次看到每个回复：在 `validate` 中（这个报文是我的吗，该去重吗）、在 `handle` 中（运行状态机、发出结果）、在 `poll` 中（每轮服务超时）。探测要么无状态（载荷进、字节出），要么有状态（带 `conn_init`/`make_hello`/`parse_response`/`conn_close` 的会话，始终在拥有该连接的处理线程上调用）。

## 线程与所有权

一次运行中的扫描使用 **N + M + 3** 个线程：一个 main、N 个发送、一个接收、一个分发和 M 个处理。默认值（`--tx-thread-count 1`、`--rx-handler-count 1`）给出五个线程。

| 线程 | 数量 | 职责 |
|:---|:---:|:---|
| main | 1 | 控制面：解析配置、初始化模块、轮询状态、处理信号、排空并关闭。不在报文路径上。 |
| tx | N | 取目标、构建报文、发送，冲刷处理线程排队的后续报文 |
| rx | 1 | 接收、预处理并校验每个回复；可选 pcap；可选去重；分发 |
| dispatch | 1 | 对源 IP 做哈希，把报文入队到 M 个处理队列之一 |
| handle | M | 运行扫描/探测状态机，格式化结果，排队后续报文 |

拆分跟随工作负载：发送侧受速率整形且受报文构建的 CPU 限制，接收侧受 I/O 限制且不能被每连接工作拖慢，处理线程则是昂贵的每目标逻辑所在之处。有状态扫描需要更多 CPU 时，处理线程就是要扩展的池。

**分发亲和性。** 分发器计算 `hash(src_ip) & (M - 1)` 并入队到 `handle_q[0..M-1]`。由于哈希只用源 IP，来自给定主机的每个报文都按到达顺序落到同一个处理线程。这正是无锁有状态扫描成为可能的原因：一个处理线程独占拥有它的连接，因此一个 TCB 永远只有一个写者。`M` 必须是 2 的幂且不超过 256；更大的值在启动时被拒绝，因为哈希只有 8 位宽。

**每处理线程的连接表。** `tcp-state` 这类有状态扫描为每个处理线程分配一张用户态 TCP 连接表，而不是一张全局表。亲和性规则意味着快路径不需要互斥锁。代价是连接状态绑定到线程：调整 `M` 会改变连接的分布。

**NetStack 队列。** 处理线程不直接发送。后续报文（ACK、RST、下一个探测）写入共享环 `transmit_queue`，tx 线程在循环顶部先冲刷该环，再生成新目标。一组匹配的固定大小 2048 字节报文缓冲区也以同样方式共享。这就是让无状态接收路径驱动真实 TCP 会话的机制：接收端保持纯粹，有状态决策表现为排队待发的报文。分发环和处理线程环在启动时确定大小（默认 16384 个槽，2 的幂）。环满时生产者睡眠并重试 —— 是背压而不是静默丢失。

CPU 亲和性按固定顺序分配 —— 先 tx 线程，再 rx，最后处理线程 —— 用 `--no-cpu-bind` 禁用。

## 报文构建、目标与结果

报文不是每目标从零构建。启动时模板层预生成一小批模板（SYN、带数据的通用 TCP、RST，以及 UDP/ICMP/ARP/NDP/SCTP 对应物）。每目标发送时把地址、端口、序列号和 IP ID 补进副本，然后重算传输层和 IP 校验和。模板假设解释了那些调参旋钮：SYN 模板通告 MSS 1460 和 64240 字节窗口，非 SYN 的 TCP 模板不带选项、窗口 1024 字节，RST 模板通告零窗口。

目标集被展平成一个 `ip × port` 的索引空间，并以置换顺序遍历。默认生成器是 **BlackRock**，一种类似 DES 的无状态置换：给定种子和索引就能算出打乱后的索引，无需存储列表，因此在互联网规模下内存保持平坦。空间限制为 63 位，超过十亿个地址且没有显式 `--exclude` 的请求会被拒绝，以防意外扫描整个互联网。`--shard` 和 `--resume-index` 在同一置换之上把一次逻辑扫描拆到多个进程和重启点。

源地址和端口可以在各自范围内随机化。源端口范围很重要：ZBanner 和 HLTCP 把探测 slot 编码进源端口（`first + index`），回复正是这样与产生它的探测匹配。因此 `--source-port` 至少要与探测的 slot 数量一样宽，否则 slot 回复会被过滤掉。

每条结果都是一个 `OutItem`：目标元组、等级（`info`、`failure` 或 `success`）、分类与原因字符串，外加三条带类型的键值链 —— 扫描字段、探测字段、输出字段。输出模块只选一次，并接收来自任意产生它的处理线程的结果；一把互斥锁串行化该调用。因此慢的目的地（例如同步数据库插入）会拖慢处理 —— 这是刻意的简单性取舍，也是吞吐敏感的运行应优先选择本地格式的原因。

## 两个引擎，一条流水线

| | ZBanner | HLTCP |
|:---|:---|:---|
| 状态 | 每目标无 | SYN-ACK 之后有 TCB |
| 发送 | SYN，然后一个携带探测的 ACK | 完整的 TCP 会话 |
| 返回 | 开放/关闭与首批 banner | TLS 握手、证书、TLS 内的 HTTP |
| 模块 | `-scan zbanner` | `-scan tcp-state` |

两者依赖同样的不变量：后续报文经 NetStack 队列而不是内联发送，并且必须阻止主机内核复位它不认识的连接。见第 05 章以及深入文档 [ZBanner](../zbanner.md) 和 [HLTCP](../hltcp.md)。

该设计刻意放弃了一些东西：单个接收线程（限制接收侧吞吐）、没有输出队列、线程亲和的连接状态、编译期静态模块。每一项都在另一栏换来简单性；它们不是 bug。

## 守护进程与控制面

同一个可执行文件既可以作为扫描命令运行，也可以作为承载本地控制面的守护进程运行。控制面是 MCP、TUI 和 GUI 共享的**本地 JSON-lines 契约**：

- 每行一个 JSON 对象；每个请求一个响应。
- 服务器从不执行 shell。
- 它**不是网络监听器**。

传输在 Linux 上是 Unix 域套接字，在 Windows 上是命名管道（例如 `\\.\pipe\xtate-control`）。没有隐式端点：服务器精确使用 `--control-plane` 路径，客户端精确使用 `--control-connect`：

```bash
# terminal 1: daemon
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --control-plane=/tmp/xtate-ctl.sock

# terminal 2: one-shot client
xtate --control-connect=/tmp/xtate-ctl.sock \
      --control-request='{"id":1,"method":"ping"}'
```

控制方法刻意很少：

| 方法 | 用途 |
|:---|:---|
| `ping` | 存活检查（`{"pong":true}`） |
| `job.start` | 校验并启动扫描 job；返回 `job_id` |
| `job.list` | 分页 job 列表（offset/limit，limit 默认 100，最大 1000） |
| `job.status` | 状态、计数器、退出码、结果/日志路径、stderr 尾部 |
| `job.result_manifest` | 结果路径、manifest 路径、大小、完整性 |
| `job.results` | 已完成 job 的 manifest 元数据（目前保留/忽略分页） |
| `job.cancel` | 请求取消；返回是否已取消 |

job 经过 `queued`、`running`、`completed`、`failed`、`cancelled`、`timed_out` 或 `stalled`。错误使用 `schemas/error-codes.json` 中的稳定码，形状为
`{"id":1,"error":{"code":"JOB_NOT_FOUND","message":"...","retryable":false}}`。
`job.start` 还接受顶层的 `result_path`、`timeout_sec`、`chunk_size`、`compression`、`index`、`quota_bytes` 和 `interface`；扫描请求异步校验，无效请求通过 `job.status` 可见。

**数据面是文件系统**，不是控制通道。控制响应有界，从不携带结果字节；job 拥有自己的结果路径，客户端读取 manifest 和分片文件。完成的结果可用 `--result-chunk-size`/`--result-index` 拆成 `<result>.<id>.ndjson` 分片加 `<result>.manifest.json`（和可选索引）。压缩是可选 zstd（默认无）；没有 zstd 的构建回退到未压缩分片，而不是让 job 失败。`quota_bytes` 在完成后检查并以警告报告 —— 它不是扫描中途的硬限制。

运营后果：一个控制面线程、串行化的管理器调用；守护进程拥有 worker；守护进程重启会终止它的 job（没有持久化或恢复）；客户端轮询 `job.status`/`job.list`，因为没有服务器推送事件流。

## GUI：回环控制台

GUI 是由同一进程提供的本地扫描控制台。浏览器页面、其资源和 API 都是本地的：服务器只绑定回环（`--gui-listen` 必须是 `127.0.0.1:PORT`），从二进制提供页面，并暴露一个小型 JSON API —— `/api/info`、`/api/system`、`/api/interfaces`、`/api/modules`、`/api/preflight`、`/api/results`，以及用于 job 白名单的 `/api/rpc`。GUI 从不执行外部命令，也从不把任意方法转发到控制面。

回环 API 的安全契约才是重点：

- **回环绑定与 Host 校验** —— 监听器仅回环，每个请求必须带回环 `Host`（`127.0.0.1:PORT` 或 `localhost:PORT`）；其他一律拒绝，从而阻断 DNS-rebinding 攻击。
- **每次运行一个 token** —— `/api/*` 请求必须带 `X-Xtate-GUI-Token`，这是启动时生成并注入所服务页面的随机 token。没有它请求得到 `403 GUI_TOKEN_REQUIRED`，且 token 值从不显示在 Settings 中；只显示其存在/缺失。
- **浏览器无法提供控制面 token。** 含 `token` 成员的 `/api/rpc` 正文会被 `400 TOKEN_NOT_ALLOWED` 拒绝；转发到控制面时，GUI 注入服务器进程自己的 `XTATE_CONTROL_TOKEN`。因此页面 JavaScript 无法选择或泄露任意控制 token。
- **有界正文与响应** —— 请求正文上限 64 KiB（超出为 `413`），转发的控制响应上限相同。
- **没有任意文件读取** —— 浏览器不能要求服务器读文件；结果访问走 job 方法及其 manifest。
- **显式授权** —— `job.start` 在服务器端要求 `params.authorized=true`；页面里的复选框是 UI 便利，不是强制点。
- **方法白名单** —— 只接受文档化的 job/读取方法。

同样的设计规则适用于渲染：扫描记录、网卡名和路由字符串在显示前转义，因为它们包含来自不可信对端的数据。

## MCP：有类型的自动化客户端

MCP server 是一个 stdio 进程（用 `--mcp` 启动），对本地 agent 讲 Model Context Protocol，并作为控制面的有类型客户端加只读发现工具。它从不内嵌扫描结果、从不派生 shell、从不接受命令字符串；发现功能用固定 argv 运行同一可执行文件。

它的工具面刻意小而结构化：`capabilities`、`iface.list`、`list_modules`、`describe_probe`、`explain_target`、`check`、`preflight`、`validate_config`、`start_scan`、`job_list`、`job_status`、`job_result_manifest` 和 `job_cancel` —— 构建/网卡/模块发现、路由与防火墙解释、无发包预检、配置校验、job 启动/列出/状态/取消以及结果 manifest 读取。扫描数据以文件系统元数据返回，不内联：客户端先读 manifest，再读分片。

MCP 加了自己的边界：

- **`start_scan` 要求 `authorized: true`** —— agent 必须声明其目标已获授权。
- **内联目标有上限**（20000 条），速率有上限（10000 pps）；端口会被校验；`result_path` 在 job 启动前会探测可写性。
- **大输入使用 `include_file`**，跨越多个路由的目标集会拒绝，而不是静默拆分。
- **资源在白名单内** —— 三个固定 URI（`docs/overview`、`docs/firewall`、`schemas/scan-request`），依次相对固定文件名、`$XTATE_MCP_DOCS_DIR`、可执行文件目录，最后是工作目录解析。绝对路径、带盘符路径和 `..` 在触碰文件系统之前就被拒绝。
- **没有任意文件系统读取**（从 URI 或工具参数）；缺失资源返回 `-32002 resource not found`，不扫描磁盘。
- **参数与缓冲区限制** —— 超大的内联参数被拒绝，MCP 参数缓冲区为 8 KiB。
- **审计轨迹** —— `start_scan` 向 MCP 进程工作目录下的 `xtate-mcp-audit.log` 追加一条记录（速率加截断有界的配置）。该路径是相对的，因此目录必须可信；它不是防篡改的审计存储。

Agent Skill 是文档/剧本，不是强制机制。它告诉 agent 如何规划一次授权扫描；真正阻止不安全请求的是 MCP server 与 job 管理器中的校验。

## 安全模型与边界

部署模型是**单个特权本地扫描器**加本地客户端。这带来一份很短的边界清单，以及一份很短的明确排除项清单。

### 什么隔离了守护进程

- **没有网络监听器。** 控制面 = Unix 套接字/命名管道；GUI = 回环 HTTP；MCP = stdio。这些都不是远程服务，也都不应通过 TCP 代理暴露并声称受支持。
- **本地认证。** 设置 `XTATE_CONTROL_TOKEN` 时，每个控制请求必须带同样的 token，缺失或错误返回 `UNAUTHORIZED`。未设置时，服务器接受每个本地客户端 —— 在单用户主机上可接受，在其他本地用户或进程不可信的地方不可接受。
- **GUI token + Host 校验**阻断对回环 HTTP API 的跨站与 DNS-rebinding 访问；token 每次运行一个并注入所服务页面。
- **启动与 job 启动时的失败关闭校验**：模块/探测类型不匹配、不支持的链路类型、无效目标/端口、不可写的结果路径、缺失授权和多路由的内联目标集都会被拒绝，而不是"尽力而为"地执行。

### 特权带来什么，代价是什么

原始套接字在 Linux 上需要 root，在 Windows 上需要管理员加 Npcap。扫描需要该特权来构建报文并完成握手；同样的特权意味着防火墙规则和网卡选择会影响整台主机。

有状态扫描使用的防火墙规则是**主机全局的**：扫描期间它们丢弃所有出向 TCP RST（IPv4 和 IPv6）与 ICMP port-unreachable。有状态扫描前安装，结束后立即移除，绝不要在共享或长期运行的主机上留着它们 —— 它们会改变无关连接的行为。Windows 上没有等价脚本：基于握手的 banner/state 扫描依赖 Windows 协议栈不复位这些连接，原始扫描还额外需要 Npcap。

### 非目标

Xtate 不内嵌 LLM、云账号、遥测或托管扫描服务，GUI/MCP 也不执行 shell。它**不是**加固的多租户服务：如果主机与不可信用户共享，本地控制面和 token 模型是你的责任，审计日志是本地文件而不是安全控制。

## 部署形态

正常部署是：

```text
                +--------------------------------------+
                | scanner host (root/Administrator)    |
                |                                      |
  GUI browser --loopback HTTP-->  xtate daemon        |
  MCP agent  --stdio-------->     + control plane      |
  TUI/CLI    --socket/pipe-->     + job manager        |
                |                 + scan engine        |
                |                                      |
                |   results <-- filesystem manifest    |
                +--------------------------------------+
```

客户端不扫描；它们提交已校验的请求并读取结果。这就是 GUI 里启动的扫描能从 MCP 列出或取消的原因，也是 job 管理器（而不是客户端）拥有结果文件的原因。

另见：

- [03 · CLI 与 job](./03-cli-and-jobs.md) 了解命令与 job 工作流
- [控制面](../control-plane.md)、[job 模型](../job-model.md)、
  [JSON 契约](../json-contracts.md)、[错误码](../error-codes.md)
- [MCP server](../mcp-server.md)、[Agent Skill](../agent-skill.md)、
  [GUI 设计说明](../../gui-3.0-design.md)
- [防火墙设置](../firewall.md)与[已知限制](../known-limitations.md)
- [09 · 故障排查](./09-troubleshooting.md)
