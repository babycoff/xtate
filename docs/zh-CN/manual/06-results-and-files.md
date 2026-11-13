# 06 · 结果与文件

[English](../../manual/06-results-and-files.md) · **中文**

每次扫描都会产生结果记录，并可选地产生结果文件。本章介绍记录模型、输出格式、转义规则，以及托管 job 额外生成的文件（心跳、分片、manifest、索引）。最后说明控制台和 MCP 如何读取这些文件。

如果你还没选输出模块，默认是 stdout，每条结果一行。深入参考见[输出](../output.md)、[job 模型](../job-model.md)和[控制面](../control-plane.md)。

## 一条结果是什么

一条结果是一个 `OutItem`：目标对、等级、可选的分类与原因，以及三组带类型的键/值字段。

| 字段 | 含义 |
|:---|:---|
| `time` | 结果时间戳 |
| `level` | `success`、`failure` 或 `information` |
| `ip_proto`、`ip_them`、`ip_me` | 协议与两个地址 |
| `port_them`、`port_me` | 端口；无端口结果省略 |
| `classification` | 简短判定，例如 `open` 或 `closed` |
| `reason` | 简短解释，例如 `syn-ack` |
| `scan report` | 扫描引擎记录的字段（TTL、窗口、flag 等） |
| `probe report` | 探测解析出的字段（banner、证书等） |
| `output report` | 输出处理加入的字段（例如 ASN） |

`scan report`、`probe report` 和 `output report` 是扁平对象；值是字符串、数字、布尔或 null。为空时省略。

## 等级与过滤

默认流只显示 `success`。失败、关闭端口和信息性观察会被记录，但隐藏到你主动请求：

```bash
xtate -ip 203.0.113.10 -p 80,443 -scan tcp-syn -show failed
xtate -ip 203.0.113.10 -p 80,443 -scan tcp-syn -show info
xtate -ip 203.0.113.10 -p 80,443 -scan tcp-syn -show all
```

`--show-output`（短形式 `-show`）接受 `failed`、`info`、`success` 和 `all`，可重复。`--no-show-output` 再次移除某个等级：`-show all -no-show success` 留下失败和信息。

过滤发生在输出模块**之前**，因此文件或数据库只包含你要求的等级。文件意外为空通常是等级过滤设置错了，而不是扫描失败。

不同引擎分配等级的方式不同。`tcp-syn` 把开放报告为 success，关闭报告为 failure。`zbanner` 和 `tcp-state` 默认把开放端口报告为 information，它们的引擎提供开关（`--port-success`、`--port-failure`、`--ack-success`）来提升等级。过滤之前先看引擎的帮助页。

## stdout

没有输出模块时，Xtate 写文本行，并把状态栏留在 stderr：

```text
[+] host: 203.0.113.10 port: 443 in tcp is "open" because "syn-ack",  ttl: 64,  win: 64240
[x] host: 203.0.113.10 port: 80 in tcp is "closed" because "rst",  ttl: 64
[*] host: 203.0.113.10 port: 8443 in tcp is "open" because "syn-ack"
```

- `[+]` success，`[x]` failure，`[*]` information。
- 二进制值打印为 `(N bytes bin)`；BSON 和 MongoDB 保留完整字节。
- 无端口结果省略 `port:` 部分。
- `--no-ansi` 关闭颜色，`--no-status` 关闭状态栏，从而让 stdout 和 stderr 都便于机器读取。

## NDJSON

`ndjson` 是机器可读的流：每行一个 JSON 对象，UTF-8，以换行结尾，无尾逗号，无外层数组。

```bash
xtate -ip 203.0.113.10 -p 443 -scan tcp-syn -show all \
  -output-module ndjson -o results.ndjson
```

```json
{"time":"2026-11-13T09:00:00Z","level":"success","ip_proto":"tcp","ip_them":"203.0.113.10","port_them":443,"ip_me":"192.168.1.24","port_me":40001,"classification":"open","reason":"syn-ack","scan report":{"ttl":64,"win":64240}}
```

契约由 `schemas/result.schema.json` 定义：

- 必需键：`time`、`level`、`ip_proto`、`ip_them`、`ip_me`。
- `level` 只能是 `information`、`failure` 或 `success`。
- 端口存在时是 0 到 65535 的整数。
- 三个 report 对象只包含标量值。
- 不允许未知的顶层键。

`-o -` 为 `text`、`csv`、`ndjson` 和 `list` 选择 stdout。`bson` 没有 stdout 约定：`-o -` 会创建一个字面名为 `-` 的文件。

## 其他格式

| 模块 | 命令 | 输出 |
|:---|:---|:---|
| `text` | `-output-module text -o results.txt` | 文件中的 stdout 风格行 |
| `csv` | `-output-module csv -o results.csv` | 表头加每条结果一行 |
| `list` | `-output-module list -o results.txt` | `address port`，每行一个 |
| `bson` | `-output-module bson -o results.bson` | 二进制 BSON 文档 |
| `mongodb` | `-output-module mongodb -o mongodb://...` | 插入集合的文档 |
| `null` | `-output-module null` | 丢弃一切（基准测试） |

CSV 总是写这个表头，追加时也一样：

```text
time,level,ip_proto,ip_them,port_them,ip_me,port_me,classification,reason,scan report,probe report,output report
```

最后三列是加了引号的类 JSON 对象。其他列不做字段转义：包含逗号或引号的 `classification` 或 `reason` 可能破坏一行。需要无歧义的记录时请用 NDJSON。

`list` 对 TCP 打印裸端口，对其他协议空间加 `u:`、`s:` 或 `o:` 前缀。`--output-arg "--no-port"` 只打印地址。

在带 libbson 的构建上可以转换 `bson` 输出：

```bash
xtate --parse-bson results.bson > results.json
```

MongoDB 选项通过 `-output-arg` 传入：`--database-name`（默认 `xtate`）、`--collection-name`（默认时间戳）、`--application-name`、`--insert-bulk`、`--bulk-size`、`--compact-mode`、`--retry-count` 和 `--retry-delay`。失败会重试有限次数；最终失败会把输出标记为致命错误，扫描以非零码退出。

## 追加、屏幕副本与转义

- `--append-output`（`-output-append`）追加到文件而不是截断。
- `--output-screen` 让模块写目的地的同时也把结果打印到 stdout。
- 只能有一个输出模块生效。没有向多个文件的分发。

转义刻意保守，因为结果可能包含任意字节：

- 默认：`"`、`'`、`\` 和不可打印字节变成 `\xNN`。这保持文本可读，但**不是合法 JSON**。
- `--no-escape-char`（`--no-escape`）：同样的字节变成 `\\xNN`，这是合法 JSON。该值往返后是字面四个字符 `\xNN`，而不是原字节。
- `classification` 和 `reason` 原样复制，从不转义，因此可能破坏一行 NDJSON 或一行 CSV。
- BSON 和 MongoDB 自行转义。不要把它们与 `--no-escape-char` 组合使用。

需要字节级精确传输时用 BSON 或 MongoDB；对文本格式，要接受二进制字段是有损的。

`--output-as-info`（别名 `--output-as`、`--out-as`、`--output-asn`、`--out-asn`）为地址出现在已加载 ip2asn 表中的目标，把 ASN、国家和描述字段加入 `output report`：

```bash
xtate --ip2asn-v4 ip2asn-v4.tsv --output-as-info \
  -ip 203.0.113.10 -p 443 -scan tcp-syn -show all
```

表必须在启动时加载，否则 Xtate 拒绝运行。

## 托管 job：心跳、分片与 manifest

通过控制面启动的 job（GUI、TUI、MCP 或 `--job-run`）把结果写到由 job 管理器拥有的文件：

```bash
xtate --job-run=request.json --job-result=out.ndjson --job-timeout=30
```

请求是 JSON 扫描请求（`schemas/scan-request.schema.json`）；worker 以 `--show all` 语义产生 NDJSON。完成时 CLI 打印一个状态对象：

```json
{"job":{"id":"job-1","state":"completed","exit_code":0,"result":"out.ndjson"}}
```

worker 运行期间维护 `<result>.heartbeat`，大约每秒原子重写一次：

```text
time=1763023200
sent=861
targets=287
success=3
failed=1
info=857
phase=tx
```

发送期间 `phase` 是 `tx`，发送停止后是 `draining`；心跳过期会让 job 变成 `stalled`（默认超时 30 秒）。普通非 job 扫描不写心跳。

分片是可选的，在扫描结束后应用，而不是写入过程中：

```bash
xtate --job-run=request.json --job-result=out.ndjson \
  --result-chunk-size 10485760 --result-index --result-compress zstd
```

- `--result-chunk-size N` 把 NDJSON 文件切成大约 `N` 字节的分片（0 为默认值，保持单文件）。一个分片最多超出 `N` 一行。分片命名为 `out.ndjson.00001.ndjson`、`out.ndjson.00002.ndjson` 等。
- 至少写入一个分片后，原文件被删除。
- manifest 是 `out.ndjson.manifest.json`：

  ```json
  {"format":"ndjson","compression":"none",
   "chunks":[{"id":1,"path":"out.ndjson.00001.ndjson","bytes":10485760,"records":20000}],
   "total_bytes":10485760,"total_records":20000}
  ```

  使用 zstd 时分片路径以 `.ndjson.zst` 结尾，`compression` 是 `zstd`，`bytes` 是压缩后大小。构建没有 zstd 时，Xtate 会警告并写入未压缩分片。Windows 上应在构建前通过 vcpkg 安装 `zstd:x64-windows`；`--list-capabilities` 会报告 zstd 是否可用。
- `--result-index` 额外写 `out.ndjson.index.json`，包含同样的 `chunks` 数组，但没有 format 和总计。
- 分片只为到达终态的 job 构建。CLI 的 `--job-run` 路径只在 job 完成时构建；控制面对任何终态都构建，因此被取消或超时的 job 也能产生分片的部分结果。

`--result-quota N` 不同：它在扫描**期间**执行。当输出文件增长超过 `N` 字节时，Xtate 记录 "result file exceeds quota; stopping scan"，把输出标记为致命错误并停止发送。job 管理器在运行后还会报告结果文件超配额的警告。配额是安全阀，不是精确的记录上限。

超时或取消不会删除结果文件：停止前写入的内容仍可读。

## 读取 job 状态与 manifest

控制面的 `job.status` 返回由心跳派生的计数器：

```json
{"job_id":"job-1","state":"running","phase":"tx","sent":512,"targets":861,
 "heartbeat_age_ms":420,"heartbeat":true,"exit_code":0,
 "result":"out.ndjson","log_path":"out.log","error":"",
 "stderr_tail":"","elapsed_ms":12000}
```

`job.results` 和 `job.result_manifest` 只返回元数据，从不返回记录：

```json
{"job_id":"job-1","state":"completed","result_path":"out.ndjson",
 "manifest_path":"out.ndjson.manifest.json","result_bytes":10485760,
 "complete":true}
```

`complete` 表示 job 到达了终态，而不是每个计划目标都被成功扫描。记录可以通过 MCP 的 `job.records` 分页读取；它会跟随 manifest 分片，并在服务端带 zstd 构建时透明解压 zstd 分片。你也可以自己从 `result_path` 或 manifest 分片读取；控制面本身不是完整结果服务器。

## 控制台

GUI 的 **Live scan** 页面轮询 `job.status`，显示状态、已发送、目标数、阶段、心跳年龄、已用时间、退出码和结果 manifest 卡片。**Results** 页面按最新在前列出控制面管理的扫描（id、状态、结果路径）；选中一个扫描会回到它的 Live 视图。Live 视图还有 **Result records** 卡片，通过 `/api/results` 每次分页读取 50 条合法 NDJSON 记录；它会跟随 manifest 分片，并在服务端带 zstd 构建时透明解压 zstd 分片。需要原始分片字节时请使用自己的工具。这也是结果路径必须是守护进程所在机器上真实文件的原因。

逐页说明和 token/回环安全模型见 [02 · GUI 控制台](./02-gui-console.md)。

## 后处理配方

```bash
# Open ports only, as compact JSON lines
jq -c 'select(.level=="success")' results.ndjson

# Tally classifications
jq -r '.classification // "none"' results.ndjson | sort | uniq -c | sort -nr

# Join JARM slots
./tools/jarm_aggregate.py results.ndjson > jarm.jsonl

# Read a specific chunk of a large job
wc -l out.ndjson.00003.ndjson
zgrep -c '"level":"success"' out.ndjson.00003.ndjson.zst
```

如果需要不同的传输、过滤或聚合，请处理 NDJSON 流；它是唯一能无歧义保留每个字段的格式。

## 限制与风险

- 一次只能有一个输出模块。结果在接收处理线程中格式化，并经模块序列化，因此慢的目的地（尤其是同步 MongoDB 插入）会给整个扫描造成背压。
- `--show` 过滤发生在输出之前：文件和数据库会继承它。
- 默认转义不是合法 JSON；`--no-escape-char` 产生合法 JSON，但不是字节精确的值。
- `classification`/`reason` 从不转义，可能破坏 CSV/NDJSON 行。
- 分片在 job 到达终态后进行；被终止的进程会留下单个未分片的文件。
- 结果文件不会自动清理。在 job 管理器清理旧 job 之前复制你需要的内容，并把结果路径视为敏感数据：它们包含扫描过的每个地址以及任何 banner/证书数据。
- `--result-quota` 会停止扫描；它不会修复或截断超配额的文件。

## 另见

- [03 · CLI 与 job](./03-cli-and-jobs.md) —— 控制面与 job 命令
- [05 · 模块与参数](./05-modules-and-parameters.md) —— 输出模块及其参数
- [输出](../output.md) —— 完整格式参考
- [job 模型](../job-model.md) —— 状态、心跳与超时语义
- [控制面](../control-plane.md) —— 传输、方法与限制
- [JSON 契约](../json-contracts.md) —— schema 与错误码
