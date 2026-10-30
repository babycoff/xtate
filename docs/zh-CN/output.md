# 输出

[English](../output.md) · **中文**

默认情况下，Xtate 把结果打印到 **stdout**，每条回复一行。*输出模块*（OutputModule）也可以改为把结果写成文本、CSV、NDJSON、BSON 或 `list` 文件，或者插入 MongoDB。状态栏是另一回事：它画在 **stderr** 上，因此重定向 stdout 不会弄脏结果流。

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan tcp-syn > results.txt
```

> 文档以 Xtate v2.17.0 为准。你所用构建的确切 flag 以 `--help` 和 `--help-output <module>` 为准。

## 结果行

```
[+] host: 192.168.1.10 port: 80 is "open" because "syn-ack",  ttl: 64,  win: 64240
[*] host: 192.168.1.11 port: 80 is "closed" because "rst"
```

前缀表示等级：`[+]` 成功、`[x]` 失败、`[*]` 信息。接下来是目标（`host`、`port`）、模块的 `classification` 与 `reason`，最后是报告：来自扫描、探测和输出模块的类型化键值对（`ttl`、`banner`、`cert_0`、`distance`、`ASN` 等）。字符串带引号并转义；整数和布尔值按字面量输出。在终端上前缀会着色、状态栏会刷新；`--no-ansi` 关闭颜色，`--no-status` 关闭状态栏。

在内部，一条结果就是一个 `OutItem`：`timestamp`（自动填充）、`level`、`target`（协议、双方地址、双方端口）、`classification` 与 `reason`（30 字节缓冲），以及三条类型化键值链——`scan_report`、`probe_report`、`output_report`。二进制值在文本格式中打印为 `(N bytes bin)`，但 `bson`/`mongodb` 会完整存储；`no_port` 标志会为无端口的结果隐藏端口。

## 等级与 `-show`

等级决定一条结果是否会被发出——**这个过滤发生在输出模块之前**，所以它同样作用于文件和数据库。

| 等级 | 默认打印？ | 典型含义 |
|:---|:---:|:---|
| `success` | 是 | 肯定回答（`open`、`alive`、banner、证书） |
| `failure` | **否** | 否定回答（`closed`、`abort`、握手失败） |
| `information` | **否** | 上下文而非发现（ZBanner 与 `tcp-state` 的端口状态、TLS alert） |

用 `-show`（`--show-output`）增加一个等级，用 `-no-show`（`--no-show-output`）移除一个；两者都可以重复。`-show` 接受 `failed`/`fail`/`failure`、`info`/`information` 和 `success`/`successed`；`-no-show` 接受 `failed`/`fail`、`info`/`information` 和 `success`。

状态栏的合计会统计每一个到达输出层的结果，包括已被过滤掉的。模块给一条结果分配哪个等级由模块自己决定：`tcp-syn` 把 `closed` 归为 `failure`，而 `zbanner` 把 `open` 和 `closed` 都归为 `information`，除非你传入 `-scan-arg "--port-success"` 或 `--port-failure`——这通常就是扫描看起来空空如也的原因。

## 输出模块

| 模块 | 需要 `-output-file` | 写入内容 |
|:---|:---:|:---|
| `text` | 是 | 与 stdout 相同的行格式，写入文件 |
| `ndjson` | 是 | 每行一个 JSON 对象（JSONL） |
| `bson` | 是 | 拼接的 BSON 文档（二进制） |
| `csv` | 是 | 一行表头加每条结果一行 |
| `list` | 是 | 只写 `ip` 和可选的 `port` |
| `mongodb` | 是 | 插入到 MongoDB 集合中；"文件"是一个 **URI** |
| `null` | 否 | 什么都不写（用于基准测试） |

编译时缺少可选库的模块不会出现在 `--list-output` 中；参见[模块](./modules.md)。

## 文件、追加与屏幕

```bash
# 文本文件，通过等级过滤把 closed 端口也包含进来
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80,443 -scan tcp-syn \
  -output-module text -output-file scan.txt -show failed

# NDJSON，追加写入，并额外回显到 stdout
sudo ./bin/xtate -ip 10.0.0.0/24 -p 80 -scan zbanner -probe http -show info \
  -output-module ndjson -output-file scan.jsonl -output-append -output-screen
```

- `-output-module`（别名 `--output`、`--out`）选择模块；`-output-file`（别名 `--out-file`、`-o`）设置目标位置。
- 不指定模块时，结果始终写到 stdout。指定模块后，除非给出 `-output-screen`（别名 `--out-screen`），否则 stdout 保持安静。
- `-output-append`（主名 `--append-output`，别名 `--append`）以追加模式打开目标，而不是截断它。`csv` 每次运行都会写表头，追加运行也一样。
- 对 `text`、`csv`、`ndjson` 和 `list`，目标恰好为 `-` 就表示 stdout。`bson` 不支持这一约定，`mongodb` 则把 `-output-file` 当作连接 URI。
- 模块选项通过 `-output-arg` 以一个带引号的字符串传入，例如 `bson` 的 `-output-arg "-compact-mode"`。

## 格式说明

### text 与 csv

`text` 复刻 stdout 行，多一个 `in tcp` 协议词，无颜色、无状态栏。`csv` 以下面的表头开始：

```text
time,level,ip_proto,ip_them,port_them,ip_me,port_me,classification,reason,scan report,probe report,output report
```

三个 report 列是内嵌的类 JSON 字符串，其内部引号会翻倍；其他列不做字段级转义，所以分类中若含逗号或引号就会破坏整行。请让 CSV 消费端保持宽容。

### ndjson

每行一个紧凑对象：

```json
{"time":"2024-05-01T12:00:00Z","level":"success","ip_proto":"tcp","ip_them":"192.168.1.10","port_them":80,"ip_me":"192.168.1.5","port_me":40001,"classification":"open","reason":"syn-ack","scan report":{"ttl":64,"win":64240},"probe report":{"banner":"HTTP/1.1 200 OK"}}
```

`scan report` / `probe report` / `output report` 子对象为空时会被省略；无端口结果的 `port_them`/`port_me` 同样省略。

### bson 与 mongodb

`bson` 把一串二进制文档写入文件，没有 stdout 约定；目标写 `-` 会得到一个字面名为 `-` 的文件。可用 `--parse-bson`（libbson 构建）把它转回 JSON：`xtate --parse-bson out.bson > out.json`。`mongodb` 把 `-output-file` 当作 URI 直接连接：

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 443 -scan zbanner -probe tls-hello -show info \
  -output-module mongodb -output-file "mongodb://127.0.0.1:27017" \
  -output-arg "-database-name xtate -collection-name scan1"
```

它的子参数有 `--database-name`（默认 `xtate`）、`--collection-name`（默认：时间戳）、`--application-name`、`--insert-bulk` / `--bulk-size`（默认 200）和 `--compact-mode`。插入发生在结果路径中；配合 `--bulk-size` 时文档会先缓冲、再分批刷写。两个模块都会自行转义字符串，所以绝不要把它们和 `--no-escape-char` 一起使用。两种格式都可以配合 `--store-bson` / `--store-json` 加 `--mongodb-uri`、`--mongodb-db-name` 和 `--mongodb-col-name` 离线导入；`--store-json` 要求每行都是合法 JSON。

### list 与 null

`list` 只写目标（`192.168.1.10 80`），因此很适合作为下一阶段的输入。UDP、SCTP 和 "other" 端口分别带 `u:`、`s:`、`o:` 前缀；TCP 端口直接写端口号。`-output-arg "--no-port"` 只写地址。`null` 丢弃一切，用于速率基准测试。

## 转义：`--no-escape-char` 与 JSON 陷阱

banner 与 UTF-8 报告字段由结果层归一化：可打印字符原样通过，而 `"`、`'`、`\` 和每个不可打印字节都变成 `\xNN`。这很好读，但**不是合法 JSON**——单个反斜杠是非法转义。加上 `--no-escape-char`（别名 `--no-escape`）后，转义本身再被转义，产生 `\\xNN`：这是合法 JSON，解析回来是字面文本 `\xNN`。

```bash
sudo ./bin/xtate -ip 192.168.1.0/24 -p 80 -scan zbanner -probe http -show info \
  -output-module ndjson -output-file scan.jsonl --no-escape-char
```

注意：**不要**对 `bson`/`mongodb` 使用这个 flag（它们会自行转义，于是变成双重转义）；`classification` 和 `reason` 用 `%s` 打印、从不转义，所以其中一旦出现引号或换行，无论是否加该 flag 都会破坏 JSON/CSV；该 flag 只改变报告字符串的转义，从不改变探测看到的原始字节。

## 用 `--output-as-info` 做 AS 标注

`--output-as-info`（别名 `--output-as`、`--out-as`、`--out-asn`）在已加载的 `ip2asn` 表中查询目标，并把 `ASN`、`AS country code` 和 `AS desc` 追加到 `output_report`。用 `--ip2asn-v4` / `--ip2asn-v6` 加载表。

```bash
sudo ./bin/xtate --ip2asn-v4 /path/to/ip2asn-v4.tsv -ip 10.0.0.0/24 -p 443 \
  -scan zbanner -probe tls-hello -show info --output-as-info \
  -output-module ndjson -output-file scan.jsonl
```

没有加载表时，`output_init` 会拒绝启动；查询按每条结果进行，所以在超大规模扫描中该 flag 会带来一些开销。

## 实践提示

- 同一时间只能有一个输出模块生效；不存在同时分发到两个模块的机制。
- 结果在接收处理线程中格式化，并在输出模块外围由互斥锁串行化，因此慢速目标端（尤其是同步的 MongoDB 插入）会对整次扫描形成背压；大规模运行更适合用 `bson`/NDJSON 搭配离线 `--store-*` 路径。
- `-show`/`-no-show` 过滤最先发生，所以 `-output-file` 绝不会包含你隐藏的等级——如果文件意外为空，先检查等级，而不是模块。
- 被标记为 `no_output` 的结果（重复项、被抑制的重复）无论等级过滤如何设置，都不会到达任何目的地。

## 参见

- [扫描模式](./scanning-modes.md) — 哪个模块产生哪些等级与字段
- [模块](./modules.md) — 模块清单与可选依赖裁剪
- [故障排查](./troubleshooting.md) — 结果缺失与格式问题
- [README](../../README.zh-CN.md) — 功能概览
