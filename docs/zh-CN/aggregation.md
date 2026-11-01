# 结果聚合

[English](../aggregation.md) · **中文**

Xtate 输出的是**事件流**，不是每目标一条最终记录。ZBanner 对同一个端口可能输出 `open`、多个 banner 段和 `acknowledged`；HLTCP 还会增加状态/探测事件。因此聚合属于**下游**工作。本页给出自带的后续处理示例。

## 推荐模型：扫描结束后处理

```text
xtate -> NDJSON 文件 -> aggregate-events.py -> 每目标 JSONL/CSV
```

默认推荐这种方式，因为：

- 原始事件流保留，可重新聚合和审计；
- 慢消费者不会反压扫描器；
- 扫描和聚合可以独立重跑；
- 容易校验事件计数。

实时看板可以用管道：

```bash
xtate ... -output-module ndjson -output-file - --no-status |
  python scripts/aggregate-events.py - --format jsonl
```

管道只适用于 NDJSON，且消费端必须跟得上；大规模扫描建议结束后处理。

## 自带示例

[scripts/aggregate-events.py](../scripts/aggregate-events.py) 只使用 Python 标准库。

```bash
xtate ... -output-module ndjson -output-file scan.jsonl
python scripts/aggregate-events.py scan.jsonl -o per-target.jsonl --stats
```

小规模冒烟：

```bash
head -n 10000 scan.jsonl |
  python scripts/aggregate-events.py - --format jsonl
```

参数：

| 参数 | 含义 |
|:---|:---|
| `input` | NDJSON 文件，或 `-` 表示 stdin |
| `-o/--output` | 输出文件，或 `-` 表示 stdout |
| `--format` | `jsonl`（默认）、`json`、`csv` |
| `--group-by` | 逗号分隔的分组字段（默认 `ip_proto,ip_them,port_them`） |
| `--strict` | JSON 解析失败时中止（默认跳过并写 stderr） |
| `--max-groups` | 超过 N 个分组就中止（默认不限制）；高基数 OOM 保护 |
| `--stats` | 输入/输出计数、分组数、耗时，以及平台支持时的最大 RSS |

每个分组输出：

```json
{
  "ip_proto": "TCP",
  "ip_them": "192.0.2.10",
  "port_them": 443,
  "status": "open",
  "status_reason": "syn-ack",
  "events": 3,
  "first_seen": "2026-11-01T12:00:00Z",
  "last_seen": "2026-11-01T12:00:02Z",
  "levels": {"success": 1},
  "classifications": {"open": 1},
  "reasons": {"syn-ack": 1},
  "scan_report": {"ttl": 54},
  "probe_report": {"tls version": "TLSv1.3"},
  "output_report": {}
}
```

状态优先级：`open` > `fake-open` > `responsed` > `acknowledged` > `closed`，同级取最新事件。未知 classification 会保留在 `classifications` 中并计数。

## 模块特定字段

NDJSON 保留公共字段和嵌套模块报告：

```text
time, level, ip_proto, ip_them, port_them, ip_me, port_me,
classification, reason, scan_report, probe_report, output_report
```

聚合器把 `scan_report`、`probe_report`、`output_report` 当作不透明对象合并，不假设 TLS/HTTP/ZBanner 的字段名；重复 key 取最后一个非空值。如果需要每个 banner 段或每个 probe 事件，请保留原始 NDJSON。

## 其它输出格式

| 输出 | 聚合方式 |
|:---|:---|
| NDJSON | 推荐：一行一个结构化事件 |
| BSON | 用 libbson / Python `bson` 解析，或先转 NDJSON |
| MongoDB | 直接用 MongoDB aggregation pipeline |
| CSV | 公共列 + 转义 JSON 字符串，解析较别扭 |
| Text | 只适合人看，不推荐机器聚合 |
| List/null | 信息不足 |

示例只支持 NDJSON；BSON/CSV 适配器是后续的小层。

## 内存与规模

示例为每个分组保留一个 Python dict；它是**结束后工具**，不影响扫描器内存。

本机 100 万事件基准（1,000,000 个唯一目标/端口分组，184 MB NDJSON 输入，Linux 容器）：

```text
input_events=1000000 groups=1000000 bad_json=0 elapsed≈50s maxrss_kb=1764064
```

峰值约 **1.68 GiB**（完整 1M 分组 dict）；输出约 361 MB JSONL，因为每个分组都带自己的元数据。Windows 主机跑同样输入约 25 秒，但 Windows 的 `--stats` 不提供 `maxrss` 字段。

这是最坏情况（每条事件一个独立分组）。更大规模时：

- 只聚合需要的字段；
- 用 `--group-by` 降低基数；
- 用 `--max-groups` 作为 OOM 保护，在吃满内存前失败；
- 10M+ 分组用 SQLite/外部排序，或按 IP 前缀分区；
- 不要在内存里构建完整 10M dict。

`--stats` 在支持 Python `resource` 的平台上报告 `maxrss_kb`（Linux/macOS）；Windows 可能没有该字段。
