# 输入/输出模块审查

[English](../input-output-audit.md) · **中文**

本审查覆盖目标/输入解析，以及 text、CSV、NDJSON、BSON、MongoDB 输出路径。
重点是正确性，不是性能基准。

## 发现与修复

| 区域 | 问题 | 状态 |
|:---|:---|:---|
| NDJSON | 字符串直接用 `%s` 写出，引号、反斜杠和控制字符会产生非法 JSON。 | 已修复：名称/值/classification/reason 逐字段 JSON 转义。 |
| BSON 输入 | 损坏的 4 字节长度可请求数 GB 分配，且未检查分配结果。 | 已修复：`--parse-bson` 和 Mongo 导入增加 16 MiB 上限及分配检查。 |
| 目标文件 | `fgets()` 会把超过 65535 字节的行拆成多行，可能被当成多个目标。 | 已修复：拒绝超长行并丢弃该行剩余内容。 |
| 目标文件 | `fgets()` 后的读取错误未检查。 | 已修复：检查 `ferror()`。 |
| 输出文件名 | 过长 `--output-file` 被静默截断到 255 字节。 | 已修复：直接报错。 |
| CSV 追加 | 每次追加都会重复写表头。 | 已修复：仅新文件写表头。 |
| 输出关闭 | `fflush()`/`fclose()` 失败被忽略。 | 已修复：text/CSV/NDJSON/BSON 记录错误。 |
| CSV 控制字符 | 没有端到端 pcap fixture（HTTP parser 拒绝原始控制字符），但 `json_escape_fuzz` 覆盖所有控制字节。 | 部分 |
| BSON 输出 | `bson_new()` 和 `fwrite()` 失败被忽略。 | 已修复：检查分配和写入。 |
| CSV | classification/reason 未加引号；报告字符串没有 CSV 转义。 | 已修复：所有字段加引号，双写引号，报告 JSON 做 CSV 安全转义。 |
| CSV 控制字符 | 没有端到端 pcap fixture（HTTP parser 拒绝原始控制字符），但 `json_escape_fuzz` 覆盖所有控制字节。 | 部分 |
| BSON 输出 | BSON 附加失败被忽略。 | 已修复：UTF-8、日期、int32/int64、double、bool、binary、OID 均检查。 |
| Mongo 输出 | BSON 导入插入失败仍计为成功；输出文档分配未检查。 | 已修复：失败返回 false，分配检查，批量失败计数。 |
| 解析器 fuzz | 输出转义和 BSON 文档没有 fuzz 目标。 | 已增加 `json_escape_fuzz` 和 `bson_doc_fuzz`，均接入 `tests/fuzz/run.sh`。 |

## 已执行验证

```text
pcap 回放 -> NDJSON：Python json 逐行解析通过
pcap 回放 -> CSV：标准 csv reader 读出 12 列，报告列可解析为 JSON
带引号/反斜杠 header 的 pcap 回放 -> NDJSON/CSV 仍保持合法 JSON
CSV 追加：只写一次表头
损坏 BSON 长度 0x7fffffff：分配前拒绝，非零退出
目标文件超长行 > 65535：带行号拒绝
Linux 构建/selftest：PASS
MSVC 构建：PASS
json_escape_fuzz：3 秒 398k 次执行，fuzz smoke passed
bson_doc_fuzz：3 秒 3.3M 次执行，fuzz smoke passed
```

## 下一步

1. 增加包含引号/换行的 CSV fixture（writer 已按 RFC4180 风格重写）。
2. 检查剩余 BSON append 返回值。
3. 增加 BSON 和目标文件的畸形输入 fixture。
4. 将 fuzz 扩展到 BSON 输入/输出（JSON 转义已覆盖）。
