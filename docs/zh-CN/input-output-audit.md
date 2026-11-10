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
| BSON 输出 | `bson_new()` 和 `fwrite()` 失败被忽略。 | 已修复：检查分配和写入。 |
| CSV | classification/reason 未加 CSV 引号；报告字符串没有专门的 CSV 转义。 | 待修：标准目标因 data-chain 转义通常安全，但任意模块输出需要专用 CSV writer。 |
| BSON 输出 | `bson_append_*` 返回值未检查。 | 待修。 |
| Mongo 输出 | 插入失败只记录日志，不重试也不计入失败。 | 待修。 |
| 解析器 fuzz | NDJSON/BSON 输出和 BSON 输入没有 fuzz 目标。 | 待补。 |

## 已执行验证

```text
pcap 回放 -> NDJSON：Python json 逐行解析通过
pcap 回放 -> CSV：标准 csv reader 读出 12 列
损坏 BSON 长度 0x7fffffff：分配前拒绝，非零退出
目标文件超长行 > 65535：带行号拒绝
Linux 构建/selftest：PASS
MSVC 构建：PASS
```

## 下一步

1. 实现对所有字段加引号、双写引号/换行的 CSV writer。
2. 检查 BSON/Mongo 的 append/insert 返回值。
3. 增加 BSON 和目标文件的畸形输入 fixture。
4. 增加 NDJSON 转义的 fuzz/回归测试。
