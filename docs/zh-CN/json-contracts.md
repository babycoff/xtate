# JSON 契约

[English](../json-contracts.md) · **中文**

这些 schema 是 AI/MCP 集成的机器可读边界。CLI 和 NDJSON 输出仍是事实来源，
schema 只是描述它们。

## Schema

| 文件 | 用途 |
|:---|:---|
| [`schemas/module.schema.json`](../schemas/module.schema.json) | 模块元数据（scan/probe/output/generate） |
| [`schemas/scan-request.schema.json`](../schemas/scan-request.schema.json) | Agent/MCP 使用的封闭扫描请求 |
| [`schemas/result.schema.json`](../schemas/result.schema.json) | 一行 NDJSON 结果 |
| [`schemas/error.schema.json`](../schemas/error.schema.json) | 稳定错误信封 |

## 规则

- JSON 使用 UTF-8；结果一行一个对象。
- 请求边界拒绝未知字段（`additionalProperties: false`）。
- `scan-request` 是数据，不是 shell 字符串；不允许命令替换、管道、重定向。
- `targets` 只能是调用者给出的内容，不做隐式扩展。
- Agent 发起的请求默认 `dry_run: true`。
- 结果必须符合 `result.schema.json`；report 值为标量。
- 错误使用稳定的大写 `code`，不使用本地化文本。

## 版本

Schema 随 Xtate 版本发布。新增字段必须先修订 schema；删除或重命名字段是破坏性变更。

## 校验

```bash
python3 -c "import json,glob; [json.load(open(f)) for f in glob.glob('schemas/*.json')]"
```

MCP server 必须在返回前校验请求和生成的结果行。
