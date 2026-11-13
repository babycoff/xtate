# JSON 契约

[English](../json-contracts.md) · **中文**

这些 schema 是 AI/MCP 集成的机器可读边界。CLI 和 NDJSON 输出仍是事实来源，
schema 只是描述它们。

## Schema

| 文件 | 用途 |
|:---|:---|
| [`schemas/module.schema.json`](../../schemas/module.schema.json) | 模块元数据（scan/probe/output/generate） |
| [`schemas/scan-request.schema.json`](../../schemas/scan-request.schema.json) | Agent/MCP 使用的封闭扫描请求 |
| [`schemas/result.schema.json`](../../schemas/result.schema.json) | 一行 NDJSON 结果 |
| [`schemas/error.schema.json`](../../schemas/error.schema.json) | 稳定错误信封 |
| [`schemas/error-codes.json`](../../schemas/error-codes.json) | 已知错误码 |

## 运行时元数据

```bash
xtate --list-modules-json
```

输出所有 scan/probe/output/generate 模块的 `name`、`kind`、`probe_type`、
描述和参数。覆盖检查：

```bash
XTATE_BIN=build/bin/xtate python3 tests/schema/validate_modules.py
```

C 运行时直连：

```bash
xtate --scan-request=request.json
```

不经过 shell/子进程，直接生成内部配置。`dry_run` 默认为 `false`；设为 `true` 时
只列出计划目标，不发送报文。错误以
`{"error":{"code":"...","message":"..."}}` 返回。

参考 scan-request 适配器：

```bash
python3 tools/scan_request_to_cli.py < request.json
```

它会按 `scan-request.schema.json` 校验并输出 argv 数组，不执行任何命令。

## 规则

- JSON 使用 UTF-8；结果一行一个对象。
- 请求边界拒绝未知字段（`additionalProperties: false`）。
- `scan-request` 是数据，不是 shell 字符串；不允许命令替换、管道、重定向。
- `targets` 只能是调用者给出的内容，不做隐式扩展。
- `dry_run` 默认为 `false`；只有 `true` 才只列目标、不发送。MCP 另行要求
  `authorized: true`。
- 结果必须符合 `result.schema.json`；report 值为标量。
- 错误使用稳定的大写 `code`，不使用本地化文本。

## 版本

Schema 随 Xtate 版本发布。新增字段必须先修订 schema；删除或重命名字段是破坏性变更。

## 校验

```bash
python3 -m pip install jsonschema
python3 tests/schema/validate_schemas.py
```

测试覆盖 schema 元校验、正反例 fixture 和真实 NDJSON 结果。MCP server 只校验它
接受的封闭请求子集（模块名、目标语法、端口范围和速率），不解析结果行。

## JSON 错误模式

`--scan-request` 模式下所有 `LOG(LEVEL_ERROR)` 输出为：

```json
{"error":{"code":"INVALID_ARGUMENT","message":"...","retryable":false}}
```

不再使用彩色 `[ERR]` 文本。提示/警告仍为人类文本；运行时错误暂用
`INTERNAL_ERROR`，后续再细分为专用错误码。

## 输出模块可见性

选择 OutputModule 但未指定 `--show` 时，只写入 success 结果。Xtate 启动时会提示。
使用 `--show failed`、`--show info` 或 `--show all`；输出失败测试特意使用
`--show failed`。
