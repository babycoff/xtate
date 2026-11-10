# AI 集成设计（MCP / Agent / Skill）

[English](../ai-integration.md) · **中文**

Xtate 应通过带类型、可审计的接口被 AI 调用，而不是把无限制 shell 交给模型。
CLI 仍是唯一事实来源；MCP 和 skill 只是它的封装层。

## 三层设计

### 1. 稳定的 JSON 契约

在任何 agent 集成之前先完成：

```text
模块元数据 schema
扫描/探针配置 schema
结果 schema（已有 NDJSON）
稳定错误码 schema
```

需要时增加 `--json`/`--json-schema`。不要让 agent 解析彩色文本。

### 2. Agent skill

受审查的 `SKILL.md`，指导 agent：

```text
确认目标授权
先跑 --check / --explain-target
仅对 stateful 扫描安装 Linux 防火墙规则
选择 scanner/probe 和速率
启动有界 job
读取 NDJSON 结果
清理防火墙规则
```

skill 是文档和策略，不是特权二进制。

### 3. MCP server

建议命令：

```text
xtate mcp --stdio
```

传输：stdio JSON-RPC（MCP）。工具小且类型化。

先只读：

```text
list_modules
describe_probe
explain_target
check
validate_config
get_scan_status
get_results
```

只读稳定后再加受控扫描：

```text
start_scan
stop_scan
```

`start_scan` 接受封闭配置对象，而不是 shell 字符串：

```json
{
  "scan": "tcp-state",
  "probe": "doh-h2",
  "targets": ["203.0.113.10"],
  "ports": [443],
  "probe_args": {"dns_name": "example.com", "authority": "dns.example"},
  "rate": 100,
  "timeout_sec": 30
}
```

返回 job id，之后读取结果。不暴露无界阻塞调用。

## 安全要求

```text
不允许任意 shell
不扩展用户给定目标
scan/probe/参数名白名单
速率和并发限制
job 超时与取消
审计日志：谁/什么/目标/参数/结果文件
写操作默认 dry-run
扫描和防火墙变更显式确认
不保存凭据
```

## 为什么不能只有 skill

skill 无法强制工具边界或校验参数。MCP 提供类型化边界，skill 教会 agent 流程。
两者都需要。

## 测试

- MCP 协议一致性和 schema 校验；
- 只读工具无网络测试；
- 扫描 job 生命周期：start/status/stop/results；
- 拒绝测试：shell 元字符、未知参数、无界目标；
- agent 评测：规划安全扫描、执行、总结结果。

## 阶段

```text
2.42.0  JSON 契约 + skill
2.43.0  只读 MCP server
2.44.0  受控扫描 job
2.45.0  评测与打包
```
