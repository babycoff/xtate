# AI 集成（MCP / Agent / Skill）

Xtate 通过类型化、可审计的接口供 AI agent 调用，而不是给它一个不受限的 shell。
CLI 仍是事实来源；控制面拥有 job，MCP server 只是控制面的轻量客户端。

## 当前状态

2.42.0 已实现：

- 托管扫描 job：超时、stall 检测、心跳和取消；
- 本地控制面：Linux Unix socket 或 Windows Named Pipe，支持通过
  `XTATE_CONTROL_TOKEN` 做共享 token 认证（生产环境应设置）；
- stdio MCP server：模块元数据、路由规划、配置校验、job 启动与查询；
- 分片结果文件和 manifest；结果不会内联返回；
- scan-request、模块、结果和错误码的 JSON 契约。

2.42.1 已交付：

- 经过审查的 Agent Skill（文档与策略，不是特权二进制），位于
  [`skills/xtate/`](../../skills/xtate/SKILL.md)。

2.43.0 已交付：

- 全屏 TUI 控制平面客户端（`xtate --tui`），复用同一套 job/控制 API，不新增扫描
  路径。

仍待完成：

- agent 评测套件与打包；
- 通过 MCP 暴露 generate/流式输入（MCP 目前只支持静态 `targets` 或
  `include_file`）。

## 三层

### 1. 稳定的 JSON 契约

已有机器可读边界：

```text
schemas/scan-request.schema.json
schemas/module.schema.json
schemas/result.schema.json
schemas/error.schema.json 与 schemas/error-codes.json
NDJSON 结果行
```

MCP 工具返回 JSON 文本，agent 不需要解析带颜色的 CLI 输出。MCP server 自身校验
封闭子集（scan/probe 名称、目标语法、端口范围、速率、互斥字段），控制面再校验
job 请求。

### 2. Agent Skill

Skill 教会 agent：

```text
确认目标授权与精确范围
先运行 explain_target / check
只对有状态扫描开放必要的 Linux 防火墙规则
选择 scan/probe 组合和有上限的速率
启动有边界、带专用 result_path 的 job
读取 manifest 和分片，而不是整个结果文件
取消 job 或等待超时
```

从 [`skills/xtate/`](../../skills/xtate/SKILL.md) 安装；参见
[Agent Skill](./agent-skill.md)。Skill 是策略和文档，不能强制工具边界；边界由
MCP server 执行。

### 3. MCP server

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --control-plane=/tmp/xtate-ctl.sock
xtate --mcp --control-connect=/tmp/xtate-ctl.sock
```

工具：

```text
list_modules
describe_probe
explain_target
check
validate_config
start_scan
job_list
job_status
job_result_manifest
job_cancel
```

`start_scan` 接受封闭对象，不接受 shell 字符串：

```json
{
  "scan": "tcp-state",
  "probe": "doh-h2",
  "targets": ["203.0.113.10"],
  "ports": [443],
  "probe_args": {"dns_name": "example.com", "authority": "dns.example"},
  "rate": 100,
  "timeout_sec": 30,
  "result_path": "results/doh.ndjson",
  "authorized": true
}
```

它立即返回 `job_id`。状态和结果稍后读取；不存在无界阻塞的工具调用，也不会内联
返回结果数据。

## 安全要求

已实现：

```text
不执行任意 shell
不超出用户输入扩展目标
scan/probe 名称限制为已注册模块
目标数量与速率上限
job 超时、取消与审计日志
start_scan 显式要求 authorized:true
resource 路径限制为固定白名单
控制面仅本地；配置 `XTATE_CONTROL_TOKEN` 时校验 token
```

仍需验证或补充：

```text
按能力划分的 token 与每客户端配额
可配置的审计输出位置与轮转
针对 prompt injection 和目标范围越界的 agent 评测
```

## 测试

- MCP 协议一致性、schema、resource 和 prompt；
- 无网络情况下的只读工具；
- job 生命周期：启动、状态、manifest、取消和超时；
- 拒绝测试：未知模块、畸形目标、混合路由、错误 token、超大参数；
- Windows 和 Linux 回归。

参见 [MCP server](./mcp-server.md)、[控制面](./control-plane.md) 和
[job 模型](./job-model.md)。

## 阶段

```text
2.42.0  job + 控制面 + MCP server（已完成）
2.42.1  Agent Skill（已完成，已发布）
2.43.0  TUI 控制平面任务面板（已完成）
下一步  评测套件与打包
以后    MCP generate/流式输入
```
