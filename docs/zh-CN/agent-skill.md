# Xtate Agent Skill

Xtate Agent Skill 是一份 Markdown 操作手册，用来教会外部 agent 安全、正确地使用
Xtate MCP server。它不是 Xtate agent，不是独立二进制，也不是权限边界。

Skill 位于仓库的 [`skills/xtate/`](../../skills/xtate/SKILL.md)。它只提供指导；
授权、目标数量、速率、路由和结果路径仍由 MCP server 与控制面强制执行。

## 范围：仅限 MCP

这份 Skill 教外部 agent 使用 **Xtate MCP server**，不教 Xtate 命令行。它不包含
CLI 命令语法，并明确要求 agent 不要用 shell 绕过 MCP 校验。直接使用 CLI 时，请阅读
[使用手册](./manual/README.md) 和 `--help`。两者使用同一个 Xtate 引擎和同一套安全
模型，但 CLI 是面向专家的接口，没有 MCP 工具调用包装。

## 内容

| 文件 | 作用 |
|---|---|
| `SKILL.md` | 触发描述与端到端扫描流程 |
| `references/tools.md` | MCP 工具契约、`start_scan` 字段、job 状态、结果文件 |
| `references/safety.md` | 授权清单、停止条件、主机前提、token 安全 |
| `references/troubleshooting.md` | 错误到处置的对照表与平台说明 |

主流程：

```text
确认授权与精确范围
→ list_modules / describe_probe
→ explain_target 与 check（多路由时拆分）
→ validate_config
→ start_scan，使用扁平字段和 authorized:true；result_path 可选
→ 轮询 job_status
→ job_result_manifest，按 id 顺序读取分片
```

## 安装

把 skill 目录复制或软链接到 agent host 扫描的位置。常见布局：

```bash
# 仓库内
skills/xtate/

# 部分 host 使用的用户级目录
~/.claude/skills/xtate/
~/.agents/skills/xtate/
```

例如：

```bash
cp -r skills/xtate ~/.claude/skills/xtate
```

以 host 文档给出的路径为准。Skill 不需要和 Xtate 二进制放在一起，只要能被 agent
发现即可。

## 使用

按 [MCP server 指南](./mcp-server.md) 启动控制面和 MCP server：

```bash
export XTATE_CONTROL_TOKEN="$(openssl rand -hex 16)"
xtate --control-plane=/tmp/xtate-ctl.sock
xtate --mcp --control-connect=/tmp/xtate-ctl.sock
```

然后给 agent 一个有边界的请求，例如：

> 用 tcp-syn 扫描 203.0.113.10 和 203.0.113.11 的 TCP 80、443，速率不超过
> 500 pps，最长 5 分钟。这个测试网段归我所有。

Skill 会要求 agent 先做路由预检、校验请求、启动有边界的 job，并报告 manifest 和
计数，而不是直接倾倒原始结果。范围仍需 agent 向用户确认；skill 不会把模糊请求
变成授权。

## 安全边界

- `authorized: true` 是调用者的声明，不是授权证明。Skill 要求 agent 先确认授权人、
  精确网段、端口和时间窗口。
- MCP server 会拒绝缺少授权、未知模块、目标来源混用、非法速率/超时、混合路由和
  不可写结果路径。Skill 不能削弱这些检查。
- Skill 不包含可执行代码，也不包含凭据；不要把控制 token 写进 skill 文件。
- Skill 不是 agent 评测。Prompt injection、范围扩张和重试行为仍需在 host 层审查。

## 大目标集

MCP 参数缓冲区为 8 KiB。更大的目标集应使用 `include_file`，每行一个目标或范围，
并用 `explain_target` 预检代表性目标。当前没有从 `include_file` 做路由发现；显式
传入 `interface` 会跳过服务端预检，因此必须由操作者自行确认。

## 维护

当 MCP 工具、`scan-request.schema.json`、错误格式或 job/结果模型变化时，同步更新
skill。保持 `skills/xtate/` 中的示例与 [MCP server 指南](./mcp-server.md) 和
[scan request schema](../../schemas/scan-request.schema.json) 一致。

修改 skill 前，先在一个有边界的扫描场景上跑无 skill 基线并记录失败；修改后用同一
场景验证 agent 使用 `target`（单数）、扁平的 `start_scan` 字段（不要嵌套
`arguments`）、`timeout_sec`，明确确认范围；提供 `result_path` 时使用专用路径，
否则使用托管的运行目录。

## 相关

- [MCP server](./mcp-server.md)——工具、resource 与限制
- [控制面](./control-plane.md)——MCP/GUI 共用的 job API
- [Job 模型](./job-model.md)——生命周期、心跳与取消
- [AI 集成设计](./ai-integration.md)——skill 在分层中的位置
