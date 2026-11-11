# 错误码

[English](../error-codes.md) · **中文**

JSON 错误信封使用的稳定错误码。机器可读列表：
[`schemas/error-codes.json`](../schemas/error-codes.json)。

| 错误码 | 可重试 | 含义 |
|:---|:---:|:---|
| `INVALID_JSON` | 否 | JSON 格式错误 |
| `INVALID_ARGUMENT` | 否 | 字段/类型/值非法 |
| `UNSUPPORTED_SCAN` | 否 | scan 模块不存在 |
| `UNSUPPORTED_PROBE` | 否 | probe 模块不存在 |
| `TARGET_INVALID` | 否 | 目标 IP/范围非法 |
| `PERMISSION_DENIED` | 否 | raw socket/Npcap 权限 |
| `FIREWALL_RULES_MISSING` | 否 | Linux RST/ICMP 规则缺失 |
| `OUTPUT_WRITE_FAILED` | 否 | 输出写入/关闭失败 |
| `IO_ERROR` | 是 | 临时文件/IO 失败 |
| `CONFIG_ERROR` | 否 | 配置被拒绝 |
| `SCAN_TIMEOUT` | 是 | job 超时 |
| `SCAN_CANCELLED` | 否 | job 被取消 |
| `JOB_NOT_FOUND` | 否 | job 不存在 |
| `JOB_ALREADY_RUNNING` | 是 | job 已运行 |
| `JOB_LIMIT_REACHED` | 是 | 并发限制 |
| `UNSUPPORTED_OPERATION` | 否 | 操作不支持 |
| `NOT_FOUND` | 否 | 对象不存在 |
| `INVALID_STATE` | 否 | 生命周期状态错误 |
| `INTERNAL_ERROR` | 否 | 内部错误 |

## 规则

- 错误码大写且稳定，不做本地化。
- `retryable` 是给 Agent 的提示。
- 只有存在真实返回路径时才加入；生命周期错误码在 job/timeout 模型中启用。
- 尚未细分的运行时错误暂用 `INTERNAL_ERROR`。
## 当前行为

- `TARGET_INVALID`：单个 IP、CIDR/range 语法错误在 CLI 解析前拒绝。
- `FIREWALL_RULES_MISSING`：`--scan-request` 模式缺少 Linux RST/ICMP 规则时
  直接中止扫描；普通 CLI 仍只是警告。
- `PERMISSION_DENIED`：由 raw socket/PCAP 权限失败设置；其他 NIC 失败仍可能
  是 `INTERNAL_ERROR`。
- `OUTPUT_WRITE_FAILED`：覆盖输出模块初始化和打开失败；扫描过程中的每次写入
  失败尚未全部映射。
