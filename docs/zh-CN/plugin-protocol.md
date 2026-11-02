# 插件协议（草案，Go sidecar）

[English](../plugin-protocol.md) · **中文**

状态：Go sidecar 的设计草案。核心**没有 C 插件 ABI**，也不做运行时插件加载。

## 为什么用 sidecar

Xtate 的数据包路径是 C，且性能敏感。Go 适合输出后处理、聚合、编排、UI 和
AI/MCP 适配，但不适合每包回调。边界是进程，不是共享库。

```text
xtate (C) ── NDJSON / JSON-RPC ──> xtate-plugin (Go)
```

## 协议形态

- 传输：stdio 或本地 socket；默认不监听远程地址；
- 结果流：每行一个 JSON 对象；控制面用 JSON-RPC 2.0；
- 版本：插件清单声明协议主/次版本和能力列表；
- 能力示例：`result.consume`、`scan.start`、`scan.stop`、`module.list`、
  `result.summary`；
- 权限：目标访问、文件路径、网络访问和速率限制由核心声明/校验。

## 数据边界

C 侧只暴露**序列化值**，不暴露指针：

- 目标地址/端口/协议；
- 结果级别、分类、原因、时间戳；
- `OutItem` 已有的 key/value 结果链；
- 错误码/消息和 correlation id。

`OutItem` 仍是 C 内部类型。未来由 `result-json` writer 映射成带版本的信封；
Go 侧不解引用 C 结构体。

## 核心接入点

1. **结果流**：输出模块把结果写成 NDJSON，插件消费；不需要改热路径。
2. **控制面**：可选的 start/stop/status/module list JSON-RPC；扫描仍在 C 中执行。
3. **可选扫描编排**：插件可生成命令/目标并读取结果，但不构造数据包。

## 第一版非目标

- 在 Tx/Rx/handle 线程里回调 Go；
- 承诺 C ABI 兼容；
- 把任意 Go 插件加载进 C 进程；
- 把原始数据包缓冲区暴露给插件。

## C 侧保持可扩展的规则

- 结果类型保持 POD，跨边界不传指针。
- 不把 `XConf`、`OutConf`、模块注册表变成公开 ABI。
- 序列化信封带版本；未知字段忽略。
- 输出序列化与数据包处理分离。
- 插件提供的目标/命令按外部输入校验。

## 下一步

1. 定义带版本的结果信封和错误 schema；
2. 增加消费 NDJSON 并聚合的 Go 示例；
3. 增加小型 JSON-RPC 控制示例；
4. 再评估跨语言 probe 的 C ABI。
