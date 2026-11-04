# HTTP 探针审计与重写计划

**中文** · [English](../http-probes-audit.md)

这是对 HTTP/1 探针的评估，不是承诺立刻全部重写。HTTP/2 是另一条线：
`h2c` 是明文 prior knowledge，`h2` 是通过 HLTCP 的 TLS/ALPN h2。

状态：第一轮重写已实现。`http` 和 `http-state` 现在都使用
`proto-http-result` 输出 status/reason/version、响应头、Content-Length 和
有限 body/chunked 信息。请求构造器仍然重复，抽取共享构造器是后续工作。

## 当前探针

| 探针 | 类型 | 约行数 | 作用 |
|:---|:---:|---:|:---|
| `http` | tcp | 700 | 无状态请求/响应 banner |
| `http-state` | state | 895 | HLTCP 请求/响应 banner |
| `get-state` | state | 112 | 最小调试 GET |
| `h2c` | tcp | 329 | 明文 HTTP/2 framing |
| `h2` | state | 646 | HLTCP 上的 TLS/ALPN h2 |

`http` 和 `http-state` 的配置表、请求构造、header 替换和响应输出高度重复。
`http-state` 能做有状态发送，但响应路径仍然是 regex/banner 思路，不是 HTTP
响应解析器。

## 发现的问题

### 1. 请求构造重复

两个探针各自维护：

- method、URL、version、Host/User-Agent；
- 自定义 header、cookie、remove-header；
- 动态 Host；
- Content-Length；
- IPv4/IPv6 请求缓冲区。

改一边很容易漏另一边。

### 2. 响应不是 HTTP-aware

响应主要是：

- 可选 PCRE2 匹配；
- 可选原始 banner/UTF-8/data；
- `all-banner` 分段。

没有结构化输出：

- 状态码和 reason；
- HTTP 版本；
- 响应 header；
- Content-Length；
- chunked；
- trailer；
- body 边界；
- 重定向。

研究扫描当然要保留原始字节，但也需要结构化解析器，否则 HTTP 结果不可比较、
不可测试。

### 3. `http-state` 不是真正的 HTTP 状态机

它能通过 HLTCP 发请求、收多段数据，但没有响应阶段模型。更准确的说法是
“有状态传输 + banner/segment 收集”，不是 HTTP/1.1 会话解析器。

### 4. `h2c`/`h2` 不应并入这次重写

`h2c` 是明文 HTTP/2 framing；`h2` 是 `tls-state` 上的 TLS/ALPN h2。它们共享
HTTP/2 frame 概念，不共享 HTTP/1 请求/响应解析器。

## 跨 TCP 段的 chunked 响应

`http` 是无状态探针，handler 只看到一个 segment；如果没有扫描器端逐目标状态，
它无法重组 chunked body。这与 ZBanner 设计冲突，因此无状态探针应只报告首段
status/header 和已捕获字节，不能声称得到完整 chunked body。

`http-state` 已有 TCB 和 `ProbeState`，技术上可以实现有界 chunked 状态机：
累积 header，之后把每个 body segment 喂给 `ph_decode_chunked`，并设置
`--max-header`/`--max-body` 和 segment 上限。它对 body 完整性重要的场景
（流式 API、无 Content-Length、研究指纹）有用；对端口/服务 banner 分类不是
必需。

代价：每个活跃 HLTCP 连接一个有界 buffer 和 decoder，外加超时和 partial
chunk 测试。HLTCP 可以承受，但 `http`/ZBanner 不值得。建议只在 `http-state`
里实现，作为 `--record-body` 或 `--chunked` 的可选项，并设上限；`http` 保持
首段。

## 建议

**不要一上来全部重写。** 按顺序重构：

1. 给当前 `http`/`http-state` 输出加特征测试（原始字节、regex、all-banner、
   `--header`、cookie、动态 Host）。
2. 抽出共享的 HTTP/1 请求构造器，两个探针复用。
3. 新增有界 HTTP/1 响应解析器：
   - 状态行/header；
   - Content-Length 和 chunked；
   - header/body 上限；
   - 保留 raw 模式。
4. 先接入 `http-state`，再让 `http` 复用同一个解析器。
5. `get-state` 保持最小调试探针，除非能复用解析器而不破坏简单性。
6. 加本地 lab：正常、chunked、截断、畸形、重定向、HTTP/1.0、keep-alive。

## 建议参数

共享参数应明确：

- `--raw` / `--banner` / `--data` / `--utf8`；
- `--max-header` / `--max-body` / `--max-segments`；
- `--follow-redirect`（有界，默认关闭）；
- `--record-status` / `--record-headers` / `--record-body`；
- 尽量保持现有 `--match`/`--regex` 行为不变。

除非用户明确要求，不要静默解压 gzip 或解码 chunked 内容。

## 验收

- 现有 raw/regex 行为不回归。
- `http-state` 对正常响应输出 `status`、`http_version`、`header_count`、
  选定 header 和 body length。
- chunked 和 Content-Length body 与参考服务器一致。
- 畸形/截断响应明确失败，不静默成功。
- 测试本地、确定。
- `h2c`/`h2` 保持独立，不被静默当成 HTTP/1 fallback。

## 优先级

P2/P3。先有参数解析器测试套件，再做重写，这样才能用旧 raw 行为做对照，而不是
盲目替换。
