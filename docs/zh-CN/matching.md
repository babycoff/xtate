# HTTP 响应匹配

[English](../matching.md) · **中文**

HTTP/1 探针（`http`、`http-state`）、HTTP/2（`h2`）和 HTTP/3（`http3-state`）
共用一套匹配模型。匹配是可选的：没有 `--keyword`/`--regex` 时按协议正常输出。

## 参数

| 参数 | 含义 |
|:---|:---|
| `--keyword TEXT` | 在选定范围内做字面量查找，不依赖 PCRE2。 |
| `--regex PATTERN` | 在选定范围内做 PCRE2 正则匹配，需要 PCRE2 构建。 |
| `--match-scope all\|headers\|body` | 匹配范围，默认 `all`。 |
| `--case-insensitive` / `--insensitive` | 关键字/正则忽略大小写。 |
| `--include-newlines` / `--newlines` | PCRE2 DOTALL，点号匹配换行。 |

`--keyword` 与 `--regex` 互斥。

## 范围

- `headers`：HTTP/1 状态行+header，HTTP/2 解码后的 header，或 HTTP/3 解码后的
  header；HTTP/3 包含 `:status`。
- `body`：响应 body。
- `all`：完整规范响应。HTTP/1 使用收到的原始字节；H2/H3 使用
  `headers + 空行 + body`。

HTTP/1 的 header/body 由结构化响应解析器切分；解析失败时把原始响应作为
`headers`，body 为空。

无状态的 `http` 探针的 `body` 只包含首个响应段/banner 中到达的内容；需要完整
HTTP body 时请用 `http-state`。

## 输出与状态

配置匹配后输出：

```text
http_match / http3_match / h2_match: 1 或 0
http_match_kind / http3_match_kind / h2_match_kind: keyword|regex
http_match_scope / ...: all|headers|body
http_match_text / ...: 匹配文本（有界）
```

命中时 success，classification 为 `matched`；未命中时 failure，
classification 为 `not matched`，reason 为 `no match`。协议细节
（status/header/body、证书/QUIC 证据）仍然输出，失败结果可诊断。

## 注意

- 匹配针对解码后的响应数据，不是压缩后的 HTTP/3 帧。
- HTTP/3 header 匹配受 `--max-headers` 限制；总数始终输出，但超出保留上限的
  header 不参与匹配。
- HTTP/2 header 匹配受探针 header 缓冲区限制；H2 当前只支持 static/literal
  HPACK。
- HTTP/1 以前的 regex 是对原始响应匹配；`all` 保持该行为，精确匹配请用
  `--match-scope headers|body`。
