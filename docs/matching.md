# HTTP response matching

**English** · [中文](zh-CN/matching.md)

The HTTP/1 probes (`http`, `http-state`), HTTP/2 (`h2`) and HTTP/3
(`http3-state`) share a matching model. Matching is optional: without
`--keyword` or `--regex` the probe reports the protocol result normally.

## Options

| Option | Meaning |
|:---|:---|
| `--keyword TEXT` | Literal search in the selected scope. Does not require PCRE2. |
| `--regex PATTERN` | PCRE2 search in the selected scope. Requires a PCRE2 build. |
| `--match-scope all\|headers\|body` | Scope; default `all`. |
| `--case-insensitive` / `--insensitive` | Case-insensitive keyword/regex. |
| `--include-newlines` / `--newlines` | PCRE2 DOTALL: dot matches newlines. |

`--keyword` and `--regex` are mutually exclusive.

## Scopes

- `headers`: HTTP/1 status/header section, decoded HTTP/2 headers, or decoded
  HTTP/3 headers. For HTTP/3 this includes `:status`.
- `body`: response body bytes.
- `all`: the complete canonical response. HTTP/1 uses the received bytes;
  H2/H3 use `headers + blank line + body`.

HTTP/1 header/body splitting uses the structured response parser. If parsing
fails, the raw response is used as `headers` and the body is empty.

With the stateless `http` probe, `body` only contains what arrived in the first
response segment/banner. Use `http-state` when the whole HTTP body is required.

## Output and status

If a matcher is configured:

```text
http_match / http3_match / h2_match: 1 or 0
http_match_kind / http3_match_kind / h2_match_kind: keyword|regex
http_match_scope / ...: all|headers|body
http_match_text / ...: matched text (bounded)
```

A match sets the result to success and classification `matched`; no match sets
failure and classification `not matched`, with reason `no match`. The protocol
details (status, headers, body, certificate/QUIC evidence) are still emitted so
a failed match remains diagnosable.

## Notes

- Matching is on decoded response data, not on compressed HTTP/3 frames.
- HTTP/3 header matching is bounded by `--max-headers`; the response header
  count is always reported, but headers beyond the retained limit are not
  matchable.
- HTTP/2 header matching is bounded by the probe's header buffer. `h2` decodes
  the HPACK static table, literal header fields and Huffman-coded string
  literals; dynamic-table insertions and a full stream state machine are not
  implemented.
- HTTP/1 regex historically matched the raw response; `all` preserves that
  behavior. Use `--match-scope headers|body` for precise matching.
