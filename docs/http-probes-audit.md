# HTTP probe audit and rewrite plan

**English** · [中文](zh-CN/http-probes-audit.md)

This is an assessment of the HTTP/1 probes, not a commitment to a full rewrite.
HTTP/2 is separate: `h2c` is cleartext prior knowledge and `h2` is TLS/ALPN h2
through HLTCP.

Status: the first rewrite pass is implemented. Both `http` and `http-state` now
use `proto-http-result` for status/reason/version, response headers,
Content-Length, and bounded body/chunked metadata. The request builders are
still duplicated; extracting them remains follow-up work.

## Current inventory

| Probe | Type | Lines (approx.) | Main role |
|:---|:---:|---:|:---|
| `http` | tcp | 700 | Stateless request/response banner |
| `http-state` | state | 895 | HLTCP request/response banner |
| `get-state` | state | 112 | Minimal debug GET |
| `h2c` | tcp | 329 | Cleartext HTTP/2 framing |
| `h2` | state | 646 | TLS/ALPN h2 via HLTCP |

`http` and `http-state` contain nearly duplicate configuration tables, request
construction, header replacement and response reporting. `http-state` is a
request sender, but its response path is still regex/banner-oriented rather
than an HTTP response parser.

## Findings

### 1. Request building is duplicated

Both probes independently maintain:

- method, URL, version, Host/User-Agent;
- custom headers, cookies, remove-header lists;
- dynamic Host formatting;
- Content-Length handling;
- IPv4/IPv6 request buffers.

A change in one probe can drift from the other.

### 2. Response parsing is not HTTP-aware

The response path mostly does:

- optional PCRE2 match;
- optional raw banner/UTF-8/data fields;
- `all-banner` segment handling.

It does not provide a structured view of:

- status code and reason phrase;
- HTTP version;
- response headers;
- Content-Length;
- chunked transfer encoding;
- trailers;
- body boundaries;
- redirects.

For a research scanner, raw bytes must remain available, but a structured
parser is needed to make HTTP results comparable and testable.

### 3. `http-state` is not a true stateful HTTP parser

It can send a request over HLTCP and collect multiple segments, but it does not
model response phases. It is better described as stateful transport plus
banner/segment collection, not an HTTP/1.1 conversation parser.

### 4. `h2c`/`h2` should not be folded into this rewrite

`h2c` is cleartext HTTP/2 framing; `h2` is TLS/ALPN h2 through `tls-state`.
They share HTTP/2 frame concepts, not the HTTP/1 request/response parser.

## Recommendation

**Do not start with a full rewrite.** Refactor in this order:

1. Add characterization tests for the current `http` and `http-state` output
   (raw bytes, regex match, all-banner, `--header`, cookies, dynamic Host).
2. Extract a shared HTTP/1 request builder used by both probes.
3. Add a bounded HTTP/1 response parser:
   - status line and headers;
   - Content-Length and chunked body;
   - headers/body size limits;
   - raw mode retained.
4. Integrate it into `http-state` first; `http` then reuses the same parser for
   stateless responses.
5. Keep `get-state` as a minimal debug probe unless it can reuse the parser
   without losing its simplicity.
6. Add local lab servers for normal, chunked, truncated, malformed, redirect,
   HTTP/1.0 and keep-alive cases.

## Proposed controls

Shared parameters should remain explicit:

- `--raw` / `--banner` / `--data` / `--utf8`;
- `--max-header` / `--max-body` / `--max-segments`;
- `--follow-redirect` (bounded, off by default);
- `--record-status` / `--record-headers` / `--record-body`;
- `--match` / `--regex` behavior unchanged where possible.

Do not silently decode gzip/chunked content unless the user asked for it.

## Acceptance

- Existing raw/regex behavior does not regress.
- `http-state` emits `status`, `http_version`, `header_count`, selected headers
  and body length for a normal response.
- Chunked and Content-Length bodies agree with a reference server.
- Malformed/truncated responses produce explicit failures, not silent success.
- Tests are local and deterministic.
- `h2c`/`h2` remain separate and are not silently used as HTTP/1 fallbacks.

## Priority

P2/P3. Do this after the current parser test suite exists, so a rewrite can be
checked against old raw behavior rather than replacing it blindly.
