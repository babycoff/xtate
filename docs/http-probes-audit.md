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
| `http` | tcp | 759 | Stateless request/response banner |
| `http-state` | state | 950 | HLTCP request/response banner |
| `get-state` | state | 113 | Minimal debug GET |
| `h2c` | tcp | 329 | Cleartext HTTP/2 framing |
| `h2` | state | 978 | TLS/ALPN h2 via HLTCP |

`http` and `http-state` contain nearly duplicate configuration tables, request
construction, header replacement and response reporting. `http-state` is a
request sender whose response path wraps `proto-http-result` (status/version,
headers, Content-Length, bounded body/chunked metadata) and still adds
regex/banner-oriented fields.

## Findings

### 1. Request building is duplicated

Both probes independently maintain:

- method, URL, version, Host/User-Agent;
- custom headers, cookies, remove-header lists;
- dynamic Host formatting;
- Content-Length handling;
- IPv4/IPv6 request buffers.

A change in one probe can drift from the other.

### 2. Response parsing is only partly HTTP-aware

Since the first rewrite pass, the response path calls `proto-http-result` and
reports:

- status code and reason phrase;
- HTTP version;
- response headers;
- Content-Length;
- bounded chunked metadata.

It still does not provide:

- trailers;
- body boundaries across segments;
- redirects (no follow-up request);
- chunked body reassembly in the stateless `http` probe.

The raw/banner/`all-banner` fields also remain. For a research scanner, raw
bytes must stay available; trailers, redirects and a complete body model need
more parser work to make HTTP results comparable.

### 3. `http-state` is not a true stateful HTTP parser

It can send a request over HLTCP and collect multiple segments, but it does not
model response phases. It is better described as stateful transport plus
banner/segment collection, not an HTTP/1.1 conversation parser.

### 4. `h2c`/`h2` should not be folded into this rewrite

`h2c` is cleartext HTTP/2 framing; `h2` is TLS/ALPN h2 through `tls-state`.
They share HTTP/2 frame concepts, not the HTTP/1 request/response parser.

## Chunked responses across TCP segments

`http` is stateless and its handler sees one segment; it cannot reassemble a
chunked body without scanner-side per-target state. That would contradict the
ZBanner design, so the stateless probe should report the first-segment
status/headers and the captured bytes, not claim a complete chunked body.

`http-state` already has a TCB and `ProbeState`, so a bounded chunked state
machine is technically possible: accumulate header bytes, then feed each body
segment through `ph_decode_chunked`, with `--max-header`/`--max-body` and
segment limits. It is useful when body completeness matters (streaming APIs,
no Content-Length, research fingerprints); it is not necessary for port/service
banner classification.

Cost: one bounded buffer and decoder per active HLTCP connection, plus timeout
and partial-chunk tests. This is acceptable for HLTCP but not justified for
`http`/ZBanner. Recommended: implement only in `http-state`, opt-in
(`--record-body` or `--chunked`), capped; leave `http` first-segment.

## Recommendation

**Do not start with a full rewrite.** Refactor in this order:

1. Add characterization tests for the current `http` and `http-state` output
   (raw bytes, regex match, all-banner, `--header`, cookies, dynamic Host).
2. Extract a shared HTTP/1 request builder used by both probes.
3. Add a bounded HTTP/1 response parser: status line and headers,
   Content-Length and chunked body, headers/body size limits, raw mode retained.
   Partly implemented via `proto-http-result`; trailers, redirects and a
   complete cross-segment body model remain.
4. Integrate it into `http-state` first; `http` then reuses the same parser for
   stateless responses. Implemented for status/version/headers/Content-Length
   and bounded chunked metadata in both probes.
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
