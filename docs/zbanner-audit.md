# ZBanner audit and simplification

**English** · [中文](zh-CN/zbanner-audit.md)

`zbanner` is the stateless TCP banner path and the largest scan-module file
(`src/scan-modules/zbanner-scan.c`, about 1200 lines). This is an audit plan, not
a claim that the current behavior is broken in every case. The goal is to make
the state machine explicit and testable without losing the stateless model.

## Findings

### 1. `AfterFirstReply` can fan out more than once

`ProbeSlot_AfterFirstReply` sends slots 1..N when slot 0 returns a banner. The
trigger is in the banner branch and has no one-shot guard or per-target group
state. A multi-segment response (or several dedup-distinct banner deliveries)
can execute the fan-out more than once, producing duplicate SYNs for slots
1..N. JARM normally returns one ServerHello, so this is not always visible, but
it is a logic issue for slow/multi-segment targets.

Possible fixes:

- require the first accepted banner (`valid_pkt->repeats == 0`) before fan-out;
- or add a bounded per-target one-shot marker;
- or move fan-out into a connection-local plan when that exists.

### 2. all-banner limit/floor boundaries were implicit

The previous code used `repeats >= limit - 1` for the RST/truncated trigger and
`repeats >= limit` for no-output. The documentation defines `truncated: 1` on
the segment that triggers the limit, so the old behavior was intentional, not
an off-by-one bug. The risk was that the rules were spread across the branch and
easy to change inconsistently.

This pass centralizes them in `zbanner-policy.c` and tests:

- record `limit` segments (ordinals 0..limit-1);
- send RST on the limit-triggering segment;
- set `truncated` on that segment (documented behavior);
- suppress further segments and do not ACK them;
- floor suppresses ordinals below the 1-based floor value.

### 3. `banner idx` is not a segment index

`banner idx` is the dedup `repeats` counter, not the TCP segment index or the
sequence-number-derived position. Under dedup pressure it can be wrong.
`banner seqno` is the exact TCP sequence number and should be the field used
for offline segment ordering. Rename or document `banner idx` as an
approximate dedup count; do not use it as the primary segment index.

### 4. `AfterFirstReply` is limited to the banner branch

The generic slot plan says "after a response", but the implementation only
fans out from the banner-with-data branch. A first response that is ACK-only or
RST does not trigger slots. This is reasonable for JARM (TLS ServerHello), but
it is not the documented generic semantics. Either narrow the docs to "after
first banner/data" or add an explicit accepted-response predicate.

### 5. `all-banner-limit/floor` depend on approximate dedup

Both options use `valid_pkt->repeats`. The dedup table is best-effort and can
evict entries under load, so limits/floors are approximate. This is already
noted in the docs, but the code and tests should treat it as a documented
accuracy limit, not a precise segment counter. Prefer `banner seqno` for
ordering and add boundary tests.

### 6. `with-ack` and zero payload

The code already only sends the extra handshake ACK when `payload_len > 0`; a
zero-payload probe sends a single ACK. Keep this behavior and cover it in tests
so a future change does not add a redundant packet.

### 7. Minor: declared versus actual payload length

The code warns when `make_payload_cb` returns a different length from
`get_payload_length_cb`, but still sends the actual payload. Dedup validation for
banner/ACK uses the declared length, so the response may not validate. This is
better treated as a probe contract error (or use the actual length consistently)
than a warning-only mismatch.

### 8. Setter validation was thin

`--all-banner-limit` and `--all-banner-floor` are now bounded to
`0..1000000`, and a nonzero floor greater than a nonzero limit is rejected at
startup.

## What is already good

- Source-port index validation before probe callbacks.
- Payload size checks against `ZBANNER_PAYLOAD_MAX` and packet-buffer length.
- Separate RST/SYN-ACK/banner/ACK branches with explicit output reasons.
- all-banner warnings for small TCP window, snaplen and max packet length.
- Slot count/source-port capacity check at init.

## Implemented in this pass

- Response classification extracted into `zb_classify()`; `validate` and
  `handle` use the same event table.
- all-banner limit/floor/RST/ACK/truncated decisions extracted into
  `zb_all_banner_decide()` with a policy self-test.
- `AfterFirstReply` requires the first accepted banner (`repeats == 0`) before
  fan-out, preventing duplicate slot bursts on repeated/multi-segment banners.
  Caveat: this relies on the dedup `repeats` counter; with `--no-dedup-banner`
  or global `-nodedup`, `repeats` stays 0 and duplicate fan-out can still occur.
  A bounded one-shot table remains future work if that mode needs it.
- all-banner limit/floor bounds and floor<=limit validation added.
- Existing `with-ack` zero-payload behavior documented and preserved.

## Remaining work

- `AfterFirstReply` still triggers only from banner/data; ACK-only/RST first
  responses do not fan out. Decide whether to narrow the documented generic
  semantics or add an accepted-response predicate.
- `banner idx` remains approximate; use `banner seqno`.
- Payload declared/actual mismatch is still warning-only.
- Dedup pressure still makes limit/floor approximate.

## Suggested refactor

1. Extract a small response classifier returning an enum
   (`SYNACK`, `RST`, `BANNER`, `ACK`, `IGNORE`) plus a normalized result.
2. Put all-banner limit/floor/truncated/RST decisions in one helper with
   boundary tests.
3. Add a one-shot `AfterFirstReply` guard and test a multi-segment banner.
4. Keep `banner seqno` as the ordering field; demote `banner idx` to an
   approximate dedup counter in docs and output.
5. Add a regression matrix:
   - limit 1, 2, 8; floor 1, 2;
   - duplicate/retransmitted banners;
   - ACK-only and RST first responses;
   - payload-length mismatch;
   - IPv4 and IPv6;
   - `with-ack` with zero and non-zero payload.

## Non-goals

- Do not turn ZBanner into HLTCP or add per-target TCP state.
- Do not change the default output or firewall requirements as part of the
  refactor without a separate compatibility decision.
