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

`banner idx` is the zero-based dedup repeat counter for the banner key: the
first banner packet seen for the flow/type after the entry is created is 0;
every later matching packet increments it, including retransmissions and new
segments. It is not the TCP segment ordinal and can restart at 0 after dedup
eviction; with dedup disabled it stays 0. The docs now state this exactly.
`banner seqno` is the exact TCP sequence number and is the field for offline
ordering/deduplication. `banner idx` is retained for compatibility and as an
approximate all-banner counter, not as the primary segment index.

### 4. `AfterFirstReply` is limited to the banner branch

The implementation fans out only from the banner-with-data branch; ACK-only and
RST first responses do not trigger slots. This is correct for JARM, and the
generic slot-plan docs now explicitly narrow the ZBanner meaning to the first
banner/data segment. No accepted-response predicate is planned.

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

### 7. Declared versus actual payload length

The code now computes the actual `make_payload_cb()` length during validation
and uses it for banner/ACK acknowledgement checks, so a declared/actual mismatch
no longer silently invalidates the response. The SYN-ACK path still warns and
emits `payload_len_declared` / `payload_len_actual` on mismatch. The probe
contract remains "declared length must equal actual"; a future probe/test should
reject inconsistent probes rather than only diagnosing them.

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
- Banner/ACK validation now uses the actual generated payload length; mismatch
  diagnostics are attached to the SYN-ACK result.

## Remaining work

- `AfterFirstReply` is intentionally narrowed to the first banner/data segment;
  ACK-only/RST first responses do not fan out. The docs now state this ZBanner
  semantics explicitly.
- `banner idx` is now documented as the zero-based dedup repeat counter, not a
  TCP segment ordinal; use `banner seqno` for offline ordering.
- Payload declared/actual mismatch is diagnosed and no longer silently breaks
  validation; a probe contract violation is still not a hard startup error.
- Dedup pressure still makes limit/floor approximate.
- The pcap matrix in `tests/zbanner/` covers SYNACK/RST, banner, retransmit,
  all-banner limit, wrong ACK and the Lua payload-mismatch fixture.

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
