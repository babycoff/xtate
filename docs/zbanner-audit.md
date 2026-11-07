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

### 2. `all-banner-limit` truncation flag is off by one

The RST/truncated condition uses `repeats >= limit - 1`. With
`--all-banner-limit 8`, the eighth allowed segment sets `truncated` even though
no ninth segment has been dropped. With limit 1 the first segment is marked as
truncated. The no-output threshold uses `repeats >= limit`, so the two checks
disagree about the boundary.

Desired semantics:

- record `limit` segments (repeats 0..limit-1);
- send RST when the scanner has enough segments;
- set `truncated` only when a segment is actually discarded beyond the limit;
- keep the limit/floor definitions in one helper.

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

### 6. Minor: zero-length payload with `with-ack`

When `--with-ack` is enabled and the probe declares zero payload, the code can
send an empty ACK and then another ACK with no data. The second packet is
harmless but unnecessary. Gate the extra ACK on `payload_len > 0`.

### 7. Minor: declared versus actual payload length

The code warns when `make_payload_cb` returns a different length from
`get_payload_length_cb`, but still sends the actual payload. Dedup validation for
banner/ACK uses the declared length, so the response may not validate. This is
better treated as a probe contract error (or use the actual length consistently)
than a warning-only mismatch.

### 8. Setter validation is thin

`--all-banner-limit` and `--all-banner-floor` are parsed as unsigned values with
no upper bound or explicit relation check. Extremely large values make the
boundary tests meaningless. Add bounded validation and document defaults.

## What is already good

- Source-port index validation before probe callbacks.
- Payload size checks against `ZBANNER_PAYLOAD_MAX` and packet-buffer length.
- Separate RST/SYN-ACK/banner/ACK branches with explicit output reasons.
- all-banner warnings for small TCP window, snaplen and max packet length.
- Slot count/source-port capacity check at init.

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
