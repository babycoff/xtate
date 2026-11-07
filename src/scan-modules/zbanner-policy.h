#ifndef ZBANNER_POLICY_H
#define ZBANNER_POLICY_H

#include <stdbool.h>

/*
 * Pure policy decisions for ZBanner. Keep this file free of packet, socket and
 * output dependencies so the boundary rules can be unit tested and reasoned
 * about independently from the scan callbacks.
 */

typedef struct ZBAllBannerDecision {
    bool record;
    bool send_rst;
    bool send_ack;
    bool truncated;
} ZBAllBannerDecision;

/*
 * |repeats| is the dedup repeat count: 0 for the first delivery of a segment.
 * |limit| 0 means unlimited. |floor| 0 means no floor; otherwise the first
 * accepted segment is ordinal |floor| (1-based).
 *
 * Semantics:
 *   ordinal = repeats + 1
 *   record    = ordinal >= floor && (limit == 0 || ordinal <= limit)
 *   send_rst  = limit != 0 && ordinal == limit
 *   send_ack  = record (all-banner ACKs only recorded segments)
 *   truncated = limit != 0 && ordinal >= limit
 *
 * "truncated" means the response was cut at the configured limit; the segment
 * that triggers the limit is marked, matching the documented ZBanner output.
 */
ZBAllBannerDecision zb_all_banner_decide(unsigned repeats, unsigned limit,
                                         unsigned floor);

/* Returns false if the policy boundary table does not hold. */
bool zbanner_policy_selftest(void);

#endif
