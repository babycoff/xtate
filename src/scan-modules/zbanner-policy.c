#include "zbanner-policy.h"

#include <limits.h>
#include <stddef.h>

ZBAllBannerDecision zb_all_banner_decide(unsigned repeats, unsigned limit,
                                         unsigned floor) {
    ZBAllBannerDecision d = {0};
    unsigned ordinal = (repeats == UINT_MAX) ? UINT_MAX : repeats + 1;

    if (floor && ordinal < floor)
        return d;

    if (limit && ordinal > limit) {
        d.truncated = true;
        return d;
    }

    d.record = true;
    d.send_ack = true;
    if (limit && ordinal == limit) {
        d.send_rst = true;
        d.truncated = true;
    }
    return d;
}

static bool policy_check(unsigned repeats, unsigned limit, unsigned floor,
                         bool record, bool rst, bool ack, bool trunc) {
    ZBAllBannerDecision d = zb_all_banner_decide(repeats, limit, floor);
    return d.record == record && d.send_rst == rst && d.send_ack == ack &&
           d.truncated == trunc;
}

bool zbanner_policy_selftest(void) {
    /* limit 8: record eight segments, RST on the eighth, truncate only the
     * ninth and later. */
    if (!policy_check(0, 8, 0, true, false, true, false) ||
        !policy_check(6, 8, 0, true, false, true, false) ||
        !policy_check(7, 8, 0, true, true, true, true) ||
        !policy_check(8, 8, 0, false, false, false, true) ||
        !policy_check(9, 8, 0, false, false, false, true))
        return false;

    /* limit 1 boundary. */
    if (!policy_check(0, 1, 0, true, true, true, true) ||
        !policy_check(1, 1, 0, false, false, false, true))
        return false;

    /* floor is 1-based: floor 2 suppresses the first delivery. */
    if (!policy_check(0, 0, 2, false, false, false, false) ||
        !policy_check(1, 0, 2, true, false, true, false) ||
        !policy_check(0, 0, 1, true, false, true, false))
        return false;

    /* limit and floor together. */
    if (!policy_check(0, 8, 3, false, false, false, false) ||
        !policy_check(1, 8, 3, false, false, false, false) ||
        !policy_check(2, 8, 3, true, false, true, false) ||
        !policy_check(7, 8, 3, true, true, true, true) ||
        !policy_check(8, 8, 3, false, false, false, true))
        return false;

    /* Unlimited, no floor. */
    if (!policy_check(0, 0, 0, true, false, true, false) ||
        !policy_check(1000000, 0, 0, true, false, true, false))
        return false;

    return true;
}
