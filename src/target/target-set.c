#include "target-set.h"
#include "../as/as-query.h"

#include <string.h>
#include <ctype.h>

#include "target-parse.h"
#include "target-rangev4.h"
#include "target-rangev6.h"
#include "target-rangeport.h"

#include "../util-out/logger.h"

void targetset_apply_excludes(TargetSet *targets, TargetSet *exclude) {
    rangelist_exclude(&targets->ipv4, &exclude->ipv4);
    range6list_exclude(&targets->ipv6, &exclude->ipv6);
    rangelist_exclude(&targets->ports, &exclude->ports);
}

void targetset_optimize(TargetSet *targets) {
    rangelist_optimize(&targets->ipv4);
    range6list_optimize(&targets->ipv6);
    rangelist_optimize(&targets->ports);

    targets->count_ports    = rangelist_count(&targets->ports);
    targets->count_ipv4s    = rangelist_count(&targets->ipv4);
    targets->count_ipv6s    = range6list_count(&targets->ipv6);
    targets->ipv4_threshold = targets->count_ipv4s * targets->count_ports;
}

void targetset_pick(const TargetSet *targetset, uint64_t index, ipaddress *addr,
                    unsigned *port) {
    /*
     * We can return either IPv4 or IPv6 addresses
     */
    if (index < targetset->ipv4_threshold) {
        addr->version = 4;
        addr->ipv4 =
            rangelist_pick(&targetset->ipv4, index % targetset->count_ipv4s);
        *port =
            rangelist_pick(&targetset->ports, index / targetset->count_ipv4s);
    } else {
        index -= targetset->ipv4_threshold;
        addr->version = 6;
        addr->ipv6    = range6list_pick(&targetset->ipv6,
                                        index % targetset->count_ipv6s.lo);
        *port         = rangelist_pick(&targetset->ports,
                                       index / targetset->count_ipv6s.lo);
    }
}

bool targetset_has_ip(const TargetSet *targetset, ipaddress ip) {
    if (ip.version == 6)
        return range6list_is_contains(&targetset->ipv6, ip.ipv6);
    else
        return rangelist_is_contains(&targetset->ipv4, ip.ipv4);
}

bool targetset_has_port(const TargetSet *targetset, unsigned port) {
    return rangelist_is_contains(&targetset->ports, port);
}

bool targetset_has_any_ipv4(const TargetSet *targetset) {
    return targetset->ipv4.list_len != 0;
}

bool targetset_has_any_ipv6(const TargetSet *targetset) {
    return targetset->ipv6.list_len != 0;
}

bool targetset_has_any_ports(const TargetSet *targetset) {
    return targetset->ports.list_len != 0;
}

int targetset_add_ip_str(TargetSet *targetset, const char *string) {
    const char *ranges     = string;
    size_t      offset     = 0;
    size_t      max_offset = strlen(ranges);

    while (offset < max_offset) {
        struct Range  range;
        struct Range6 range6;
        int           err;

        /* Grab the next IPv4 or IPv6 range */
        err = target_parse_range(ranges, &offset, max_offset, &range, &range6);
        switch (err) {
            case Ipv4_Address:
                rangelist_add_range(&targetset->ipv4, range.begin, range.end);
                break;
            case Ipv6_Address:
                range6list_add_range(&targetset->ipv6, range6.begin,
                                     range6.end);
                break;
            default:
                offset = max_offset; /* An error means skipping the rest of the
                                        string */
                return 1;
        }
        while (offset < max_offset &&
               (isspace(ranges[offset] & 0xFF) || ranges[offset] == ','))
            offset++;
    }
    return 0;
}

int targetset_add_asn4_str(TargetSet             *targetset,
                           const struct AS_Query *as_query,
                           const char            *asn_str) {
    bool   added      = false;
    size_t offset     = 0;
    size_t max_offset = strlen(asn_str);

    while (offset < max_offset) {
        while (offset < max_offset && !isdigit(asn_str[offset])) {
            if (asn_str[offset] != ',' && !isspace(asn_str[offset])) {
                LOG(LEVEL_ERROR, "(%s) invalid ASN string: %s\n", __func__,
                    asn_str);
                return -1;
            }

            offset++;
        }

        if (offset >= max_offset)
            break;

        unsigned asn = 0;
        while (asn_str[offset] && isdigit(asn_str[offset])) {
            asn = asn * 10 + (asn_str[offset] - '0');
            offset++;
        }

        if (!as_query_add_as_to_range(as_query, &targetset->ipv4, asn)) {
            return -1;
        } else {
            added = true;
        }
    }

    if (added)
        return 0;
    else
        return -1;
}

int targetset_add_asn6_str(TargetSet             *targetset,
                           const struct AS_Query *as_query,
                           const char            *asn_str) {
    bool   added      = false;
    size_t offset     = 0;
    size_t max_offset = strlen(asn_str);

    while (offset < max_offset) {
        while (offset < max_offset && !isdigit(asn_str[offset])) {
            if (asn_str[offset] != ',' && !isspace(asn_str[offset])) {
                LOG(LEVEL_ERROR, "(%s) invalid ASN string: %s\n", __func__,
                    asn_str);
                return -1;
            }

            offset++;
        }

        if (offset >= max_offset)
            break;

        unsigned asn = 0;
        while (asn_str[offset] && isdigit(asn_str[offset])) {
            asn = asn * 10 + (asn_str[offset] - '0');
            offset++;
        }

        if (!as_query_add_as_to_range6(as_query, &targetset->ipv6, asn)) {
            return -1;
        } else {
            added = true;
        }
    }

    if (added)
        return 0;
    else
        return -1;
}

int targetset_add_port_str(TargetSet *targets, const char *string,
                           unsigned proto_offset) {
    unsigned is_error = 0;
    rangelist_parse_ports(&targets->ports, string, &is_error, proto_offset);
    if (is_error)
        return 1;
    else
        return 0;
}

void targetset_rm_all(TargetSet *targets) {
    rangelist_rm_all(&targets->ipv4);
    rangelist_rm_all(&targets->ports);
    range6list_rm_all(&targets->ipv6);
    targets->count_ipv4s    = 0;
    targets->count_ipv6s.hi = 0;
    targets->count_ipv6s.lo = 0;
    targets->count_ports    = 0;
    targets->ipv4_threshold = 0;
}

void targetset_rm_ip(TargetSet *targets) {
    rangelist_rm_all(&targets->ipv4);
    range6list_rm_all(&targets->ipv6);
    targets->count_ipv4s    = 0;
    targets->count_ipv6s.hi = 0;
    targets->count_ipv6s.lo = 0;
    targets->ipv4_threshold = 0;
}

void targetset_rm_port(TargetSet *targets) {
    rangelist_rm_all(&targets->ports);
    targets->ipv4_threshold = 0;
    targets->count_ports    = 0;
}

int targetset_selftest() {
    TargetSet targets  = {.ipv4 = {0}, .ipv6 = {0}, .ports = {0}};
    TargetSet excludes = {.ipv4 = {0}, .ipv6 = {0}, .ports = {0}};
    int128_t  count;
    int       line;
    int       err;

    rangelist_parse_ports(&targets.ports, "80", 0, 0);

    /* First, create a list of targets */
    line = __LINE__;
    err =
        targetset_add_ip_str(&targets, "2607:f8b0:4002:801::2004/124,1111::1");
    if (err)
        goto fail;

    /* Second, create an exclude list */
    line = __LINE__;
    err  = targetset_add_ip_str(&excludes,
                                "2607:f8b0:4002:801::2004/126,1111::/16");
    if (err)
        goto fail;

    /* Third, apply the excludes, causing ranges to be removed
     * from the target list */
    targetset_apply_excludes(&targets, &excludes);

    /* Now make sure the count equals the expected count */
    line  = __LINE__;
    count = targetset_count(&targets);
    if (count.hi != 0 || count.lo != 12)
        goto fail;

    return 0;
fail:
    LOG(LEVEL_ERROR, "(%s) line=%d\n", __func__, line);
    return 1;
}