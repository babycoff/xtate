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

#define TARGET_COMPONENT_RANGE_MAX 65536

static int _component_parse_dec(const char *text, unsigned max, unsigned *out) {
    unsigned value = 0;

    if (*text == '\0')
        return 1;
    while (*text) {
        if (*text < '0' || *text > '9')
            return 1;
        {
            unsigned digit = (unsigned)(*text - '0');
            if (value > (max - digit) / 10)
                return 1;
            value = value * 10 + digit;
        }
        text++;
    }
    *out = value;
    return 0;
}

static int _component_parse_hex(const char *text, unsigned *out) {
    unsigned value = 0;
    unsigned digits = 0;

    if (*text == '\0')
        return 1;
    while (*text) {
        unsigned char c = (unsigned char)*text++;
        unsigned      nibble;

        if (c >= '0' && c <= '9')
            nibble = c - '0';
        else if (c >= 'a' && c <= 'f')
            nibble = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            nibble = c - 'A' + 10;
        else
            return 1;

        if (++digits > 4)
            return 1;
        value = value * 16 + nibble;
    }
    *out = value;
    return 0;
}

static int _expand_ipv4_component(TargetSet *targetset, const char *token) {
    char     tmp[64];
    char    *parts[4];
    unsigned octet[4] = {0};
    unsigned lo = 0, hi = 0;
    int      range_index = -1;
    size_t   length      = strlen(token);

    if (length == 0 || length >= sizeof(tmp))
        return 0;
    memcpy(tmp, token, length + 1);

    {
        char *p = tmp;
        for (unsigned i = 0; i < 4; i++) {
            parts[i] = p;
            char *dot = strchr(p, '.');
            if (i == 3) {
                if (dot != NULL)
                    return 0;
                break;
            }
            if (dot == NULL)
                return 0;
            *dot = '\0';
            p    = dot + 1;
            if (*p == '\0')
                return 0;
        }
    }

    for (unsigned i = 0; i < 4; i++) {
        char *dash = strchr(parts[i], '-');
        if (dash != NULL) {
            if (range_index >= 0)
                return 0; /* only one variable component */
            *dash = '\0';
            if (_component_parse_dec(parts[i], 255, &lo) ||
                _component_parse_dec(dash + 1, 255, &hi) || lo > hi)
                return 0;
            range_index = (int)i;
        } else if (_component_parse_dec(parts[i], 255, &octet[i])) {
            return 0;
        }
    }

    if (range_index < 0 || (uint64_t)hi - lo + 1 > TARGET_COMPONENT_RANGE_MAX)
        return 0;

    {
        unsigned shift = 8u * (3u - (unsigned)range_index);
        uint32_t base  = 0;

        for (unsigned i = 0; i < 4; i++)
            base |= (uint32_t)octet[i] << (8u * (3u - i));
        base &= ~(0xFFu << shift);

        for (unsigned value = lo; value <= hi; value++) {
            uint32_t address = base | ((uint32_t)value << shift);
            rangelist_add_range(&targetset->ipv4, address, address);
        }
    }
    return 1;
}

static int _split_hex_groups(char *text, char **groups, int max_groups) {
    int count = 0;

    if (*text == '\0')
        return 0;
    for (;;) {
        char *colon;
        if (count >= max_groups)
            return -1;
        groups[count++] = text;
        colon           = strchr(text, ':');
        if (colon == NULL)
            break;
        *colon = '\0';
        text   = colon + 1;
        if (*text == '\0')
            return -1;
    }
    return count;
}

static int _expand_ipv6_component(TargetSet *targetset, const char *token) {
    char      tmp[128];
    char     *left;
    char     *right = NULL;
    char     *left_groups[8];
    char     *right_groups[8];
    int       left_count  = 0;
    int       right_count = 0;
    size_t    length      = strlen(token);

    if (length >= sizeof(tmp))
        return 0;
    memcpy(tmp, token, length + 1);

    if (tmp[0] == '[') {
        if (length < 3 || tmp[length - 1] != ']')
            return 0;
        tmp[length - 1] = '\0';
        memmove(tmp, tmp + 1, length - 1);
    }

    left = tmp;
    {
        char *ellipsis = strstr(tmp, "::");
        if (ellipsis != NULL) {
            if (strstr(ellipsis + 2, "::") != NULL)
                return 0;
            *ellipsis = '\0';
            right     = ellipsis + 2;
        }
    }

    left_count = _split_hex_groups(left, left_groups, 8);
    if (left_count < 0)
        return 0;
    if (right != NULL) {
        right_count = _split_hex_groups(right, right_groups, 8);
        if (right_count < 0)
            return 0;
        if (left_count + right_count >= 8)
            return 0; /* '::' must fill at least one group */
    } else if (left_count != 8) {
        return 0;
    }

    {
        unsigned short base[8] = {0};
        unsigned       range_lo = 0, range_hi = 0;
        int            range_index = -1;
        int            total       = left_count + right_count;

        for (int i = 0; i < left_count; i++) {
            char *dash = strchr(left_groups[i], '-');
            if (dash != NULL) {
                if (range_index >= 0)
                    return 0;
                *dash = '\0';
                if (_component_parse_hex(left_groups[i], &range_lo) ||
                    _component_parse_hex(dash + 1, &range_hi) ||
                    range_lo > range_hi)
                    return 0;
                range_index = i;
            } else {
                unsigned value;
                if (_component_parse_hex(left_groups[i], &value))
                    return 0;
                base[i] = (unsigned short)value;
            }
        }
        for (int i = 0; i < right_count; i++) {
            char *dash = strchr(right_groups[i], '-');
            int   dst  = 8 - right_count + i;
            if (dash != NULL) {
                if (range_index >= 0)
                    return 0;
                *dash = '\0';
                if (_component_parse_hex(right_groups[i], &range_lo) ||
                    _component_parse_hex(dash + 1, &range_hi) ||
                    range_lo > range_hi)
                    return 0;
                range_index = dst;
            } else {
                unsigned value;
                if (_component_parse_hex(right_groups[i], &value))
                    return 0;
                base[dst] = (unsigned short)value;
            }
        }
        if (range_index < 0 || total > 8 ||
            (uint64_t)range_hi - range_lo + 1 > TARGET_COMPONENT_RANGE_MAX)
            return 0;

        for (unsigned value = range_lo; value <= range_hi; value++) {
            ipv6address address;
            base[range_index] = (unsigned short)value;
            address.hi = (uint64_t)base[0] << 48 | (uint64_t)base[1] << 32 |
                         (uint64_t)base[2] << 16 | (uint64_t)base[3];
            address.lo = (uint64_t)base[4] << 48 | (uint64_t)base[5] << 32 |
                         (uint64_t)base[6] << 16 | (uint64_t)base[7];
            range6list_add_range(&targetset->ipv6, address, address);
        }
    }
    return 1;
}

static int _targetset_add_ip_token(TargetSet *targetset, const char *token) {
    struct Range  range4;
    struct Range6 range6;
    int           err;

    err = target_parse_range(token, NULL, 0, &range4, &range6);
    if (err == Ipv4_Address) {
        rangelist_add_range(&targetset->ipv4, range4.begin, range4.end);
        return 0;
    }
    if (err == Ipv6_Address) {
        range6list_add_range(&targetset->ipv6, range6.begin, range6.end);
        return 0;
    }

    if (_expand_ipv4_component(targetset, token) ||
        _expand_ipv6_component(targetset, token))
        return 0;

    LOG(LEVEL_ERROR, "invalid target address: %s\n", token);
    return 1;
}

int targetset_add_ip_str(TargetSet *targetset, const char *string) {
    const char *p = string;

    while (*p) {
        while (*p && (isspace((unsigned char)*p) || *p == ','))
            p++;
        if (*p == '\0')
            break;

        if (*p == '#' || *p == ';' || *p == '/' || *p == '-') {
            while (*p && *p != '\n')
                p++;
            continue;
        }

        {
            char   token[128];
            size_t length = 0;

            while (*p && !isspace((unsigned char)*p) && *p != ',' &&
                   *p != '#' && *p != ';') {
                if (length + 1 >= sizeof(token)) {
                    LOG(LEVEL_ERROR, "target token too long\n");
                    return 1;
                }
                token[length++] = *p++;
            }
            token[length] = '\0';
            if (length != 0 && _targetset_add_ip_token(targetset, token))
                return 1;
        }
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

    /* Component ranges: one variable octet/hextet, other parts fixed. */
    {
        TargetSet component = {0};
        ipaddress first4 = {.version = 4, .ipv4 = 0x84505a0f};
        ipaddress last4  = {.version = 4, .ipv4 = 0x84585a0f};
        ipaddress mid4   = {.version = 4, .ipv4 = 0x84515a0f};
        ipaddress first6 = {.version = 6,
                            .ipv6 = {0x20010db800010000ULL, 1}};
        ipaddress last6  = {.version = 6,
                            .ipv6 = {0x20010db800030000ULL, 1}};
        line = __LINE__;
        if (targetset_add_ip_str(&component, "132.80-88.90.15"))
            goto fail;
        if (rangelist_count(&component.ipv4) != 9 ||
            !targetset_has_ip(&component, first4) ||
            !targetset_has_ip(&component, last4) ||
            !targetset_has_ip(&component, mid4))
            goto fail;

        line = __LINE__;
        if (targetset_add_ip_str(&component, "2001:db8:1-3::1"))
            goto fail;
        if (range6list_count(&component.ipv6).lo != 3 ||
            !targetset_has_ip(&component, first6) ||
            !targetset_has_ip(&component, last6))
            goto fail;

    }

    return 0;
fail:
    LOG(LEVEL_ERROR, "(%s) line=%d\n", __func__, line);
    return 1;
}