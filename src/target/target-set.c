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

#define TARGET_COMPONENT_PRODUCT_MAX 1048576ULL
#define TARGET_COMPONENT_RANGES_MAX 4

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

static int _component_product_count(const unsigned *counts, unsigned count,
                                    uint64_t *out) {
    uint64_t product = 1;

    for (unsigned i = 0; i < count; i++) {
        uint64_t values = counts[i];
        if (values == 0 || values > TARGET_COMPONENT_PRODUCT_MAX ||
            product > TARGET_COMPONENT_PRODUCT_MAX / values)
            return 1;
        product *= values;
    }
    *out = product;
    return 0;
}

static void _emit_ipv4_product(TargetSet *targetset, const unsigned lo[4],
                               const unsigned hi[4], unsigned index,
                               uint32_t address) {
    if (index == 4) {
        rangelist_add_range(&targetset->ipv4, address, address);
        return;
    }

    for (unsigned value = lo[index]; value <= hi[index]; value++) {
        uint32_t next = address | (value << (8u * (3u - index)));
        _emit_ipv4_product(targetset, lo, hi, index + 1, next);
    }
}

static int _expand_ipv4_component(TargetSet *targetset, const char *token) {
    char     tmp[64];
    char    *parts[4];
    unsigned lo[4] = {0};
    unsigned hi[4] = {0};
    unsigned counts[4];
    unsigned ranges = 0;
    uint64_t product;
    size_t   length = strlen(token);

    if (length == 0 || length >= sizeof(tmp))
        return 0;
    memcpy(tmp, token, length + 1);

    {
        char *p = tmp;
        for (unsigned i = 0; i < 4; i++) {
            char *dot;
            parts[i] = p;
            dot      = strchr(p, '.');
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
            *dash = '\0';
            if (_component_parse_dec(parts[i], 255, &lo[i]) ||
                _component_parse_dec(dash + 1, 255, &hi[i]) || lo[i] > hi[i])
                return 0;
            ranges++;
        } else {
            if (_component_parse_dec(parts[i], 255, &lo[i]))
                return 0;
            hi[i] = lo[i];
        }
    }

    if (ranges == 0)
        return 0;
    if (ranges > TARGET_COMPONENT_RANGES_MAX)
        return 3;
    for (unsigned i = 0; i < 4; i++)
        counts[i] = hi[i] - lo[i] + 1;
    if (_component_product_count(counts, 4, &product))
        return 2;
    (void)product;

    _emit_ipv4_product(targetset, lo, hi, 0, 0);
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

static void _emit_ipv6_product(TargetSet *targetset, const unsigned short lo[8],
                               const unsigned short hi[8], unsigned index,
                               unsigned short groups[8]) {
    if (index == 8) {
        ipv6address address;
        address.hi = (uint64_t)groups[0] << 48 | (uint64_t)groups[1] << 32 |
                     (uint64_t)groups[2] << 16 | (uint64_t)groups[3];
        address.lo = (uint64_t)groups[4] << 48 | (uint64_t)groups[5] << 32 |
                     (uint64_t)groups[6] << 16 | (uint64_t)groups[7];
        range6list_add_range(&targetset->ipv6, address, address);
        return;
    }

    for (unsigned value = lo[index]; value <= hi[index]; value++) {
        groups[index] = (unsigned short)value;
        _emit_ipv6_product(targetset, lo, hi, index + 1, groups);
    }
}

static int _expand_ipv6_component(TargetSet *targetset, const char *token) {
    char           tmp[128];
    char          *left;
    char          *right = NULL;
    char          *left_groups[8];
    char          *right_groups[8];
    int            left_count  = 0;
    int            right_count = 0;
    unsigned short lo[8]       = {0};
    unsigned short hi[8]       = {0};
    unsigned       counts[8];
    unsigned       ranges      = 0;
    uint64_t       product;
    size_t         length = strlen(token);

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

    for (int i = 0; i < left_count; i++) {
        char *dash = strchr(left_groups[i], '-');
        unsigned value;
        if (dash != NULL) {
            unsigned range_hi;
            *dash = '\0';
            if (_component_parse_hex(left_groups[i], &value) ||
                _component_parse_hex(dash + 1, &range_hi) || value > range_hi)
                return 0;
            lo[i] = (unsigned short)value;
            hi[i] = (unsigned short)range_hi;
            ranges++;
        } else {
            if (_component_parse_hex(left_groups[i], &value))
                return 0;
            lo[i] = hi[i] = (unsigned short)value;
        }
    }
    for (int i = 0; i < right_count; i++) {
        char *dash = strchr(right_groups[i], '-');
        int   dst  = 8 - right_count + i;
        unsigned value;
        if (dash != NULL) {
            unsigned range_hi;
            *dash = '\0';
            if (_component_parse_hex(right_groups[i], &value) ||
                _component_parse_hex(dash + 1, &range_hi) || value > range_hi)
                return 0;
            lo[dst] = (unsigned short)value;
            hi[dst] = (unsigned short)range_hi;
            ranges++;
        } else {
            if (_component_parse_hex(right_groups[i], &value))
                return 0;
            lo[dst] = hi[dst] = (unsigned short)value;
        }
    }

    if (ranges == 0)
        return 0;
    if (ranges > TARGET_COMPONENT_RANGES_MAX)
        return 3;
    for (unsigned i = 0; i < 8; i++)
        counts[i] = (unsigned)hi[i] - lo[i] + 1;
    if (_component_product_count(counts, 8, &product))
        return 2;
    (void)product;

    {
        unsigned short groups[8] = {0};
        _emit_ipv6_product(targetset, lo, hi, 0, groups);
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

    {
        int expanded = _expand_ipv4_component(targetset, token);
        if (expanded == 0)
            expanded = _expand_ipv6_component(targetset, token);
        if (expanded == 1)
            return 0;
        if (expanded == 2) {
            LOG(LEVEL_ERROR,
                "component range product exceeds %llu addresses: %s\n",
                (unsigned long long)TARGET_COMPONENT_PRODUCT_MAX, token);
            return 1;
        }
    }

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

        /* Cartesian products of up to four component ranges. */
        {
            TargetSet product = {0};
            ipaddress last4 = {.version = 4, .ipv4 = 0x02040608};
            ipaddress last6 = {.version = 6,
                               .ipv6 = {0x20010db800020004ULL,
                                        0x0006000800000001ULL}};

            line = __LINE__;
            if (targetset_add_ip_str(&product, "1-2.3-4.5.6"))
                goto fail;
            if (rangelist_count(&product.ipv4) != 4)
                goto fail;

            line = __LINE__;
            if (targetset_add_ip_str(&product, "1-2.3-4.5-6.7-8"))
                goto fail;
            if (rangelist_count(&product.ipv4) != 20 ||
                !targetset_has_ip(&product, last4))
                goto fail;

            line = __LINE__;
            if (targetset_add_ip_str(&product,
                                     "2001:db8:1-2:3-4:5-6:7-8::1"))
                goto fail;
            if (range6list_count(&product.ipv6).lo != 16 ||
                !targetset_has_ip(&product, last6))
                goto fail;
        }

    }

    return 0;
fail:
    LOG(LEVEL_ERROR, "(%s) line=%d\n", __func__, line);
    return 1;
}