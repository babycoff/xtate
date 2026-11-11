#include "explain-target.h"
#include "../target/target-set.h"
#include "../target/target-rangev4.h"
#include "../target/target-rangev6.h"
#include "../rawsock/rawsock-route.h"
#include "../target/target-ipaddress.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct Group {
    char ifname[256];
    ipaddress source, gateway;
    uint64_t count;
    char samples[8][64];
    unsigned nsamples;
    bool used;
} Group;

int explain_targets(const char *targets, bool check, const char *forced_if) {
    TargetSet set; memset(&set, 0, sizeof(set));
    if (targetset_add_ip_str(&set, targets ? targets : "8.8.8.8") != 0) {
        rangelist_rm_all(&set.ipv4); range6list_rm_all(&set.ipv6);
        return 1;
    }
    Group groups[32]; memset(groups, 0, sizeof(groups)); int ng = 0;
    uint64_t total = 0;
    for (unsigned i = 0; i < set.ipv4.list_len; i++) {
        struct Range r = set.ipv4.list[i];
        uint64_t count = (uint64_t)r.end - r.begin + 1;
        ipaddress ip = {0}; ip.version = 4; ip.ipv4 = r.begin;
        RawRoute route; memset(&route, 0, sizeof(route));
        if (forced_if && forced_if[0]) { snprintf(route.ifname, sizeof(route.ifname), "%s", forced_if); }
        else if (rawsock_route_lookup(ip, &route) != 0) {
            snprintf(route.ifname, sizeof(route.ifname), "(no route)");
        }
        int gi = -1;
        for (int k = 0; k < ng; k++) {
            if (strcmp(groups[k].ifname, route.ifname) == 0 &&
                groups[k].gateway.version == route.gateway.version &&
                (route.gateway.version != 4 ||
                 groups[k].gateway.ipv4 == route.gateway.ipv4) &&
                (route.gateway.version != 6 ||
                 (groups[k].gateway.ipv6.hi == route.gateway.ipv6.hi &&
                  groups[k].gateway.ipv6.lo == route.gateway.ipv6.lo))) { gi = k; break; }
        }
        if (gi < 0 && ng < 32) { gi = ng++; snprintf(groups[gi].ifname, sizeof(groups[gi].ifname), "%s", route.ifname); groups[gi].gateway = route.gateway; groups[gi].source = route.source_ip; }
        if (gi >= 0) {
            groups[gi].used = true; groups[gi].count += count; total += count;
            if (groups[gi].nsamples < 8) {
                unsigned prefix = 32;
                struct Range cidr = range_first_cidr(r, &prefix);
                groups[gi].samples[groups[gi].nsamples][0] = 0;
                if (cidr.begin == cidr.end)
                    snprintf(groups[gi].samples[groups[gi].nsamples], 64,
                             "%u.%u.%u.%u",
                             (cidr.begin>>24)&255,(cidr.begin>>16)&255,
                             (cidr.begin>>8)&255,cidr.begin&255);
                else
                    snprintf(groups[gi].samples[groups[gi].nsamples], 64,
                             "%u.%u.%u.%u-%u.%u.%u.%u/%u",
                             (cidr.begin>>24)&255,(cidr.begin>>16)&255,
                             (cidr.begin>>8)&255,cidr.begin&255,
                             (cidr.end>>24)&255,(cidr.end>>16)&255,
                             (cidr.end>>8)&255,cidr.end&255,prefix);
                groups[gi].nsamples++;
            }
        }
    }
    for (size_t i = 0; i < set.ipv6.list_len; i++) {
        struct Range6 r = set.ipv6.list[i];
        uint64_t count = 1;
        if (r.begin.hi == r.end.hi) count = r.end.lo - r.begin.lo + 1;
        else count = UINT64_MAX;
        ipaddress ip = {0}; ip.version = 6; ip.ipv6 = r.begin;
        RawRoute route; memset(&route, 0, sizeof(route));
        if (forced_if && forced_if[0]) snprintf(route.ifname, sizeof(route.ifname), "%s", forced_if);
        else if (rawsock_route_lookup(ip, &route) != 0) {
            snprintf(route.ifname, sizeof(route.ifname), "(no route)");
        }
        int gi = -1;
        for (int k = 0; k < ng; k++) {
            if (strcmp(groups[k].ifname, route.ifname) == 0 &&
                groups[k].gateway.version == route.gateway.version &&
                (route.gateway.version != 4 || groups[k].gateway.ipv4 == route.gateway.ipv4) &&
                (route.gateway.version != 6 || (groups[k].gateway.ipv6.hi == route.gateway.ipv6.hi && groups[k].gateway.ipv6.lo == route.gateway.ipv6.lo))) { gi = k; break; }
        }
        if (gi < 0 && ng < 32) { gi = ng++; snprintf(groups[gi].ifname, sizeof(groups[gi].ifname), "%s", route.ifname); groups[gi].gateway = route.gateway; groups[gi].source = route.source_ip; }
        if (gi >= 0) {
            groups[gi].used = true; groups[gi].count += count; total += count;
            if (groups[gi].nsamples < 8) {
                ipaddress_formatted_t f = ipaddress_fmt(ip);
                snprintf(groups[gi].samples[groups[gi].nsamples], 64, "%s", f.string);
                groups[gi].nsamples++;
            }
        }
    }
    printf("Targets: %llu\nRoute groups: %d\n", (unsigned long long)total, ng);
    for (int k = 0; k < ng; k++) {
        if (!groups[k].used) continue;
        printf("\nRoute group %d:\n  Targets: %llu\n  Interface: %s\n", k + 1,
               (unsigned long long)groups[k].count, groups[k].ifname);
        if (groups[k].source.version == 4) {
            unsigned s = groups[k].source.ipv4;
            printf("  Source IPv4: %u.%u.%u.%u\n",(s>>24)&255,(s>>16)&255,(s>>8)&255,s&255);
        } else if (groups[k].source.version == 6) {
            ipaddress_formatted_t f = ipaddress_fmt(groups[k].source);
            printf("  Source IPv6: %s\n", f.string);
        }
        if (groups[k].gateway.version == 4) {
            unsigned g = groups[k].gateway.ipv4;
            if (g) printf("  Gateway: %u.%u.%u.%u\n",(g>>24)&255,(g>>16)&255,(g>>8)&255,g&255);
            else printf("  Gateway: on-link\n");
        } else if (groups[k].gateway.version == 6) {
            ipaddress_formatted_t f = ipaddress_fmt(groups[k].gateway);
            printf("  Gateway: %s\n", f.string);
        } else printf("  Gateway: on-link\n");
        printf("  Samples:");
        for (unsigned si = 0; si < groups[k].nsamples; si++)
            printf(" %s", groups[k].samples[si]);
        if (groups[k].count && groups[k].nsamples == 8) printf(" ...");
        printf("\n");
    }
    if (ng > 1) printf("\nWARNING: targets span %d routes; split into separate jobs.\n", ng);
    rangelist_rm_all(&set.ipv4); range6list_rm_all(&set.ipv6);
    return 0;
}
