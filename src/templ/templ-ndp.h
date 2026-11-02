#ifndef TEMPL_NDP_H
#define TEMPL_NDP_H

#include "templ-pkt.h"
#include "../target/target-ipaddress.h"

#define NDP_NA_FLAG_ROUTER    0B10000000
#define NDP_NA_FLAG_SOLICITED 0B01000000
#define NDP_NA_FLAG_OVERRIDE  0B00100000

#define NDP_NA_FLAGS(px, transport_offset) ((px)[(transport_offset) + 4])
#define NDP_NA_HAS_FLAG(px, transport_offset, flag)                            \
    ((NDP_NA_FLAGS((px), (transport_offset)) & (flag)) == (flag))

#define NDP_OPT_TYPE_SRC_LINK_ADDR   1
#define NDP_OPT_TYPE_TGT_LINK_ADDR   2
#define NDP_OPT_TYPE_PREFIX_INFO     3
#define NDP_OPT_TYPE_REDIRECT_HDR    4
#define NDP_OPT_TYPE_MTU             5
#define NDP_OPT_TYPE_RDNS_SERVER     25
#define NDP_OPT_TYPE_DNS_SEARCH_LIST 31

/**
 * This is a wrapped func that uses global_tmplset to create ndp neighbor
 * solicit packet.
 * @param ttl it is for ipv4's ttl or ipv6's hop limit. use value in default
 * template packet if set it to zero.
 * @return len of packet generated.
 */
size_t ndp_create_ns_packet(ipaddress ip_them, ipaddress ip_me,
                            macaddress_t src_mac, unsigned char *px,
                            size_t sizeof_px);

size_t ndp_create_ns_by_template_ipv6(const TmplPkt *tmpl, ipv6address ip_them,
                                      ipv6address ip_me, macaddress_t src_mac,
                                      unsigned char *px, size_t sizeof_px);

/**
 * Check if an NA is for solicitation by checking the target IP in IP header is
 * equal to target ip in ICMPv6
 */
bool ndp_is_solicited_advertise(ipv6address ip_them, const unsigned char *px,
                                size_t px_length, unsigned icmpv6_offset);

int ndp_selftest(void);

#endif