#include "stack-ndpv6.h"

#include <string.h>
#include <time.h>

#include "stack-src.h"
#include "../proto/proto-preprocess.h"
#include "../templ/templ-icmp.h"
#include "../rawsock/rawsock.h"
#include "../util-misc/checksum.h"
#include "../util-out/logger.h"
#include "../target/target.h"
#include "../stub/stub-pcap-dlt.h"
#include "../templ/templ-icmp.h"
#include "../templ/templ-ndp.h"

/* ICMPv6 NDP Router Solicitation according to RFC4861

   Hosts send Router Solicitations in order to prompt routers to
   generate Router Advertisements quickly.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                            Reserved                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Options ...
     +-+-+-+-+-+-+-+-+-+-+-+-

   IP Fields:

      Source Address
                     An IP address assigned to the sending interface, or
                     the unspecified address if no address is assigned
                     to the sending interface.

      Destination Address
                     Typically the all-routers multicast address.

      Hop Limit      255

   ICMP Fields:

      Type           133

      Code           0

      Checksum       The ICMP checksum.  See [ICMPv6].

      Reserved       This field is unused.  It MUST be initialized to
                     zero by the sender and MUST be ignored by the
                     receiver.
   Valid Options:

      Source link-layer address The link-layer address of the sender, if
                     known.  MUST NOT be included if the Source Address
                     is the unspecified address.  Otherwise, it SHOULD
                     be included on link layers that have addresses.

      Future versions of this protocol may define new option types.
      Receivers MUST silently ignore any options they do not recognize
      and continue processing the message.
*/

/* ICMPv6 NDP Router Advertisement according to RFC4861

   Routers send out Router Advertisement messages periodically, or in
   response to Router Solicitations.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         Reachable Time                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Retrans Timer                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Options ...
     +-+-+-+-+-+-+-+-+-+-+-+-

   IP Fields:

      Source Address
                     MUST be the link-local address assigned to the
                     interface from which this message is sent.
      Destination Address
                     Typically the Source Address of an invoking Router
                     Solicitation or the all-nodes multicast address.

      Hop Limit      255

   ICMP Fields:

      Type           134

      Code           0

      Checksum       The ICMP checksum.  See [ICMPv6].

      Cur Hop Limit  8-bit unsigned integer.  The default value that
                     should be placed in the Hop Count field of the IP
                     header for outgoing IP packets.  A value of zero
                     means unspecified (by this router).

      M              1-bit "Managed address configuration" flag.  When
                     set, it indicates that addresses are available via
                     Dynamic Host Configuration Protocol [DHCPv6].

                     If the M flag is set, the O flag is redundant and
                     can be ignored because DHCPv6 will return all
                     available configuration information.

      O              1-bit "Other configuration" flag.  When set, it
                     indicates that other configuration information is
                     available via DHCPv6.  Examples of such information
                     are DNS-related information or information on other
                     servers within the network.

        Note: If neither M nor O flags are set, this indicates that no
        information is available via DHCPv6.

      Reserved       A 6-bit unused field.  It MUST be initialized to
                     zero by the sender and MUST be ignored by the
                     receiver.

      Router Lifetime
                     16-bit unsigned integer.  The lifetime associated
                     with the default router in units of seconds.  The
                     field can contain values up to 65535 and receivers
                     should handle any value, while the sending rules in
                     Section 6 limit the lifetime to 9000 seconds.  A
                     Lifetime of 0 indicates that the router is not a
                     default router and SHOULD NOT appear on the default
                     router list.  The Router Lifetime applies only to
                     the router's usefulness as a default router; it
                     does not apply to information contained in other
                     message fields or options.  Options that need time
                     limits for their information include their own
                     lifetime fields.

      Reachable Time 32-bit unsigned integer.  The time, in
                     milliseconds, that a node assumes a neighbor is
                     reachable after having received a reachability
                     confirmation.  Used by the Neighbor Unreachability
                     Detection algorithm (see Section 7.3).  A value of
                     zero means unspecified (by this router).

      Retrans Timer  32-bit unsigned integer.  The time, in
                     milliseconds, between retransmitted Neighbor
                     Solicitation messages.  Used by address resolution
                     and the Neighbor Unreachability Detection algorithm
                     (see Sections 7.2 and 7.3).  A value of zero means
                     unspecified (by this router).

   Possible options:

      Source link-layer address
                     The link-layer address of the interface from which
                     the Router Advertisement is sent.  Only used on
                     link layers that have addresses.  A router MAY omit
                     this option in order to enable inbound load sharing
                     across multiple link-layer addresses.

      MTU            SHOULD be sent on links that have a variable MTU
                     (as specified in the document that describes how to
                     run IP over the particular link type).  MAY be sent
                     on other links.

      Prefix Information
                     These options specify the prefixes that are on-link
                     and/or are used for stateless address
                     autoconfiguration.  A router SHOULD include all its
                     on-link prefixes (except the link-local prefix) so
                     that multihomed hosts have complete prefix
                     information about on-link destinations for the
                     links to which they attach.  If complete
                     information is lacking, a host with multiple
                     interfaces may not be able to choose the correct
                     outgoing interface when sending traffic to its
                     neighbors.
*/

/**
 * NOTE: Detailed Option info could be checked in templ-ndp.c file.
 */

static inline void _append(unsigned char *buf, size_t *r_offset, size_t max,
                           unsigned x) {
    if (*r_offset >= max)
        return;
    buf[(*r_offset)++] = (unsigned char)x;
}
static inline void _append_bytes(unsigned char *buf, size_t *r_offset,
                                 size_t max, const void *v_bytes, size_t len) {
    const unsigned char *bytes = (const unsigned char *)v_bytes;
    if (*r_offset + len >= max)
        return;
    memcpy(buf + *r_offset, bytes, len);
    *r_offset += len;
}

static inline void _append_short(unsigned char *buf, size_t *offset, size_t max,
                                 unsigned num) {
    if (2 > max - *offset) {
        *offset = max;
        return;
    }
    buf[(*offset)++] = (unsigned char)(num >> 8);
    buf[(*offset)++] = (unsigned char)(num & 0xFF);
}

static inline unsigned _read_byte(const unsigned char *buf, size_t *offset,
                                  size_t max) {
    if (*offset + 1 < max) {
        return buf[(*offset)++];
    } else
        return (unsigned)~0;
}
static inline unsigned _read_short(const unsigned char *buf, size_t *offset,
                                   size_t max) {
    if (*offset + 2 <= max) {
        unsigned result;
        result = buf[(*offset)++] << 8;
        result |= buf[(*offset)++];
        return result;
    } else
        return (unsigned)~0;
}

static inline unsigned _read_number(const unsigned char *buf, size_t *offset,
                                    size_t max) {
    if (*offset + 4 <= max) {
        unsigned result;
        result = buf[(*offset)++] << 24;
        result |= buf[(*offset)++] << 16;
        result |= buf[(*offset)++] << 8;
        result |= buf[(*offset)++];
        return result;
    } else
        return (unsigned)~0;
}

static inline ipv6address_t _read_ipv6(const unsigned char *buf, size_t *offset,
                                       size_t max) {
    ipv6address_t result = {0, 0};

    if (*offset + 16 <= max) {
        result = ipv6address_from_bytes(buf + *offset);
        *offset += 16;
    } else {
        *offset = max;
    }
    return result;
}

/**
 * Handle the IPv6 Neighbor Solicitation request.
 * This happens after we've transmitted a packet, a response is on
 * it's way back, and the router needs to give us the response
 * packet. The router sends us a solicitation, like an ARP request,
 * to which we must respond.
 */
int stack_ndpv6_incoming_request(NetStack *stack, PreInfo *parsed,
                                 const unsigned char *px, size_t length) {
    PktBuf              *response = 0;
    size_t               offset;
    size_t               remaining;
    ipaddress            target_ip;
    const unsigned char *target_ip_buf;
    macaddress_t         target_mac = stack->source_mac;
    unsigned             xsum;
    unsigned char       *buf2;
    static const size_t  max       = sizeof(response->px);
    size_t               offset_ip = parsed->ip_offset;
    size_t               offset_ip_src =
        offset_ip + 8; /* offset in packet to the source IPv6 address */
    size_t offset_ip_dst = offset_ip + 24;
    size_t offset_icmpv6 = parsed->transport_offset;

    /* Verify it's a "Neighbor Solitication" opcode */
    if (parsed->icmp_type != ICMPv6_TYPE_NS)
        return -1;

    /* Make sure there's at least a full header */
    offset = parsed->transport_offset;
    if (offset > length)
        return -1;
    remaining = length - offset;
    if (remaining < 24)
        return -1;

    /* Make sure it's looking for our own address */
    target_ip_buf     = px + offset + 8;
    target_ip.version = 6;
    target_ip.ipv6    = ipv6address_from_bytes(target_ip_buf);
    if (!is_my_ip(stack->src, target_ip))
        return -1;

    /* Print a log message */
    {
        ipv6address_t         a    = ipv6address_from_bytes(px + offset_ip_src);
        ipaddress_formatted_t fmt1 = ipv6address_fmt(a);
        ipaddress_formatted_t fmt2 = ipaddress_fmt(target_ip);
        LOG(LEVEL_DETAIL, "received NDP request from %s for %s\n", fmt1.string,
            fmt2.string);
    }

    /* Get a buffer for sending the response packet. This thread doesn't
     * send the packet itself. Instead, it formats a packet, then hands
     * that packet off to a transmit thread for later transmission. */
    response = stack_get_pktbuf(stack);

    /* Use the request packet as a template for the response */
    memcpy(response->px, px, length > max ? max : length);
    buf2 = response->px;

    /* Set the destination MAC address and destination IPv6 address*/
    memcpy(buf2 + 0, px + 6, 6);
    memcpy(buf2 + offset_ip_dst, px + offset_ip_src, 16);

    /* Set the source MAC address and source IPv6 address */
    memcpy(buf2 + offset_ip_src, target_ip_buf, 16);
    memcpy(buf2 + 6, target_mac.addr, 6);

    /* Format the response */
    _append(buf2, &offset, max, ICMPv6_TYPE_NA); /* type */
    _append(buf2, &offset, max, ICMPv6_CODE_NA); /* code */
    _append(buf2, &offset, max, 0);              /*checksum[hi] */
    _append(buf2, &offset, max, 0);              /*checksum[lo] */
    _append(buf2, &offset, max, 0x60);           /* flags*/
    _append(buf2, &offset, max, 0);
    _append(buf2, &offset, max, 0);
    _append(buf2, &offset, max, 0);
    _append_bytes(buf2, &offset, max, target_ip_buf, 16);
    _append(buf2, &offset, max, 2);
    _append(buf2, &offset, max, 1);
    _append_bytes(buf2, &offset, max, target_mac.addr, 6);

    xsum = checksum_ipv6_upper(buf2 + offset_ip_src, buf2 + offset_ip_dst,
                               IP_PROTO_IPv6_ICMP, offset - offset_icmpv6,
                               buf2 + offset_icmpv6);
    buf2[offset_icmpv6 + 2] = (unsigned char)(xsum >> 8);
    buf2[offset_icmpv6 + 3] = (unsigned char)(xsum >> 0);

    /* Transmit the packet-buffer */
    response->length = offset;
    stack_transmit_pktbuf(stack, response);

    return 0;
}

static int _extract_router_advertisement(const unsigned char *buf,
                                         size_t length, PreInfo *parsed,
                                         ipv6address   my_ipv6,
                                         ipv6address  *router_ip,
                                         macaddress_t *router_mac) {
    size_t offset;
    int    is_same_prefix  = 1;
    int    is_mac_explicit = 0;

    if (parsed->ip_version != 6)
        return 1;

    *router_ip = parsed->src_ip.ipv6;

    if (parsed->ip_protocol != IP_PROTO_IPv6_ICMP)
        return 1;
    offset = parsed->transport_offset;

    if (_read_byte(buf, &offset, length) != ICMPv6_TYPE_RA)
        return 1;

    if (_read_byte(buf, &offset, length) != ICMPv6_CODE_RA)
        return 1;

    /* checksum */
    _read_short(buf, &offset, length);

    /* hop limit */
    _read_byte(buf, &offset, length);

    /* flags */
    _read_byte(buf, &offset, length);

    /* router life time */
    _read_short(buf, &offset, length);

    /* reachable time */
    _read_number(buf, &offset, length);

    /* retrans timer */
    _read_number(buf, &offset, length);

    while (offset + 8 <= length) {
        unsigned             type = buf[offset + 0];
        size_t               len2 = buf[offset + 1] * 8;
        size_t               off2 = 2;
        const unsigned char *buf2 = buf + offset;

        /* Reject zero-length options (would loop forever) and options that
         * extend beyond the received frame (would read out of bounds). */
        if (len2 < 8 || len2 > length - offset) {
            break;
        }

        switch (type) {
            case NDP_OPT_TYPE_PREFIX_INFO: {
                unsigned              prefix_len;
                ipv6address           prefix;
                ipaddress_formatted_t fmt;

                prefix_len = _read_byte(buf2, &off2, len2);
                _read_byte(buf2, &off2, len2);   /* flags */
                _read_number(buf2, &off2, len2); /* valid lifetime */
                _read_number(buf2, &off2, len2); /* preferred lifetime */
                _read_number(buf2, &off2, len2); /* reserved */
                prefix = _read_ipv6(buf2, &off2, len2);

                fmt = ipv6address_fmt(prefix);
                LOG(LEVEL_DETAIL, "ipv6.prefix = %s/%u\n", fmt.string,
                    prefix_len);
                if (ipv6address_is_equal_prefixed(my_ipv6, prefix,
                                                  prefix_len)) {
                    is_same_prefix = 1;
                } else {
                    ipaddress_formatted_t fmt1 = ipv6address_fmt(my_ipv6);
                    ipaddress_formatted_t fmt2 = ipv6address_fmt(prefix);

                    LOG(LEVEL_WARN,
                        "our source-ip is %s, but router prefix announces "
                        "%s/%u\n",
                        fmt1.string, fmt2.string, prefix_len);
                    is_same_prefix = 0;
                }
            } break;
            case NDP_OPT_TYPE_RDNS_SERVER: /* recursive DNS server */
                _read_short(buf2, &off2, len2);
                _read_number(buf2, &off2, len2);

                while (off2 + 16 <= len2) {
                    ipv6address resolver      = _read_ipv6(buf2, &off2, len2);
                    ipaddress_formatted_t fmt = ipv6address_fmt(resolver);
                    LOG(LEVEL_DETAIL, "ipv6.dns = %s\n", fmt.string);
                }
                break;
            case NDP_OPT_TYPE_SRC_LINK_ADDR:
                if (len2 == 8) {
                    memcpy(router_mac->addr, buf2 + 2, 6);
                    is_mac_explicit = 1;
                }
                break;
        }

        offset += len2;
    }

    if (!is_mac_explicit) {
        /* The router advertisement didn't include an explicit
         * source address. Therefore, pull the response from
         * the Ethernet header of the packet instead */
        memcpy(router_mac->addr, parsed->mac_src, 6);
    }

    if (!is_same_prefix) {
        /* We had a valid router advertisement, but it didn't
         * match the IPv6 address we are using. This presumably
         * means there are multiple possible IPv6 routers on the
         * network. Therefore, we are going to discard this
         * packet and wait for another one */
        return 1;
    }

    return 0;
}

/****************************************************************************
 ****************************************************************************/
int stack_ndpv6_resolve(Adapter *adapter, AdapterCache *acache,
                        ipv6address my_ipv6, macaddress_t my_mac_address,
                        macaddress_t *router_mac) {
    unsigned char buf[128];
    size_t        max    = sizeof(buf);
    size_t        offset = 0;
    unsigned      i;
    time_t        start;
    unsigned      is_arp_notice_given = 0;
    int           is_delay_reported   = 0;
    size_t        offset_ip;
    size_t        offset_ip_src;
    size_t        offset_ip_dst;
    size_t        offset_icmpv6;
    unsigned      xsum;
    PreInfo       parsed = {0};

    /*
     * [KLUDGE]
     *  If this is a VPN connection, then there is no answer
     */
    if (rawsock_if_datalink(adapter) == PCAP_DLT_NULL) {
        memcpy(router_mac->addr, "\0\0\0\0\0\2", 6);
        return 0; /* success */
    }

    /*
     * Ethernet header
     */
    _append_bytes(buf, &offset, max, "\x33\x33\x00\x00\x00\x02", 6);
    _append_bytes(buf, &offset, max, my_mac_address.addr, 6);

    if (adapter->is_vlan) {
        _append_short(buf, &offset, max, ETHERTYPE_VLAN_8021Q);
        _append_short(buf, &offset, max, adapter->vlan_id);
    }
    _append_short(buf, &offset, max, ETHERTYPE_IPv6);

    /*
     * Create IPv6 header
     */
    offset_ip = offset;
    _append(buf, &offset, max, 0x60); /* version = 6 */
    _append(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0); /* length = 0 */
    _append(buf, &offset, max, IP_PROTO_IPv6_ICMP);
    _append(buf, &offset, max, 255); /*hop limit must be 255 */

    /* Link local source address based on MAC address */
    offset_ip_src = offset;
    _append_short(buf, &offset, max, 0xfe80);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_bytes(buf, &offset, max, my_mac_address.addr, 3);
    buf[offset - 3] |= 2;
    _append_short(buf, &offset, max, 0xfffe);
    _append_bytes(buf, &offset, max, my_mac_address.addr + 3, 3);

    /* All-routers link local address */
    offset_ip_dst = offset;
    _append_short(buf, &offset, max, 0xff02);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 2);

    /* ICMPv6 Router Solicitation */
    offset_icmpv6 = offset;
    _append(buf, &offset, max, ICMPv6_TYPE_RS);
    _append(buf, &offset, max, ICMPv6_CODE_RS);
    _append_short(buf, &offset, max, 0); /* checksum = 0 (for the moment) */
    _append_short(buf, &offset, max, 0); /* reserved */
    _append_short(buf, &offset, max, 0); /* reserved */
    _append(buf, &offset, max, 1); /* option = source link layer address */
    _append(buf, &offset, max, 1); /* length = 2 + 6 / 8*/
    _append_bytes(buf, &offset, max, my_mac_address.addr, 6);

    buf[offset_ip + 4] = (unsigned char)((offset - offset_icmpv6) >> 8);
    buf[offset_ip + 5] = (unsigned char)((offset - offset_icmpv6) & 0xFF);
    xsum = checksum_ipv6_upper(buf + offset_ip_src, buf + offset_ip_dst,
                               IP_PROTO_IPv6_ICMP, offset - offset_icmpv6,
                               buf + offset_icmpv6);
    buf[offset_icmpv6 + 2] = (unsigned char)(xsum >> 8);
    buf[offset_icmpv6 + 3] = (unsigned char)(xsum >> 0);
    rawsock_send_packet(adapter, acache, buf, (unsigned)offset);
    rawsock_flush(adapter, acache);

    /*
     * Send a shorter version after the long version. I don't know
     * why, but some do this on the Internet.
     */
    offset -= 8;
    buf[offset_ip + 4] = (unsigned char)((offset - offset_icmpv6) >> 8);
    buf[offset_ip + 5] = (unsigned char)((offset - offset_icmpv6) & 0xFF);
    xsum = checksum_ipv6_upper(buf + offset_ip_src, buf + offset_ip_dst,
                               IP_PROTO_IPv6_ICMP, offset - offset_icmpv6,
                               buf + offset_icmpv6);
    buf[offset_icmpv6 + 2] = (unsigned char)(xsum >> 8);
    buf[offset_icmpv6 + 3] = (unsigned char)(xsum >> 0);
    rawsock_send_packet(adapter, acache, buf, (unsigned)offset);
    rawsock_flush(adapter, acache);

    start = time(0);
    i     = 0;
    for (;;) {
        unsigned             length2;
        unsigned             secs;
        unsigned             usecs;
        const unsigned char *buf2;
        int                  err;
        ipv6address          router_ip;

        /* Resend every so often */
        if (time(0) != start) {
            start = time(0);
            rawsock_send_packet(adapter, acache, buf, (unsigned)offset);
            rawsock_flush(adapter, acache);
            if (i++ >= 10)
                break; /* timeout */

            /* It's taking too long, so notify the user */
            if (!is_delay_reported) {
                LOG(LEVEL_HINT, "resolving IPv6 router MAC address (may take "
                                "some time)...\n");
                is_delay_reported = 1;
            }
        }

        /* If we aren't getting a response back to our ARP, then print a
         * status message */
        if (time(0) > start + 1 && !is_arp_notice_given) {
            LOG(LEVEL_HINT, "resolving local IPv6 router\n");
            is_arp_notice_given = 1;
        }

        err = rawsock_recv_packet(adapter, &length2, &secs, &usecs, &buf2);

        if (err != 0)
            continue;

        /*
         * Parse the packet. We'll get lots of packets we aren't interested
         * in,so we'll just loop around and keep searching until we find
         * one.
         */
        err = preprocess_frame(buf2, length2, PCAP_DLT_ETHERNET, &parsed);
        if (err != 1)
            continue;
        if (parsed.found != FOUND_NDPv6)
            continue;

        /* We've found a packet that may be the one we want, so parse it */
        err = _extract_router_advertisement(buf2, length2, &parsed, my_ipv6,
                                            &router_ip, router_mac);
        if (err)
            continue;

        /* The previous call found 'router_mac", so now return */
        return 0;
    }

    return 1;
}

bool is_ipv6_multicast(ipaddress ip_me) {
    /* If this is an IPv6 multicast packet, one sent to the IPv6
     * address with a prefix of FF02::/16 */
    return ip_me.version == 6 && (ip_me.ipv6.hi >> 48ULL) == 0xFF02;
}