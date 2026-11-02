#include "templ-ndp.h"

#include <string.h>

#include "templ-pkt.h"
#include "../globals.h"
#include "../target/target.h"
#include "../util-out/logger.h"
#include "../util-misc/checksum.h"
#include "../util-data/data-convert.h"

/* ICMPv6 NDP Nerghbor Solicitation according to RFC4861
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Code      |          Checksum             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Reserved                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +                                                               +
     |                                                               |
     +                       Target Address                          +
     |                                                               |
     +                                                               +
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Options ...
     +-+-+-+-+-+-+-+-+-+-+-+-

      Destination Address:
                     Either the solicited-node multicast address
                     corresponding to the target address, or the target
                     address. (The latter is for verifying the reachability
                     of a neighbor and We must know its mac addr.)

      Target Address: The IP address of the target of the solicitation.
                      It MUST NOT be a multicast address.

   Possible options:

      Source link-layer address
                     The link-layer address for the sender.  MUST NOT be
                     included when the source IP address is the
                     unspecified address.  Otherwise, on link layers
                     that have addresses this option MUST be included in
                     multicast solicitations and SHOULD be included in
                     unicast solicitations.


*/

/* ICMPv6 NDP Nerghbor Advertisement according to RFC4861
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |R|S|O|                     Reserved                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      |                                                               |
      +                       Target Address                          +
      |                                                               |
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Options ...
      +-+-+-+-+-+-+-+-+-+-+-+-

      Destination Address
                     For solicited advertisements, the Source Address of
                     an invoking Neighbor Solicitation or, if the
                     solicitation's Source Address is the unspecified
                     address, the all-nodes multicast address.

                     For unsolicited advertisements typically the all-
                     nodes multicast address.

      Target Address
                     For solicited advertisements, the Target Address
                     field in the Neighbor Solicitation message that
                     prompted this advertisement.  For an unsolicited
                     advertisement, the address whose link-layer address
                     has changed.  The Target Address MUST NOT be a
                     multicast address.

      R              Router flag.  When set, the R-bit indicates that
                     the sender is a router.  The R-bit is used by
                     Neighbor Unreachability Detection to detect a
                     router that changes to a host.

      S              Solicited flag.  When set, the S-bit indicates that
                     the advertisement was sent in response to a
                     Neighbor Solicitation from the Destination address.
                     The S-bit is used as a reachability confirmation
                     for Neighbor Unreachability Detection.  It MUST NOT
                     be set in multicast advertisements or in
                     unsolicited unicast advertisements.

      O              Override flag.  When set, the O-bit indicates that
                     the advertisement should override an existing cache
                     entry and update the cached link-layer address.
                     When it is not set the advertisement will not
                     update a cached link-layer address though it will
                     update an existing Neighbor Cache entry for which
                     no link-layer address is known.  It SHOULD NOT be
                     set in solicited advertisements for anycast
                     addresses and in solicited proxy advertisements.
                     It SHOULD be set in other solicited advertisements
                     and in unsolicited advertisements.

   Possible options:

      Target link-layer address
                     The link-layer address for the target, i.e., the
                     sender of the advertisement.  This option MUST be
                     included on link layers that have addresses when
                     responding to multicast solicitations.  When
                     responding to a unicast Neighbor Solicitation this
                     option SHOULD be included.

                     The option MUST be included for multicast
                     solicitations in order to avoid infinite Neighbor
                     Solicitation "recursion" when the peer node does
                     not have a cache entry to return a Neighbor
                     Advertisements message.  When responding to unicast
                     solicitations, the option can be omitted since the
                     sender of the solicitation has the correct link-
                     layer address; otherwise, it would not be able to
                     send the unicast solicitation in the first place.
                     However, including the link-layer address in this
                     case adds little overhead and eliminates a
                     potential race condition where the sender deletes
                     the cached link-layer address prior to receiving a
                     response to a previous solicitation.

*/

/* ICMPv6 NDP general Option Format according to RFC4861

   Neighbor Discovery messages include zero or more options, some of
   which may appear multiple times in the same message.  Options should
   be padded when necessary to ensure that they end on their natural
   64-bit boundaries.  All options are of the form:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Type      |    Length     |              ...              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                              ...                              ~
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Fields:

      Type           8-bit identifier of the type of option.  The
                     options defined in this document are:

                           Option Name                             Type

                        Source Link-Layer Address                    1
                        Target Link-Layer Address                    2
                        Prefix Information                           3
                        Redirected Header                            4
                        MTU                                          5

      Length         8-bit unsigned integer.  The length of the option
                     (including the type and length fields) in units of
                     8 octets.  The value 0 is invalid.  Nodes MUST
                     silently discard an ND packet that contains an
                     option with length zero.
*/

/* NDP Source/Target Link-layer Address Option according to RFC4861

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |    Length     |    Link-Layer Address ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Fields:

      Type
                     1 for Source Link-layer Address
                     2 for Target Link-layer Address
      Length         The length of the option (including the type and
                     length fields) in units of 8 octets.  For example,
                     the length for IEEE 802 addresses is 1
                     [IPv6-ETHER].

      Link-Layer Address
                     The variable length link-layer address.

                     The content and format of this field (including
                     byte and bit ordering) is expected to be specified
                     in specific documents that describe how IPv6
                     operates over different link layers.  For instance,
                     [IPv6-ETHER].

   Description
                     The Source Link-Layer Address option contains the
                     link-layer address of the sender of the packet.  It
                     is used in the Neighbor Solicitation, Router
                     Solicitation, and Router Advertisement packets.

                     The Target Link-Layer Address option contains the
                     link-layer address of the target.  It is used in
                     Neighbor Advertisement and Redirect packets.

                     These options MUST be silently ignored for other
                     Neighbor Discovery messages.

*/

/* NDP Prefix Information Option according to RFC4861

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Valid Lifetime                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Preferred Lifetime                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                           Reserved2                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      |                                                               |
      +                            Prefix                             +
      |                                                               |
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Fields:

      Type           3

      Length         4

      Prefix Length  8-bit unsigned integer.  The number of leading bits
                     in the Prefix that are valid.  The value ranges
                     from 0 to 128.  The prefix length field provides
                     necessary information for on-link determination
                     (when combined with the L flag in the prefix
                     information option).  It also assists with address
                     autoconfiguration as specified in [ADDRCONF], for
                     which there may be more restrictions on the prefix
                     length.

      L              1-bit on-link flag.  When set, indicates that this
                     prefix can be used for on-link determination.  When
                     not set the advertisement makes no statement about
                     on-link or off-link properties of the prefix.  In
                     other words, if the L flag is not set a host MUST
                     NOT conclude that an address derived from the
                     prefix is off-link.  That is, it MUST NOT update a
                     previous indication that the address is on-link.

      A              1-bit autonomous address-configuration flag.  When
                     set indicates that this prefix can be used for
                     stateless address configuration as specified in
                     [ADDRCONF].

      Reserved1      6-bit unused field.  It MUST be initialized to zero
                     by the sender and MUST be ignored by the receiver.

      Valid Lifetime
                     32-bit unsigned integer.  The length of time in
                     seconds (relative to the time the packet is sent)
                     that the prefix is valid for the purpose of on-link
                     determination.  A value of all one bits
                     (0xffffffff) represents infinity.  The Valid
                     Lifetime is also used by [ADDRCONF].

      Preferred Lifetime
                     32-bit unsigned integer.  The length of time in
                     seconds (relative to the time the packet is sent)
                     that addresses generated from the prefix via
                     stateless address autoconfiguration remain
                     preferred [ADDRCONF].  A value of all one bits
                     (0xffffffff) represents infinity.  See [ADDRCONF].

                     Note that the value of this field MUST NOT exceed
                     the Valid Lifetime field to avoid preferring
                     addresses that are no longer valid.

      Reserved2      This field is unused.  It MUST be initialized to
                     zero by the sender and MUST be ignored by the
                     receiver.

      Prefix         An IP address or a prefix of an IP address.  The
                     Prefix Length field contains the number of valid
                     leading bits in the prefix.  The bits in the prefix
                     after the prefix length are reserved and MUST be
                     initialized to zero by the sender and ignored by
                     the receiver.  A router SHOULD NOT send a prefix
                     option for the link-local prefix and a host SHOULD
                     ignore such a prefix option.

   Description
                     The Prefix Information option provide hosts with
                     on-link prefixes and prefixes for Address
                     Autoconfiguration.  The Prefix Information option
                     appears in Router Advertisement packets and MUST be
                     silently ignored for other messages.

*/

/* NDP RA Options for DNS Configuration Option according to RFC8106

Recursive DNS Server Option

   The RDNSS option contains one or more IPv6 addresses of RDNSSes.  All
   of the addresses share the same Lifetime value.  If it is desirable
   to have different Lifetime values, multiple RDNSS options can be
   used.  Figure 1 shows the format of the RDNSS option.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Type      |     Length    |           Reserved            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Lifetime                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     :            Addresses of IPv6 Recursive DNS Servers            :
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                       Figure 1: RDNSS Option Format

   Fields:

   Type        8-bit identifier of the RDNSS option type as assigned by
               IANA: 25

   Length      8-bit unsigned integer.  The length of the option
               (including the Type and Length fields) is in units of
               8 octets.  The minimum value is 3 if one IPv6 address is
               contained in the option.  Every additional RDNSS address
               increases the length by 2.  The Length field is used by
               the receiver to determine the number of IPv6 addresses in
               the option.

   Lifetime    32-bit unsigned integer.  The maximum time in seconds
               (relative to the time the packet is received) over which
               these RDNSS addresses MAY be used for name resolution.
               The value of Lifetime SHOULD by default be at least
               3 * MaxRtrAdvInterval, where MaxRtrAdvInterval is the
               maximum RA interval as defined in [RFC4861].  A value of
               all one bits (0xffffffff) represents infinity.  A value
               of zero means that the RDNSS addresses MUST no longer
               be used.
   Addresses of IPv6 Recursive DNS Servers
               One or more 128-bit IPv6 addresses of the RDNSSes.  The
               number of addresses is determined by the Length field.
               That is, the number of addresses is equal to
               (Length - 1) / 2.

   Note: The addresses for RDNSSes in the RDNSS option MAY be link-local
         addresses.  Such link-local addresses SHOULD be registered in
         the Resolver Repository along with the corresponding link zone
         indices of the links that receive the RDNSS option(s) for them.
         The link-local addresses MAY be represented in the Resolver
         Repository with their link zone indices in the textual format
         for scoped addresses as described in [RFC4007].  When a
         resolver sends a DNS query message to an RDNSS identified by a
         link-local address, it MUST use the corresponding link.

         The rationale of the default value of the Lifetime field is as
         follows.  The Router Lifetime field, set by AdvDefaultLifetime,
         has the default of 3 * MaxRtrAdvInterval as specified in
         [RFC4861], so such a default or a larger default can allow for
         the reliability of DNS options even under the loss of RAs on
         links with a relatively high rate of packet loss.  Note that
         the ratio of AdvDefaultLifetime to MaxRtrAdvInterval is the
         number of unsolicited multicast RAs sent by the router.  Since
         the DNS option entries can survive for at most three
         consecutive losses of RAs containing DNS options, the default
         value of the Lifetime lets the DNS option entries be resilient
         to packet-loss environments.

*/

static size_t
ndp_create_ns_by_template_ipv6(const TmplPkt *tmpl, ipv6address ip_them,
                               ipv6address ip_me, macaddress_t src_mac,
                               unsigned char *px, size_t sizeof_px) {
    if (tmpl->tmpl_type != TmplType_NDP_NS) {
        LOG(LEVEL_ERROR, "(ndp_create_by_template_ipv6) need a TmplType_NDP_NS "
                         "TemplatePacket.\n");
        return 0;
    }

    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum_ndp;
    unsigned ndp_length;

    unsigned r_len = tmpl->ipv6.length;

    if (sizeof_px < r_len) {
        LOG(LEVEL_ERROR, "(ndp_create_by_template_ipv6) buffer too small\n");
        return 0;
    }
    memcpy(px, tmpl->ipv6.packet, r_len);
    offset_ip  = tmpl->ipv6.offset_ip;
    offset_tcp = tmpl->ipv6.offset_tcp;

    /*

       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Version| Traffic Class |           Flow Label                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Payload Length        |  Next Header  |   Hop Limit   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +                                                               +
       |                                                               |
       +                         Source Address                        +
       |                                                               |
       +                                                               +
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +                                                               +
       |                                                               |
       +                      Destination Address                      +
       |                                                               |
       +                                                               +
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    /*set dst mac as multicast addr*/
    px[0] = 0x33;
    px[1] = 0x33;
    px[2] = 0xFF;
    px[3] = (unsigned char)((ip_them.lo >> 16ULL) & 0xFF);
    px[4] = (unsigned char)((ip_them.lo >> 8ULL) & 0xFF);
    px[5] = (unsigned char)((ip_them.lo >> 0ULL) & 0xFF);

    /*
     * Fill in the empty fields in the IP header and then re-calculate
     * the checksum.
     */
    ndp_length = r_len - tmpl->ipv6.offset_ip - 40;
    U16_TO_BE(px + offset_ip + 4, ndp_length);

    /**
     * !Must be 255. ref:RFC4861
     */
    px[offset_ip + 7] = 0xFF;

    U64_TO_BE(px + offset_ip + 8, ip_me.hi);
    U64_TO_BE(px + offset_ip + 16, ip_me.lo);

    /*set solicited-node addr*/
    px[offset_ip + 24] = 0xFF;
    px[offset_ip + 25] = 0x02;
    px[offset_ip + 26] = 0x00;
    px[offset_ip + 27] = 0x00;
    px[offset_ip + 28] = 0x00;
    px[offset_ip + 29] = 0x00;
    px[offset_ip + 30] = 0x00;
    px[offset_ip + 31] = 0x00;

    px[offset_ip + 32] = 0x00;
    px[offset_ip + 33] = 0x00;
    px[offset_ip + 34] = 0x00;
    px[offset_ip + 35] = 0x01;
    px[offset_ip + 36] = 0xFF;
    px[offset_ip + 37] = (unsigned char)((ip_them.lo >> 16ULL) & 0xFF);
    px[offset_ip + 38] = (unsigned char)((ip_them.lo >> 8ULL) & 0xFF);
    px[offset_ip + 39] = (unsigned char)((ip_them.lo >> 0ULL) & 0xFF);

    /*set Target Address in NDP*/
    U64_TO_BE(px + offset_tcp + 8, ip_them.hi);
    U64_TO_BE(px + offset_tcp + 16, ip_them.lo);

    /*set src link addr in NDP*/
    px[offset_tcp + 26] = src_mac.addr[0];
    px[offset_tcp + 27] = src_mac.addr[1];
    px[offset_tcp + 28] = src_mac.addr[2];
    px[offset_tcp + 29] = src_mac.addr[3];
    px[offset_tcp + 30] = src_mac.addr[4];
    px[offset_tcp + 31] = src_mac.addr[5];

    /*
     * Now do the checksum for the higher layer protocols
     */
    xsum_ndp = checksum_ipv6_upper(px + offset_ip + 8, px + offset_ip + 24,
                                   IP_PROTO_IPv6_ICMP, r_len - offset_tcp,
                                   px + offset_tcp);

    U16_TO_BE(px + offset_tcp + 2, xsum_ndp);

    return r_len;
}

size_t ndp_create_ns_packet(ipaddress ip_them, ipaddress ip_me,
                            macaddress_t src_mac, unsigned char *px,
                            size_t sizeof_px) {
    /*just for IPv6*/
    if (ip_them.version == 4) {
        LOG(LEVEL_ERROR, "(ndp_create_ns_packet) cannot create for ipv4.\n");
        return 0;
    }

    return ndp_create_ns_by_template_ipv6(
        &global_tmplset->pkts[TmplType_NDP_NS], ip_them.ipv6, ip_me.ipv6,
        src_mac, px, sizeof_px);
}

bool ndp_is_solicited_advertise(ipv6address ip_them, const unsigned char *px,
                                size_t px_length, unsigned icmpv6_offset) {
    /* Target address is ICMPv6 offset + 8..23 (16 bytes). */
    if (px_length < (size_t)icmpv6_offset + 24)
        return false;
    if (U64_EQUAL_TO_BE(px + icmpv6_offset + 8, ip_them.hi) &&
        U64_EQUAL_TO_BE(px + icmpv6_offset + 16, ip_them.lo))
        return true;

    return false;
}

int ndp_selftest(void) {
    unsigned char px[32] = {0};
    ipv6address   target = {0x20010db800000001ULL, 0x0000000000000002ULL};
    int           x      = 0;

    /* Big-endian target address at ICMPv6 offset + 8 and + 16. */
    for (unsigned i = 0; i < 8; i++) {
        px[8 + i]  = (unsigned char)(target.hi >> (56 - 8 * i));
        px[16 + i] = (unsigned char)(target.lo >> (56 - 8 * i));
    }
    if (!ndp_is_solicited_advertise(target, px, sizeof(px), 0))
        x++;
    px[8] ^= 1;
    if (ndp_is_solicited_advertise(target, px, sizeof(px), 0))
        x++;
    px[8] ^= 1;

    /* Offset must be honored. */
    for (unsigned i = 0; i < 8; i++) {
        px[16 + i] = (unsigned char)(target.hi >> (56 - 8 * i));
        px[24 + i] = (unsigned char)(target.lo >> (56 - 8 * i));
    }
    if (!ndp_is_solicited_advertise(target, px, sizeof(px), 8))
        x++;

    if (x)
        LOG(LEVEL_ERROR, "(%s) selftest failed\n", __func__);
    return x;
}
