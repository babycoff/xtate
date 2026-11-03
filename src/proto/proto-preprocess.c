/* Copyright: (c) 2009-2010 by Robert David Graham */
/****************************************************************************

        PREPROCESS PACKETS

  This function parses the entire TCP/IP stack looking for IP addresses and
  ports. The intent is that this is the minimal parsing necessary to find
  address/port information. While it does basic checking (to confirm length
  information, for example), it does not do more extensive checking (like
  whether the checksum is correct).


 * Modified: Alvin Chen 2024

 ****************************************************************************/
#include "proto-preprocess.h"

#include <assert.h>
#include <string.h>

#include "../target/target.h"
#include "../util-data/data-convert.h"
#include "../stub/stub-pcap-dlt.h"
#include "../templ/templ-icmp.h"
#include "../util-out/logger.h"

/**
 *  Call this frequently while parsing through the headers to make sure that
 *  we don't go past the end of a packet. Remember that 1 byte past the
 *  end can cause a crash.
 **/
#define VERIFY_REMAINING(n, f)                                                 \
    if (offset + (n) > length)                                                 \
        return 0;                                                              \
    else {                                                                     \
        info->found_offset = offset;                                           \
        info->found        = f;                                                \
    }

/****************************************************************************
 ****************************************************************************/
bool preprocess_frame(const unsigned char *px, unsigned length,
                      unsigned link_type, PreInfo *info) {
    unsigned offset    = 0;
    unsigned ethertype = 0;

    info->transport_offset = 0;
    info->found            = FOUND_NOTHING;
    info->found_offset     = 0;

    /* If not standard Ethernet, go do something else */
    if (link_type != PCAP_DLT_ETHERNET)
        goto parse_linktype;

parse_ethernet:
    VERIFY_REMAINING(14, FOUND_ETHERNET);

    info->mac_dst = px + offset + 0;
    info->mac_src = px + offset + 6;
    ethertype     = BE_TO_U16(px + offset + 12);
    offset += 14;
    if (ethertype < 2000)
        goto parse_llc;
    if (ethertype != ETHERTYPE_IPv4)
        goto parse_ethertype;

parse_ipv4: {
    unsigned header_length;
    unsigned flags;
    unsigned fragment_offset;
    unsigned total_length;

    info->ip_offset = offset;
    VERIFY_REMAINING(20, FOUND_IPV4);

    /* Check version */
    if ((px[offset] >> 4) != 4)
        return false; /* not IPv4 or corrupt */

    /* Check header length */
    header_length = (px[offset] & 0x0F) * 4;
    VERIFY_REMAINING(header_length, FOUND_IPV4);

    /*TODO: verify checksum */

    /* Check for fragmentation */
    flags           = px[offset + 6] & 0xE0;
    fragment_offset = (BE_TO_U16(px + offset + 6) & 0x3FFF) << 3;
    if (fragment_offset != 0 || (flags & 0x20))
        return false; /* fragmented */

    /* Check for total-length */
    total_length = BE_TO_U16(px + offset + 2);
    VERIFY_REMAINING(total_length, FOUND_IPV4);
    if (total_length < header_length)
        return false;               /* weird corruption */
    length = offset + total_length; /* reduce the max length */

    /* Save off pseudo header for checksum calculation */
    info->ip_v4_id       = BE_TO_U16(px + offset + 4);
    info->ip_version     = (px[offset] >> 4) & 0xF;
    info->_ip_src        = px + offset + 12;
    info->_ip_dst        = px + offset + 16;
    info->src_ip.ipv4    = BE_TO_U32(px + offset + 12);
    info->src_ip.version = 4;
    info->dst_ip.ipv4    = BE_TO_U32(px + offset + 16);
    info->dst_ip.version = 4;
    info->ip_ttl         = px[offset + 8];
    info->ip_protocol    = px[offset + 9];
    info->ip_v4_length   = total_length;

    if (info->ip_version != 4)
        return false;

    /* next protocol */
    offset += header_length;
    info->transport_offset = offset;
    info->transport_length = length - info->transport_offset;

    switch (info->ip_protocol) {
        case IP_PROTO_ICMP:
            goto parse_icmp;
        case IP_PROTO_IGMP:
            goto parse_igmp;
        case IP_PROTO_TCP:
            goto parse_tcp;
        case IP_PROTO_UDP:
            goto parse_udp;
        case IP_PROTO_SCTP:
            goto parse_sctp;
        default:
            VERIFY_REMAINING(0, FOUND_OPROTO);
            return false; /* TODO: should add more protocols, like ICMP */
    }
}

parse_tcp: {
    unsigned tcp_length;
    VERIFY_REMAINING(20, FOUND_TCP);
    tcp_length = px[offset + 12] >> 2;
    if (tcp_length < 20) {
        return false; /* TCP data offset must cover the 20-byte header */
    }
    VERIFY_REMAINING(tcp_length, FOUND_TCP);
    info->port_src   = BE_TO_U16(px + offset + 0);
    info->port_dst   = BE_TO_U16(px + offset + 2);
    info->app_offset = offset + tcp_length;
    info->app_length = length - info->app_offset;
    // assert(info->app_length < 2000);

    return true;
}

parse_udp: {
    unsigned udp_length;

    VERIFY_REMAINING(8, FOUND_UDP);

    info->port_src = BE_TO_U16(px + offset + 0);
    info->port_dst = BE_TO_U16(px + offset + 2);
    udp_length     = BE_TO_U16(px + offset + 4);

    /* UDP length includes the 8-byte header and must fit in the IP payload.
     * IPv6 jumbograms (length 0) are not supported. */
    if (udp_length < 8 || udp_length > length - offset)
        return false;

    offset += 8;
    info->app_offset = offset;
    info->app_length = udp_length - 8;

    return true;
}

parse_icmp: {
    VERIFY_REMAINING(8, FOUND_ICMP);
    info->icmp_type  = px[offset + 0];
    info->icmp_code  = px[offset + 1];
    info->icmp_id    = BE_TO_U16(px + offset + 4);
    info->icmp_seqno = BE_TO_U16(px + offset + 6);
    /*for icmp echo*/
    info->app_offset = offset + 8;
    info->app_length = length - info->app_offset;

    return true;
}

parse_igmp: {
    VERIFY_REMAINING(4, FOUND_IGMP);
    info->port_src = 0;
    info->port_dst = px[offset + 0];
    return true;
}

parse_sctp: {
    VERIFY_REMAINING(12, FOUND_SCTP);
    info->port_src   = BE_TO_U16(px + offset + 0);
    info->port_dst   = BE_TO_U16(px + offset + 2);
    info->app_offset = offset + 12;
    info->app_length = length - info->app_offset;
    return true;
}

parse_ipv6: {
    unsigned payload_length;

    info->ip_offset = offset;
    VERIFY_REMAINING(40, FOUND_IPV6);

    /* Check version */
    if ((px[offset] >> 4) != 6)
        return false; /* not IPv4 or corrupt */

    /* Payload length */
    payload_length = BE_TO_U16(px + offset + 4);
    VERIFY_REMAINING(40 + payload_length, FOUND_IPV6);
    if (length > offset + 40 + payload_length)
        length = offset + 40 + payload_length;

    /* Save off pseudo header for checksum calculation */
    info->ip_version  = (px[offset] >> 4) & 0xF;
    info->ip_protocol = px[offset + 6];
    info->ip_ttl      = px[offset + 7];
    info->_ip_src     = px + offset + 8;
    info->_ip_dst     = px + offset + 8 + 16;

    info->src_ip.version = 6;
    info->src_ip.ipv6.hi = BE_TO_U64(px + offset + 8);
    info->src_ip.ipv6.lo = BE_TO_U64(px + offset + 16);

    info->dst_ip.version = 6;
    info->dst_ip.ipv6.hi = BE_TO_U64(px + offset + 24);
    info->dst_ip.ipv6.lo = BE_TO_U64(px + offset + 32);

    /* next protocol */
    offset += 40;
    info->transport_offset = offset;
    info->transport_length = length - info->transport_offset;

parse_ipv6_next:
    switch (info->ip_protocol) {
        case IP_PROTO_HOPOPT:
            goto parse_ipv6_hop_by_hop;
        case IP_PROTO_TCP:
            goto parse_tcp;
        case IP_PROTO_UDP:
            goto parse_udp;
        case IP_PROTO_IPv6_ICMP:
            goto parse_icmpv6;
        case IP_PROTO_SCTP:
            goto parse_sctp;
        case IP_PROTO_IPv6_Frag:
            return false;
        default:
            // printf("***** test me ******\n");
            return false;
    }
}

parse_ipv6_hop_by_hop: {
    unsigned len;

    VERIFY_REMAINING(8, FOUND_IPV6_HOP);
    info->ip_protocol = px[offset];
    /* IPv6 extension-header length is in 8-octet units after the first 8
     * bytes: total = (Hdr Ext Len + 1) * 8. */
    len = ((unsigned)px[offset + 1] + 1) * 8;

    VERIFY_REMAINING(len, FOUND_IPV6_HOP);
    offset += len;
    info->transport_offset = offset;
    info->transport_length = length - info->transport_offset;
}
    goto parse_ipv6_next;

parse_icmpv6: {
    VERIFY_REMAINING(8, FOUND_ICMP);

    info->icmp_type  = px[offset + 0];
    info->icmp_code  = px[offset + 1];
    info->icmp_id    = BE_TO_U16(px + offset + 4);
    info->icmp_seqno = BE_TO_U16(px + offset + 6);
    /*for icmp echo*/
    info->app_offset = offset + 8;
    info->app_length = length - info->app_offset;

    if (ICMPv6_TYPE_RS <= info->icmp_type &&
        info->icmp_type <= ICMPv6_TYPE_NA) {
        info->found = FOUND_NDPv6;
    }
}
    return true;

parse_vlan8021q:
    VERIFY_REMAINING(4, FOUND_8021Q);
    ethertype = BE_TO_U16(px + offset + 2);
    offset += 4;
    goto parse_ethertype;

parse_vlanmpls:
    /* MULTILEVEL:
     * Regress: wireshark/mpls-twolevel.cap(9)
     * There can be multiple layers of MPLS tags. This is marked by a
     * flag in the header whether the current header is the "final"
     * header in the stack*/
    while (offset + 4 < length && !(px[offset + 2] & 1))
        offset += 4;

    VERIFY_REMAINING(4, FOUND_MPLS);
    offset += 4;

    if (px[offset - 4 + 2] & 1) {
        goto parse_ipv4;
    } else
        return false;

wifi_data: {
    unsigned flag;
    /* 24-byte base header; ToDS+FromDS adds an Address4 field and shifts the
     * later fields by 6 bytes. */
    VERIFY_REMAINING(30, FOUND_WIFI_DATA);

    flag = px[offset];

    switch (px[offset + 1] & 0x03) {
        case 0:
        case 2:
            info->mac_dst = px + offset + 4;
            info->mac_bss = px + offset + 10;
            info->mac_src = px + offset + 16;
            break;
        case 1:
            info->mac_bss = px + offset + 4;
            info->mac_src = px + offset + 10;
            info->mac_dst = px + offset + 16;
            break;
        case 3:
            info->mac_bss = (const unsigned char *)"\0\0\0\0\0\0";
            info->mac_dst = px + offset + 16;
            info->mac_src = px + offset + 24;
            offset += 6;
            break;
    }

    if ((px[offset + 1] & 0x04) != 0 || (px[offset + 22] & 0xF) != 0)
        return false;

    offset += 24;
    if (flag == 0x88) {
        offset += 2;
    }

    goto parse_llc;
}

parse_wifi:
    VERIFY_REMAINING(2, FOUND_WIFI);
    switch (px[offset]) {
        case 0x08:
        case 0x88: /* QoS data */
            if (px[1] & 0x40)
                return false;
            goto wifi_data;
            break;
        default:
            return false;
    }

parse_radiotap_header:
    /* Radiotap headers for WiFi. http://www.radiotap.org/
     *
     *   struct ieee80211_radiotap_header {
     *           u_int8_t        it_version;     // set to 0
     *           u_int8_t        it_pad;
     *           u_int16_t       it_len;         // entire length
     *           u_int32_t       it_present;     // fields present
     *   };
     */
    {
        unsigned header_length;
        unsigned features;

        VERIFY_REMAINING(8, FOUND_RADIOTAP);
        if (px[offset] != 0)
            return false;
        header_length = LE_TO_U16(px + offset + 2);
        features      = LE_TO_U32(px + offset + 4);

        VERIFY_REMAINING(header_length, FOUND_RADIOTAP);

        /* If FCS is present at the end of the packet, then change
         * the length to remove it */
        if (features & 0x4000) {
            if (header_length < 4 || length < 4)
                return false;
            unsigned fcs_header = LE_TO_U32(px + offset + header_length - 4);
            unsigned fcs_frame  = LE_TO_U32(px + length - 4);
            if (fcs_header == fcs_frame)
                length -= 4;
            VERIFY_REMAINING(header_length, FOUND_RADIOTAP);
        }
        offset += header_length;
        goto parse_wifi;
    }

parse_prism_header:
    /* DLT_PRISM_HEADER */
    /* This was original created to handle Prism II cards, but now we see this
     * from other cards as well, such as the 'madwifi' drivers using Atheros
     * chipsets.
     *
     * This starts with a "TLV" format, a 4-byte little-endian tag, followed by
     * a 4-byte little-endian length. This TLV should contain the entire Prism
     * header, after which we'll find the real header. Therefore, we should just
     * be able to parse the 'length', and skip that many bytes. I'm told it's
     * more complicated than that, but it seems to work right now, so I'm
     * keeping it this way.
     */
    {
        unsigned header_length;
        VERIFY_REMAINING(8, FOUND_PRISM);

        if (LE_TO_U32(px + offset + 0) != 0x00000044)
            return false;
        header_length = LE_TO_U32(px + offset + 4);
        if (header_length > 0xFFFFF)
            return false;
        VERIFY_REMAINING(header_length, FOUND_PRISM);
        offset += header_length;
        goto parse_wifi;
    }

parse_llc: {
    unsigned oui;

    VERIFY_REMAINING(3, FOUND_LLC);

    switch (BE_TO_U24(px + offset)) {
        case 0x0000aa:
            offset += 2;
            goto parse_llc;
        default:
            return false;
        case 0xaaaa03:
            break;
    }

    offset += 3;

    VERIFY_REMAINING(5, FOUND_LLC);

    oui       = BE_TO_U24(px + offset);
    ethertype = BE_TO_U16(px + offset + 3);
    offset += 5;

    switch (oui) {
        case 0x000000:
            goto parse_ethertype;
        default:
            return false;
    }
}

parse_ethertype:
    switch (ethertype) {
        case ETHERTYPE_IPv4:
            goto parse_ipv4;
        case ETHERTYPE_ARP:
            goto parse_arp;
        case ETHERTYPE_IPv6:
            goto parse_ipv6;
        case ETHERTYPE_VLAN_8021Q:
            goto parse_vlan8021q;
        case ETHERTYPE_MLPS_UNI:
            goto parse_vlanmpls;
        default:
            return false;
    }

parse_linktype:
    /*
     * The "link-type" is the same as specified in "libpcap" headers
     * ref: https://www.tcpdump.org/linktypes.html
     */
    switch (link_type) {
        case PCAP_DLT_NULL:
            if (length < 4)
                return false;
            offset += 4;
            /**
             * This can be different in LE or BE, too.
             * ref: https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
             * */
            switch (BE_TO_U32(px)) {
                case 0x02000000:
                case 0x00000002:
                    goto parse_ipv4;
                /* Depending on operating system, these can have
                 different values: 24, 28, or 30 */
                case 0x18000000:
                case 0x00000018:
                case 0x1c000000:
                case 0x0000001c:
                case 0x1e000000:
                case 0x0000001e:
                    goto parse_ipv6;
            }
            return false;
        case PCAP_DLT_ETHERNET:
            goto parse_ethernet;
        case PCAP_DLT_RAW:
            if (offset >= length)
                return false;
            switch (px[offset] >> 4) {
                case 4:
                    goto parse_ipv4;
                case 6:
                    goto parse_ipv6;
            }
            return false;
        case PCAP_DLT_IEEE802_11:
            goto parse_wifi;
        case PCAP_DLT_LINUX_SLL:
            goto parse_linux_sll;
        case PCAP_DLT_PRISM_HEADER:
            goto parse_prism_header;
        case PCAP_DLT_IEEE802_11_RADIO:
            goto parse_radiotap_header;
        default:
            return false;
    }

parse_linux_sll:
    /*
     +--------+--------+
     |    packet type  |
     +--------+--------+
     |   ARPHRD_ type  |
     +--------+--------+
     |   addr length   |
     +--------+--------+
     |                 |
     +  first 8 bytes  +
     |     of the      |
     +  hardware/MAC   +
     |     address     |
     +                 +
     |                 |
     +--------+--------+
     |     ethertype   |
     +--------+--------+
     */
    {
        struct {
            unsigned      packet_type;
            unsigned      arp_type;
            unsigned      addr_length;
            unsigned char mac_address[8];
            unsigned      ethertype;
        } sll;

        VERIFY_REMAINING(16, FOUND_SLL);

        sll.packet_type = BE_TO_U16(px + offset + 0);
        sll.arp_type    = BE_TO_U16(px + offset + 2);
        sll.addr_length = BE_TO_U16(px + offset + 4);
        memcpy(sll.mac_address, px + offset + 6, 8);
        sll.ethertype = BE_TO_U16(px + offset + 14);

        offset += 16;

        goto parse_ethertype;
    }

parse_arp:
    VERIFY_REMAINING(8, FOUND_ARP);
    info->ip_version = (px[offset] >> 4) & 0xF;
    info->ip_offset  = offset;
    {
        info->arp_info.hardware_type = BE_TO_U16(px + offset);
        info->arp_info.protocol_type = BE_TO_U16(px + offset + 2);
        info->arp_info.hardware_size = px[offset + 4];
        info->arp_info.protocol_size = px[offset + 5];
        info->arp_info.opcode        = BE_TO_U16(px + offset + 6);
        info->ip_protocol            = info->arp_info.opcode; /*for convenient*/

        /* ARP addresses follow the 8-byte header. Validate the complete
         * address area and require a 4-byte protocol address before reading
         * the IPv4 addresses below. */
        unsigned hw_len  = info->arp_info.hardware_size;
        unsigned proto_len = info->arp_info.protocol_size;
        VERIFY_REMAINING(8 + 2 * hw_len + 2 * proto_len, FOUND_ARP);
        if (proto_len < 4) {
            info->found_offset = info->ip_offset;
            return true;
        }
        offset += 8;

        VERIFY_REMAINING(2 * info->arp_info.hardware_size +
                             2 * info->arp_info.protocol_size,
                         FOUND_ARP);

        info->arp_info.sender_mac = &px[offset + 0];
        info->arp_info.target_mac = &px[offset + info->arp_info.hardware_size +
                                        info->arp_info.protocol_size];

        info->_ip_src = px + offset + info->arp_info.hardware_size;
        info->_ip_dst = px + offset + 2 * info->arp_info.hardware_size +
                        info->arp_info.protocol_size;

        info->src_ip.version = 4;
        info->src_ip.ipv4 =
            BE_TO_U32(px + offset + info->arp_info.hardware_size);
        info->dst_ip.version = 4;
        info->dst_ip.ipv4 =
            BE_TO_U32(px + offset + 2 * info->arp_info.hardware_size +
                      info->arp_info.protocol_size);
        info->found_offset = info->ip_offset;
        return true;
    }
}


int preprocess_selftest(void) {
    int x = 0;

    /* 1. Truncated ICMP: the parser must not read id/sequence bytes. */
    {
        unsigned char buf[14 + 24] = {0};
        PreInfo       info;
        U16_TO_BE(buf + 12, ETHERTYPE_IPv4);
        buf[14]     = 0x45;
        U16_TO_BE(buf + 16, 24); /* IPv4 total length */
        buf[23]     = IP_PROTO_ICMP;
        if (preprocess_frame(buf, sizeof(buf), PCAP_DLT_ETHERNET, &info))
            x++;
    }

    /* 2. TCP data offset must cover the 20-byte header. */
    {
        unsigned char buf[14 + 40] = {0};
        PreInfo       info;
        U16_TO_BE(buf + 12, ETHERTYPE_IPv4);
        buf[14] = 0x45;
        U16_TO_BE(buf + 16, 40);
        buf[23] = IP_PROTO_TCP;
        buf[34 + 12] = 0; /* data offset = 0 */
        if (preprocess_frame(buf, sizeof(buf), PCAP_DLT_ETHERNET, &info))
            x++;
    }

    /* 3. IPv6 Hop-by-Hop length is (Hdr Ext Len + 1) * 8. */
    {
        unsigned char buf[14 + 40 + 24] = {0};
        PreInfo       info;
        U16_TO_BE(buf + 12, ETHERTYPE_IPv6);
        buf[14] = 0x60;
        U16_TO_BE(buf + 18, 24); /* payload: 16-byte hop header + 8 UDP */
        buf[20] = IP_PROTO_HOPOPT;
        /* Hop-by-Hop: next=UDP, Hdr Ext Len=1 -> 16 bytes total. */
        buf[54] = IP_PROTO_UDP;
        buf[55] = 1;
        /* UDP header after 16-byte hop header. */
        buf[70] = 0x12;
        buf[71] = 0x34;
        buf[72] = 0x56;
        buf[73] = 0x78;
        U16_TO_BE(buf + 74, 8); /* UDP length */
        if (!preprocess_frame(buf, sizeof(buf), PCAP_DLT_ETHERNET, &info) ||
            info.found != FOUND_UDP || info.app_offset != 78 ||
            info.port_src != 0x1234 || info.port_dst != 0x5678)
            x++;
    }

    /* 4. ARP header without address bytes must not read IP fields. */
    {
        unsigned char buf[14 + 8] = {0};
        PreInfo       info;
        U16_TO_BE(buf + 12, ETHERTYPE_ARP);
        buf[14 + 4] = 0; /* hardware size */
        buf[14 + 5] = 0; /* protocol size */
        if (!preprocess_frame(buf, sizeof(buf), PCAP_DLT_ETHERNET, &info) ||
            info.found != FOUND_ARP)
            x++;
    }

    /* 5. All-ones IPv4 addresses exercise the unsigned BE_TO_U32 path. */
    {
        unsigned char buf[14 + 40] = {0};
        PreInfo       info;
        U16_TO_BE(buf + 12, ETHERTYPE_IPv4);
        buf[14] = 0x45;
        U16_TO_BE(buf + 16, 40);
        buf[14 + 9] = IP_PROTO_TCP;
        memset(buf + 14 + 12, 0xFF, 8);
        buf[14 + 20 + 12] = 5 << 4; /* TCP data offset */
        if (!preprocess_frame(buf, sizeof(buf), PCAP_DLT_ETHERNET, &info) ||
            info.src_ip.ipv4 != 0xFFFFFFFF ||
            info.dst_ip.ipv4 != 0xFFFFFFFF)
            x++;
    }

    /* 6. Short RAW/NULL frames must fail without touching px[0]/px[0..3]. */
    {
        PreInfo info;
        unsigned char one = 0;
        if (preprocess_frame(&one, 1, PCAP_DLT_RAW, &info))
            x++;
        if (preprocess_frame(&one, 3, PCAP_DLT_NULL, &info))
            x++;
    }

    /* 7. Radiotap with FCS flag but a header shorter than the FCS field must
     * fail instead of reading at header_length - 4. */
    {
        unsigned char buf[8] = {0};
        PreInfo       info;
        buf[2] = 0; /* radiotap header length */
        buf[4] = 0x00;
        buf[5] = 0x40; /* LE features: FCS present */
        if (preprocess_frame(buf, sizeof(buf), PCAP_DLT_IEEE802_11_RADIO,
                            &info))
            x++;
    }

    /* 8. 802.11 ToDS+FromDS adds an Address4 field; a 24-byte header must not
     * be read as if the extra 6 bytes were present. */
    {
        unsigned char buf[24] = {0};
        PreInfo       info;
        buf[1] = 0x03; /* ToDS | FromDS */
        if (preprocess_frame(buf, sizeof(buf), PCAP_DLT_IEEE802_11, &info))
            x++;
    }

    if (x)
        LOG(LEVEL_ERROR, "(%s) selftest failed\n", __func__);
    return x;
}
