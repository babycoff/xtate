#include "templ-init.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "templ-tcp.h"
#include "templ-udp.h"
#include "templ-sctp.h"
#include "templ-arp.h"
#include "templ-ndp.h"
#include "templ-opts.h"
#include "templ-icmp.h"

#include "../xcmd.h"
#include "../version.h"
#include "../target/target.h"
#include "../stub/stub-pcap-dlt.h"
#include "../proto/proto-preprocess.h"

#include "../util-out/logger.h"
#include "../util-data/data-convert.h"
#include "../util-data/fine-malloc.h"

/**
 * ! All of templs are hard coded in IPv4.
 * ! IPv6 version will be convert while pkt init.
 */

/**
 * No tcp options.
 * For ACK */
unsigned char default_tcp_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */

    "\x45" /* IP type */
    "\x00"
    "\x00\x28" /* total length from ip = 40 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x06" /* TTL=255, proto=TCP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\0\0"     /* source port */
    "\0\0"     /* destination port */
    "\0\0\0\0" /* sequence number */
    "\0\0\0\0" /* ACK number */
    "\x50"     /* header length: the first 4bits 0101=5 -> 5*4=20bytes */
    "\x02"     /* SYN */
    "\x04\x01" /* window fixed to 1024, too large could make troubles for
                  zbanner*/
    "\xFF\xFF" /* checksum */
    "\x00\x00" /* urgent pointer */
    ;

/**
 * Could add some fixed tcp options.
 * Just for SYN*/
unsigned char default_tcp_syn_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */

    "\x45" /* IP type */
    "\x00"
    "\x00\x2c" /* total length from ip = 44 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x06" /* TTL=255, proto=TCP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\0\0"     /* source port */
    "\0\0"     /* destination port */
    "\0\0\0\0" /* sequence number */
    "\0\0\0\0" /* ACK number */
    "\x60"     /* header length: the first 4bits 0110=6 -> 6*4=24bytes */
    "\x02"     /* SYN */
    "\xfa\xf0" /* window 64240 (default ipv4 tcp win of my win11, and tcp win
                  of win11 ipv6 is \xfd\x20->64800) */
    "\xFF\xFF" /* checksum */
    "\x00\x00" /* urgent pointer */
    "\x02\x04\x05\xb4" /* opt [mss 1460] */
    ;

/**
 * No tcp options and zero window.
 * For RST */
unsigned char default_tcp_rst_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */

    "\x45" /* IP type */
    "\x00"
    "\x00\x28" /* total length from ip = 40 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x06" /* TTL=255, proto=TCP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\0\0"     /* source port */
    "\0\0"     /* destination port */
    "\0\0\0\0" /* sequence number */
    "\0\0\0\0" /* ACK number */
    "\x50"     /* header length: the first 4bits 0101=5 -> 5*4=20bytes */
    "\x04"     /* RST */
    "\x00\x00" /* zero window */
    "\xFF\xFF" /* checksum */
    "\x00\x00" /* urgent pointer */
    ;

static unsigned char default_udp_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x1c" /* total length from ip = 28 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x11" /* TTL=255, proto=UDP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\xfe\xdc" /* source port */
    "\x00\x00" /* destination port */
    "\x00\x08" /* length */
    "\x00\x00" /* checksum */
    /* payload */
    ;

static unsigned char default_sctp_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x34" /* total length from ip = 52 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x84" /* TTL=255, proto = SCTP */
    "\x00\x00" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\x00\x00"         /* source port */
    "\x00\x00"         /* destination port */
    "\x00\x00\x00\x00" /* verification tag */
    "\x58\xe4\x5d\x36" /* checksum */
    "\x01"             /* type = init */
    "\x00"             /* flags = none */
    "\x00\x14"         /* length = 20 */
    "\x9e\x8d\x52\x25" /* initiate tag */
    "\x00\x00\x80\x00" /* receiver window credit */
    "\x00\x0a"         /* outbound streams = 10 */
    "\x08\x00"         /* inbound streams = 2048 */
    "\x46\x1a\xdf\x3d" /* initial TSN */
    ;

static unsigned char default_icmp_ping_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x1C" /* total length from ip = 44 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x01" /* TTL=255, proto=ICMP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\x08\x00" /* Ping Request */
    "\x00\x00" /* checksum */
    "\x00\x00" /* identifier */
    "\x00\x00" /* sequence number */

    /* payload */
    ;

static unsigned char default_icmp_timestamp_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x28" /* total length from ip = 40 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x01" /* TTL=255, proto=ICMP */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\x0d\x00" /* timestamp request */
    "\x00\x00" /* checksum */
    "\x00\x00" /* identifier */
    "\x00\x00" /* sequence number */

    /* payload */
    "\x00\x00\x00\x00" /* originate timestamp */
    "\x00\x00\x00\x00" /* receive timestamp */
    "\x00\x00\x00\x00" /* transmit timestamp */
    ;

static unsigned char default_arp_template[] =
    "\xff\xff\xff\xff\xff\xff" /* Ethernet: destination */
    "\x00\x00\x00\x00\x00\x00" /* Ethernet: source */
    "\x08\x06"                 /* Ethernet type: ARP */
    "\x00\x01"                 /* hardware = Ethernet */
    "\x08\x00"                 /* protocol = IPv4 */
    "\x06\x04"                 /* MAC length = 6, IPv4 length = 4 */
    "\x00\x01"                 /* opcode = request */

    "\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00"

    "\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00";

static unsigned char default_ndp_ns_template[] =
    "\0\1\2\3\4\5"     /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb" /* Ethernet: source */
    "\x08\x00"         /* Ethernet type: IPv4 */
    "\x45"             /* IP type */
    "\x00"
    "\x00\x34" /* total length from ip = 54 bytes */
    "\x00\x00" /* identification */
    "\x00\x00" /* fragmentation flags */
    "\xFF\x01" /* TTL=255, proto=ICMP (should be converted while initing...)
                */
    "\xFF\xFF" /* checksum */
    "\0\0\0\0" /* source address */
    "\0\0\0\0" /* destination address */

    "\x87\x00"         /* neighbor solicitation */
    "\x00\x00"         /* checksum */
    "\x00\x00\x00\x00" /* reserved */
    "\x00\x00\x00\x00" /* Target address */
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00"
    "\x01" /* ICMPv6 Option Type: Source link-layer address */
    "\x01" /* Length for 8 bytes */
    "\x00\x00\x00\x00\x00\x00" /* Link-layer address */
    ;

#if defined(_WIN32)
#define AF_INET6 23
#else
#include <sys/socket.h>
#endif

/***************************************************************************
 * Creates an IPv6 packet from an IPv4 template, by simply replacing
 * the IPv4 header with the IPv6 header.
 ***************************************************************************/
static void _template_init_ipv6(TmplPkt *tmpl, macaddress_t router_mac_ipv6,
                                unsigned data_link_type) {
    PreInfo        parsed;
    unsigned       payload_length;
    unsigned       offset_ip;
    unsigned       offset_tcp;
    unsigned       offset_tcp6;
    unsigned char *buf;
    unsigned       x;

    /* Zero out everything and start from scratch */
    FREE(tmpl->ipv6.packet);
    memset(&tmpl->ipv6, 0, sizeof(tmpl->ipv6));

    /* Parse the existing IPv4 packet */
    x = preprocess_frame(tmpl->ipv4.packet, tmpl->ipv4.length, data_link_type,
                         &parsed);
    if (!x || parsed.found == FOUND_NOTHING) {
        LOG(LEVEL_ERROR, "bad packet template\n");
        xcmd_try_reboot();
        exit(1);
    }

    /* The "payload" in this case is everything past the IP header,
     * so TCP or UDP headers are inside the IP payload */
    payload_length = tmpl->ipv4.length - tmpl->ipv4.offset_tcp;
    offset_ip      = tmpl->ipv4.offset_ip;
    offset_tcp     = tmpl->ipv4.offset_tcp;

    /* Create a copy of the IPv4 packet */
    buf = MALLOC(tmpl->ipv4.length + 40);
    memcpy(buf, tmpl->ipv4.packet, tmpl->ipv4.length);
    tmpl->ipv6.packet = buf;

    /**
     * Align the offset of ip payload.
     * destination = end of IPv6 header
     * source = end of IPv4 header
     * contents = everything after IPv4/IPv6 header */
    offset_tcp6 = offset_ip + 40;
    memmove(buf + offset_tcp6, buf + offset_tcp, payload_length);

    /* fill the IPv6 header with zeroes */
    memset(buf + offset_ip, 0, 40);
    tmpl->ipv6.length = offset_ip + 40 + payload_length;

    /**
     * we have removed useless header in initing of ipv4.
     */
    switch (data_link_type) {
        case PCAP_DLT_NULL:
            /**
             * !FIXME: insert platform dependent value here
             * ref: https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
             * Depending on operating system, these can have
             * different values: 24, 28, or 30
             * */
            *(int *)buf = 24;
            break;
        case PCAP_DLT_RAW:
            break;
        case PCAP_DLT_ETHERNET:
            /* Reset the destination MAC address to be the IPv6 router
             * instead of the IPv4 router, which sometimes are different */
            memcpy(buf + 0, router_mac_ipv6.addr, 6);

            /* Reset the Ethertype field */
            U16_TO_BE(buf + 12, ETHERTYPE_IPv6);
            break;
    }

    /* IP.version = 6 */
    buf[offset_ip + 0] = 0x60;

    /* Set payload length field. In IPv4, this field included the header,
     * but in IPv6, it's everything after the header. In other words,
     * the size of an IPv6 packet is 40+payload_length, whereas in IPv4
     * it was total_length. */
    U16_TO_BE(buf + offset_ip + 4, payload_length);

    /**
     * set ip proto.
     * NOTE: Some info about ip proto and icmp should be converted to ipv6
     * version.
     * */
    buf[offset_ip + 6] = (unsigned char)parsed.ip_protocol;

    /**
     * ICMP is different between IPv4 & IPv6 from protocol number of IP layer to
     * internal field. So it should be handle specially.
     */
    if (parsed.ip_protocol == IP_PROTO_ICMP) {
        buf[offset_ip + 6] = IP_PROTO_IPv6_ICMP;
        if (payload_length > 0 &&
            buf[offset_tcp6 + 0] == ICMPv4_TYPE_ECHO_REQUEST) {
            buf[offset_tcp6 + 0] = ICMPv6_TYPE_ECHO_REQUEST;
        }
    }

    /* Hop limit is equal to ttl of ipv4 in default */
    buf[offset_ip + 7] = tmpl->ipv4.ip_ttl & 0xFF;
    tmpl->ipv6.ip_ttl  = tmpl->ipv4.ip_ttl;

    /* Parse our newly construct IPv6 packet */
    x = preprocess_frame(buf, tmpl->ipv6.length, data_link_type, &parsed);
    if (!x || parsed.found == FOUND_NOTHING) {
        LOG(LEVEL_ERROR, "bad packet template\n");
        xcmd_try_reboot();
        exit(1);
    }

    tmpl->ipv6.offset_ip  = parsed.ip_offset;
    tmpl->ipv6.offset_tcp = parsed.transport_offset;
    tmpl->ipv6.offset_app = parsed.app_offset;
}

/***************************************************************************
 * Here we take a packet template, parse it, then make it easier to work
 * with.
 ***************************************************************************/
static void _template_init(TmplPkt *tmpl, macaddress_t source_mac,
                           macaddress_t router_mac_ipv4,
                           macaddress_t router_mac_ipv6,
                           const void *packet_bytes, size_t packet_size,
                           unsigned data_link_type) {
    unsigned char *px;
    PreInfo        parsed;
    unsigned       x;

    /*
     * Create the new template structure:
     * - zero it out
     * - make copy of the old packet to serve as new template
     */
    memset(tmpl, 0, sizeof(*tmpl));
    tmpl->ipv4.length = (unsigned)packet_size;

    tmpl->ipv4.packet = MALLOC(2048 + packet_size);
    memcpy(tmpl->ipv4.packet, packet_bytes, tmpl->ipv4.length);
    px = tmpl->ipv4.packet;

    x = preprocess_frame(px, tmpl->ipv4.length, PCAP_DLT_ETHERNET, &parsed);
    if (!x || parsed.found == FOUND_NOTHING) {
        LOG(LEVEL_ERROR, "bad packet template\n");
        xcmd_try_reboot();
        exit(1);
    }
    tmpl->ipv4.offset_ip  = parsed.ip_offset;
    tmpl->ipv4.offset_tcp = parsed.transport_offset;
    tmpl->ipv4.offset_app = parsed.app_offset;
    if (parsed.found == FOUND_ARP) {
        tmpl->ipv4.length = parsed.ip_offset + 28;
    } else {
        tmpl->ipv4.length = parsed.ip_offset + parsed.ip_v4_length;
    }

    /*
     * Overwrite the MAC and IP addresses
     */
    memcpy(px + 0, router_mac_ipv4.addr, 6);
    memcpy(px + 6, source_mac.addr, 6);
    memset((void *)parsed._ip_src, 0, 4);
    memset((void *)parsed._ip_dst, 0, 4);

    /*
     * ARP
     *
     * If this is an ARP template (for doing arpscans), then just set our
     * configured source IP and MAC addresses.
     */
    if (parsed.found == FOUND_ARP) {
        memcpy((char *)parsed._ip_src - 6, source_mac.addr, 6);
        tmpl->tmpl_type = TmplType_ARP;
        return;
    }

    /*
     * IPv4
     *
     * Calculate the partial checksum. Zero out the fields that will be
     * added later the packet, then calculate the checksum as if they were
     * zero. This makes recalculation of the checksum easier when we transmit
     */
    memset(px + tmpl->ipv4.offset_ip + 4, 0, 2);  /* IP ID field */
    memset(px + tmpl->ipv4.offset_ip + 10, 0, 2); /* checksum */
    memset(px + tmpl->ipv4.offset_ip + 12, 0, 8); /* addresses */

    tmpl->ipv4.ip_ttl = parsed.ip_ttl;

    /**
     * Higher layer protocols: zero out dest/checksum fields
     */
    switch (parsed.ip_protocol) {
        case IP_PROTO_ICMP:
            memset(px + tmpl->ipv4.offset_tcp + 2, 0, 2); /* checksum */
            switch (px[tmpl->ipv4.offset_tcp]) {
                case ICMPv4_TYPE_ECHO_REQUEST:
                    tmpl->tmpl_type = TmplType_ICMP_ECHO;
                    break;
                case ICMPv4_TYPE_TIMESTAMP_MSG:
                    tmpl->tmpl_type = TmplType_ICMP_TS;
                    break;
                case ICMPv6_TYPE_NS:
                    tmpl->tmpl_type = TmplType_NDP_NS;
                    break;
            }
            break;
        case IP_PROTO_TCP:
            /* port, seqno and ackno */
            memset(px + tmpl->ipv4.offset_tcp + 0, 0, 12);
            memset(px + tmpl->ipv4.offset_tcp + 16, 0, 2); /* checksum */
            tmpl->tmpl_type = TmplType_TCP;
            break;
        case IP_PROTO_UDP:
            memset(px + tmpl->ipv4.offset_tcp + 0, 0, 4); /*port*/
            memset(px + tmpl->ipv4.offset_tcp + 6, 0, 2); /* checksum */
            tmpl->tmpl_type = TmplType_UDP;
            break;
        case IP_PROTO_SCTP:
            /*port, veri tag and checksum*/
            memset(px + tmpl->ipv4.offset_tcp + 0, 0, 12);
            tmpl->tmpl_type = TmplType_SCTP;
            break;
    }

    /*
     * Handle datalink, a little bit kludge...
     */
    if (data_link_type == PCAP_DLT_NULL) {
        /**
         * ref: https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
         */
        int linkproto = 2;
        tmpl->ipv4.length -= tmpl->ipv4.offset_ip - sizeof(int);
        tmpl->ipv4.offset_tcp -= tmpl->ipv4.offset_ip - sizeof(int);
        tmpl->ipv4.offset_app -= tmpl->ipv4.offset_ip - sizeof(int);
        memmove(tmpl->ipv4.packet + sizeof(int),
                tmpl->ipv4.packet + tmpl->ipv4.offset_ip, tmpl->ipv4.length);
        tmpl->ipv4.offset_ip = 4;
        memcpy(tmpl->ipv4.packet, &linkproto, sizeof(int));
    } else if (data_link_type == PCAP_DLT_RAW) {
        tmpl->ipv4.length -= tmpl->ipv4.offset_ip;
        tmpl->ipv4.offset_tcp -= tmpl->ipv4.offset_ip;
        tmpl->ipv4.offset_app -= tmpl->ipv4.offset_ip;
        memmove(tmpl->ipv4.packet, tmpl->ipv4.packet + tmpl->ipv4.offset_ip,
                tmpl->ipv4.length);
        tmpl->ipv4.offset_ip = 0;
    } else if (data_link_type == PCAP_DLT_ETHERNET) {
        /* the default, do nothing */
    } else {
        LOG(LEVEL_ERROR, "bad packet template, unknown data link type\n");
        LOG(LEVEL_ERROR, XTATE_NAME_TITLE_CASE
            " doesn't know how to format packets for this interface\n");
        xcmd_try_reboot();
        exit(1);
    }

    /* Now create an IPv6 template based upon the IPv4 template */
    _template_init_ipv6(tmpl, router_mac_ipv6, data_link_type);
}

/***************************************************************************
 ***************************************************************************/
void template_packet_init(TmplSet *templset, macaddress_t source_mac,
                          macaddress_t router_mac_ipv4,
                          macaddress_t router_mac_ipv6, int data_link,
                          uint64_t entropy, const TmplOpt *templ_opts) {
    unsigned char *buf;
    size_t         length;
    templset->count   = 0;
    templset->entropy = entropy;

    /* [SCTP] */
    _template_init(&templset->pkts[TmplType_SCTP], source_mac, router_mac_ipv4,
                   router_mac_ipv6, default_sctp_template,
                   sizeof(default_sctp_template) - 1, data_link);
    templset->count++;

    /* [TCP] */
    _template_init(&templset->pkts[TmplType_TCP], source_mac, router_mac_ipv4,
                   router_mac_ipv6, default_tcp_template,
                   sizeof(default_tcp_template) - 1, data_link);
    templset->count++;

    /* [TCP SYN] */
    length = sizeof(default_tcp_syn_template) - 1;
    buf    = MALLOC(length);
    memcpy(buf, default_tcp_syn_template, length);
    templ_tcp_apply_options(&buf, &length, templ_opts); /*set options for syn*/
    _template_init(&templset->pkts[TmplType_TCP_SYN], source_mac,
                   router_mac_ipv4, router_mac_ipv6, buf, length, data_link);
    templset->count++;
    free(buf);

    /* [TCP] */
    _template_init(&templset->pkts[TmplType_TCP_RST], source_mac,
                   router_mac_ipv4, router_mac_ipv6, default_tcp_rst_template,
                   sizeof(default_tcp_rst_template) - 1, data_link);
    templset->count++;

    /* [UDP] */
    _template_init(&templset->pkts[TmplType_UDP], source_mac, router_mac_ipv4,
                   router_mac_ipv6, default_udp_template,
                   sizeof(default_udp_template) - 1, data_link);
    templset->count++;

    /* [ICMP ping] */
    _template_init(&templset->pkts[TmplType_ICMP_ECHO], source_mac,
                   router_mac_ipv4, router_mac_ipv6, default_icmp_ping_template,
                   sizeof(default_icmp_ping_template) - 1, data_link);
    templset->count++;

    /* [ICMP timestamp] */
    _template_init(&templset->pkts[TmplType_ICMP_TS], source_mac,
                   router_mac_ipv4, router_mac_ipv6,
                   default_icmp_timestamp_template,
                   sizeof(default_icmp_timestamp_template) - 1, data_link);
    templset->count++;

    /* [ARP] */
    _template_init(&templset->pkts[TmplType_ARP], source_mac, router_mac_ipv4,
                   router_mac_ipv6, default_arp_template,
                   sizeof(default_arp_template) - 1, data_link);
    templset->count++;

    /* [NDP NS] */
    _template_init(&templset->pkts[TmplType_NDP_NS], source_mac,
                   router_mac_ipv4, router_mac_ipv6, default_ndp_ns_template,
                   sizeof(default_ndp_ns_template) - 1, data_link);
    templset->count++;
}

void template_packet_clear(TmplSet *templset) {
    for (unsigned i = 0; i < templset->count; i++) {
        FREE(templset->pkts[i].ipv4.packet);
        FREE(templset->pkts[i].ipv6.packet);
    }

    memset(templset, 0, sizeof(TmplSet));
}

void template_set_tcp_syn_win_of_default(unsigned window) {
    U16_TO_BE(default_tcp_syn_template + 48, window);
}

void template_set_tcp_win_of_default(unsigned window) {
    U16_TO_BE(default_tcp_template + 48, window);
}

/**
 * We don't calc checksum here but in pkt creating.
 */
void template_set_ttl(TmplSet *tmplset, unsigned ttl) {
    unsigned       i;
    TmplPkt       *tmpl_pkt;
    unsigned char *px;
    unsigned       offset;

    for (i = 0; i < tmplset->count; i++) {
        /**
         * Kludge, very kludge...
         */
        tmpl_pkt = &tmplset->pkts[i];
        if (tmpl_pkt->tmpl_type == TmplType_ARP)
            continue;

        px             = tmpl_pkt->ipv4.packet;
        offset         = tmpl_pkt->ipv4.offset_ip;
        px[offset + 8] = ttl & 0xFF;

        px             = tmpl_pkt->ipv6.packet;
        offset         = tmpl_pkt->ipv6.offset_ip;
        px[offset + 7] = ttl & 0xFF;
    }
}

/**
 * We don't calc checksum here but in pkt creating.
 */
void template_packet_set_ttl(TmplPkt *tmpl_pkt, unsigned ttl) {
    unsigned char *px;
    unsigned       offset;

    px             = tmpl_pkt->ipv4.packet;
    offset         = tmpl_pkt->ipv4.offset_ip;
    px[offset + 8] = ttl & 0xFF;

    px             = tmpl_pkt->ipv6.packet;
    offset         = tmpl_pkt->ipv6.offset_ip;
    px[offset + 7] = ttl & 0xFF;
}

/**
 * We don't calc checksum here but in pkt creating.
 */
void template_set_vlan(TmplSet *tmplset, unsigned vlan) {
    unsigned i;

    for (i = 0; i < tmplset->count; i++) {
        TmplPkt       *tmpl = &tmplset->pkts[i];
        unsigned char *px;

        if (tmpl->ipv4.length < 14)
            continue;

        px = MALLOC(tmpl->ipv4.length + 4);
        memcpy(px, tmpl->ipv4.packet, 12);
        memcpy(px + 16, tmpl->ipv4.packet + 12, tmpl->ipv4.length - 12);

        px[12] = 0x81;
        px[13] = 0x00;
        U16_TO_BE(px + 14, vlan);

        tmpl->ipv4.packet = px;
        tmpl->ipv4.length += 4;

        tmpl->ipv4.offset_ip += 4;
        tmpl->ipv4.offset_tcp += 4;
        tmpl->ipv4.offset_app += 4;
    }
}

/**
 * We don't calc checksum here but in pkt creating.
 */
void template_packet_set_vlan(TmplPkt *tmpl_pkt, unsigned vlan) {
    unsigned char *px;

    if (tmpl_pkt->ipv4.length < 14)
        return;

    px = MALLOC(tmpl_pkt->ipv4.length + 4);
    memcpy(px, tmpl_pkt->ipv4.packet, 12);
    memcpy(px + 16, tmpl_pkt->ipv4.packet + 12, tmpl_pkt->ipv4.length - 12);

    px[12] = 0x81;
    px[13] = 0x00;
    U16_TO_BE(px + 14, vlan);

    tmpl_pkt->ipv4.packet = px;
    tmpl_pkt->ipv4.length += 4;

    tmpl_pkt->ipv4.offset_ip += 4;
    tmpl_pkt->ipv4.offset_tcp += 4;
    tmpl_pkt->ipv4.offset_app += 4;
}

/***************************************************************************
 ***************************************************************************/
static int _packet_builder_selftest(TmplSet *tmplset) {
    unsigned char pkt[2048];
    const unsigned char payload[4] = {1, 2, 3, 4};
    PreInfo info;
    size_t n;
    int failures = 0;

    ipaddress ip4_me = {.version = 4, .ipv4 = 0x0A000001};
    ipaddress ip4_them = {.version = 4, .ipv4 = 0x0A000002};
    ipaddress ip6_me = {.version = 6, .ipv6 = {0x20010db800000001ULL, 1}};
    ipaddress ip6_them = {.version = 6, .ipv6 = {0x20010db800000002ULL, 2}};
    macaddress_t mac = macaddress_from_bytes("\x00\x11\x22\x33\x44\x55");

#define CHECK_PKT(cond)                                                        \
    do {                                                                       \
        if (!(cond)) {                                                         \
            LOG(LEVEL_ERROR, "(builder) selftest failed at %s:%u\n", __FILE__, \
                __LINE__);                                                     \
            failures++;                                                        \
        }                                                                      \
    } while (0)

    /* TCP, IPv4 and IPv6. */
    n = tcp_create_by_template(&tmplset->pkts[TmplType_TCP], ip4_them, 80,
                               ip4_me, 12345, 1, 2, TCP_FLAG_SYN, 64, 1000,
                               payload, sizeof(payload), pkt, sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_TCP && info.ip_version == 4 &&
              info.port_dst == 80 && info.port_src == 12345);

    n = tcp_create_by_template(&tmplset->pkts[TmplType_TCP], ip6_them, 443,
                               ip6_me, 54321, 3, 4, TCP_FLAG_SYN, 64, 1000,
                               payload, sizeof(payload), pkt, sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_TCP && info.ip_version == 6 &&
              info.port_dst == 443 && info.port_src == 54321);

    /* TCP SYN template with options. */
    n = tcp_create_by_template(&tmplset->pkts[TmplType_TCP_SYN], ip4_them, 22,
                               ip4_me, 40000, 5, 6, TCP_FLAG_SYN, 64, 1000,
                               payload, sizeof(payload), pkt, sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_TCP && info.ip_version == 4 &&
              info.port_dst == 22 && info.port_src == 40000);

    /* UDP, IPv4 and IPv6. */
    n = udp_create_by_template(&tmplset->pkts[TmplType_UDP], ip4_them, 53,
                               ip4_me, 5353, 64, (unsigned char *)payload,
                               sizeof(payload), pkt, sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_UDP && info.ip_version == 4 &&
              info.port_dst == 53 && info.port_src == 5353);

    n = udp_create_by_template(&tmplset->pkts[TmplType_UDP], ip6_them, 53,
                               ip6_me, 5353, 64, (unsigned char *)payload,
                               sizeof(payload), pkt, sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_UDP && info.ip_version == 6 &&
              info.port_dst == 53 && info.port_src == 5353);

    /* ICMP echo, IPv4 and IPv6. */
    n = icmp_echo_create_by_template(&tmplset->pkts[TmplType_ICMP_ECHO],
                                     ip4_them, ip4_me, 0x1234, 0x5678, 0, 64,
                                     (unsigned char *)payload, sizeof(payload),
                                     pkt, sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_ICMP && info.ip_version == 4);

    n = icmp_echo_create_by_template(&tmplset->pkts[TmplType_ICMP_ECHO],
                                     ip6_them, ip6_me, 0x1234, 0x5678, 0, 64,
                                     (unsigned char *)payload, sizeof(payload),
                                     pkt, sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_ICMP && info.ip_version == 6);

    /* ICMP timestamp (IPv4 only). */
    n = icmp_timestamp_create_by_template(
        &tmplset->pkts[TmplType_ICMP_TS], ip4_them, ip4_me, 0x1111, 0x2222, 0,
        64, 1, 2, 3, pkt, sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_ICMP && info.ip_version == 4);

    /* SCTP, IPv4 and IPv6. */
    n = sctp_create_by_template(&tmplset->pkts[TmplType_SCTP], ip4_them, 3868,
                                ip4_me, 3869, 0x11223344, 64, pkt,
                                sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_SCTP && info.ip_version == 4);

    n = sctp_create_by_template(&tmplset->pkts[TmplType_SCTP], ip6_them, 3868,
                                ip6_me, 3869, 0x11223344, 64, pkt,
                                sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_SCTP && info.ip_version == 6);

    /* ARP and NDP. */
    n = arp_create_by_template(&tmplset->pkts[TmplType_ARP], ip4_them, ip4_me,
                               pkt, sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_ARP);

    n = ndp_create_ns_by_template_ipv6(&tmplset->pkts[TmplType_NDP_NS],
                                       ip6_them.ipv6, ip6_me.ipv6, mac, pkt,
                                       sizeof(pkt));
    CHECK_PKT(n != 0);
    CHECK_PKT(preprocess_frame(pkt, (unsigned)n, PCAP_DLT_ETHERNET, &info) &&
              info.found == FOUND_NDPv6 && info.ip_version == 6);

#undef CHECK_PKT
    return failures;
}

int template_selftest() {
    TmplSet tmplset[1] = {{0}};
    TmplOpt templ_opts = {{0}};
    int     failures   = 0;

    /* Test the module that edits TCP headers */
    if (templ_tcp_selftest()) {
        return 1;
    }

    template_packet_init(tmplset,
                         macaddress_from_bytes("\x00\x11\x22\x33\x44\x55"),
                         macaddress_from_bytes("\x66\x55\x44\x33\x22\x11"),
                         macaddress_from_bytes("\x66\x55\x44\x33\x22\x11"),
                         PCAP_DLT_ETHERNET, 0, /* no entropy */
                         &templ_opts);
    failures += tmplset->pkts[TmplType_TCP].tmpl_type != TmplType_TCP;
    failures += tmplset->pkts[TmplType_TCP_SYN].tmpl_type != TmplType_TCP;
    failures += tmplset->pkts[TmplType_TCP_RST].tmpl_type != TmplType_TCP;
    failures += tmplset->pkts[TmplType_UDP].tmpl_type != TmplType_UDP;
    failures += tmplset->pkts[TmplType_SCTP].tmpl_type != TmplType_SCTP;
    failures +=
        tmplset->pkts[TmplType_ICMP_ECHO].tmpl_type != TmplType_ICMP_ECHO;
    failures += tmplset->pkts[TmplType_ICMP_TS].tmpl_type != TmplType_ICMP_TS;
    failures += tmplset->pkts[TmplType_ARP].tmpl_type != TmplType_ARP;
    failures += tmplset->pkts[TmplType_NDP_NS].tmpl_type != TmplType_NDP_NS;

    failures += _packet_builder_selftest(tmplset);

    if (failures)
        LOG(LEVEL_ERROR, "(template) selftest failed\n");

    template_packet_clear(tmplset);
    return failures;
}