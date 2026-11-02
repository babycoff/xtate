/**
 * RFC 768
                      User Datagram Header Format

                  0      7 8     15 16    23 24    31
                 +--------+--------+--------+--------+
                 |     Source      |   Destination   |
                 |      Port       |      Port       |
                 +--------+--------+--------+--------+
                 |                 |                 |
                 |     Length      |    Checksum     |
                 +--------+--------+--------+--------+
                 |
                 |          data octets ...
                 +---------------- ...


                pseudo header

                  0      7 8     15 16    23 24    31
                 +--------+--------+--------+--------+
                 |          source address           |
                 +--------+--------+--------+--------+
                 |        destination address        |
                 +--------+--------+--------+--------+
                 |  zero  |protocol|   UDP length    |
                 +--------+--------+--------+--------+

*/
#include "templ-udp.h"

#include <string.h>

#include "../globals.h"
#include "../util-out/logger.h"
#include "../util-misc/checksum.h"
#include "../util-data/data-convert.h"
#include "../target/target.h"

static size_t udp_create_by_template_ipv4(
    const TmplPkt *tmpl, ipv4address ip_them, unsigned port_them,
    ipv4address ip_me, unsigned port_me, unsigned ttl, unsigned char *payload,
    size_t payload_length, unsigned char *px, size_t sizeof_px) {
    uint64_t xsum_udp;
    unsigned xsum_ip;
    unsigned offset_ip  = tmpl->ipv4.offset_ip;
    unsigned offset_tcp = tmpl->ipv4.offset_tcp;
    unsigned ip_id      = ip_them ^ port_them;
    unsigned r_len      = tmpl->ipv4.offset_app + payload_length;

    if (r_len > sizeof_px) {
        LOG(LEVEL_ERROR, "(udp_create_by_template_ipv4) too much payload\n");
        return 0;
    }

    memcpy(px, tmpl->ipv4.packet, tmpl->ipv4.offset_app);
    memcpy(px + tmpl->ipv4.offset_app, payload, payload_length);

    /*

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  */

    /*
     * Fill in the empty fields in the IP header and then re-calculate
     * the checksum.
     */
    unsigned ip_len = r_len - tmpl->ipv4.offset_ip;
    U16_TO_BE(px + offset_ip + 2, ip_len);
    U16_TO_BE(px + offset_ip + 4, ip_id);

    if (ttl)
        px[offset_ip + 8] = (unsigned char)(ttl);

    U32_TO_BE(px + offset_ip + 12, ip_me);
    U32_TO_BE(px + offset_ip + 16, ip_them);

    /*set ip header checksum to zero*/
    U16_TO_BE(px + offset_ip + 10, 0);

    xsum_ip = checksum_ipv4_header(px, offset_ip, tmpl->ipv4.offset_app);
    U16_TO_BE(px + offset_ip + 10, xsum_ip);

    /*
     * Now do the checksum for the higher layer protocols
     */
    U16_TO_BE(px + offset_tcp + 0, port_me);
    U16_TO_BE(px + offset_tcp + 2, port_them);
    U16_TO_BE(px + offset_tcp + 4, r_len - tmpl->ipv4.offset_app + 8);

    /*set udp checksum to zero*/
    U16_TO_BE(px + offset_tcp + 6, 0);
    xsum_udp = checksum_ipv4_udp(px, offset_ip, offset_tcp, r_len - offset_tcp);
    /* RFC 768: a computed zero checksum is transmitted as all ones. */
    if (xsum_udp == 0)
        xsum_udp = 0xFFFF;
    U16_TO_BE(px + offset_tcp + 6, xsum_udp);

    return r_len;
}

static size_t udp_create_by_template_ipv6(
    const TmplPkt *tmpl, ipv6address ip_them, unsigned port_them,
    ipv6address ip_me, unsigned port_me, unsigned ttl, unsigned char *payload,
    size_t payload_length, unsigned char *px, size_t sizeof_px) {
    uint64_t xsum_udp;
    unsigned offset_ip  = tmpl->ipv6.offset_ip;
    unsigned offset_tcp = tmpl->ipv6.offset_tcp;
    unsigned r_len      = tmpl->ipv6.offset_app + payload_length;

    if (r_len > sizeof_px) {
        LOG(LEVEL_ERROR, "(udp_create_by_template_ipv6) too much payload\n");
        return 0;
    }

    memcpy(px, tmpl->ipv6.packet, tmpl->ipv6.offset_app);
    memcpy(px + tmpl->ipv6.offset_app, payload, payload_length);

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
    /*
     * Fill in the empty fields in the IP header and then re-calculate
     * the checksum.
     */
    payload_length = r_len - tmpl->ipv6.offset_ip - 40;
    U16_TO_BE(px + offset_ip + 4, payload_length);
    if (ttl)
        px[offset_ip + 7] = (unsigned char)(ttl);
    U64_TO_BE(px + offset_ip + 8, ip_me.hi);
    U64_TO_BE(px + offset_ip + 16, ip_me.lo);
    U64_TO_BE(px + offset_ip + 24, ip_them.hi);
    U64_TO_BE(px + offset_ip + 32, ip_them.lo);

    U16_TO_BE(px + offset_tcp + 0, port_me);
    U16_TO_BE(px + offset_tcp + 2, port_them);
    U16_TO_BE(px + offset_tcp + 4, r_len - tmpl->ipv6.offset_app + 8);

    /*
     * Now do the checksum for the higher layer protocols
     */

    /*set udp checksum to zero*/
    U16_TO_BE(px + offset_tcp + 6, 0);
    xsum_udp =
        checksum_ipv6_upper(px + offset_ip + 8, px + offset_ip + 24,
                            IP_PROTO_UDP, r_len - offset_tcp, px + offset_tcp);
    /* RFC 8200: zero is not a valid transmitted UDP checksum. */
    if (xsum_udp == 0)
        xsum_udp = 0xFFFF;
    U16_TO_BE(px + offset_tcp + 6, xsum_udp);

    return r_len;
}

size_t udp_create_by_template(const TmplPkt *tmpl, ipaddress ip_them,
                              unsigned port_them, ipaddress ip_me,
                              unsigned port_me, unsigned ttl,
                              unsigned char *payload, size_t payload_length,
                              unsigned char *px, size_t sizeof_px) {
    if (tmpl->tmpl_type != TmplType_UDP) {
        LOG(LEVEL_ERROR,
            "udp_create_by_template: need a TmplType_UDP TemplatePacket.\n");
        return 0;
    }

    size_t r_len = 0;

    if (ip_them.version == 4) {
        r_len = udp_create_by_template_ipv4(tmpl, ip_them.ipv4, port_them,
                                            ip_me.ipv4, port_me, ttl, payload,
                                            payload_length, px, sizeof_px);
    } else {
        r_len = udp_create_by_template_ipv6(tmpl, ip_them.ipv6, port_them,
                                            ip_me.ipv6, port_me, ttl, payload,
                                            payload_length, px, sizeof_px);
    }
    return r_len;
}

size_t udp_create_packet(ipaddress ip_them, unsigned port_them, ipaddress ip_me,
                         unsigned port_me, unsigned ttl, unsigned char *payload,
                         size_t payload_length, unsigned char *px,
                         size_t sizeof_px) {
    return udp_create_by_template(&global_tmplset->pkts[TmplType_UDP], ip_them,
                                  port_them, ip_me, port_me, ttl, payload,
                                  payload_length, px, sizeof_px);
}