#include "templ-icmp.h"

#include <string.h>

#include "../globals.h"
#include "../target/target.h"
#include "../util-out/logger.h"
#include "../util-misc/checksum.h"
#include "../util-data/data-convert.h"

/* Generic ICMPv4 according to RFC792
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Internet Header + 64 bits of Original Data Datagram      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/* Generic ICMPv6 according to RFC4443
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |     Type      |     Code      |          Checksum             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                         Message Body                          +
      |                                                               |
*/

/* echo request and reply ICMP(v4/v6) according to RFC792 and RFC4443.
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-

   So we set messages in `Identifier` and `Sequence Number` fields for echoing.
*/

/*
ICMPv4 Timestamp or Timestamp Reply Message according to RFC792

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |      Code     |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Originate Timestamp                                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Receive Timestamp                                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Transmit Timestamp                                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

static size_t icmp_echo_create_by_template_ipv4(
    const TmplPkt *tmpl, ipv4address ip_them, ipv4address ip_me,
    uint16_t identifier, uint16_t sequence, uint16_t ip_id, uint8_t ttl,
    unsigned char *payload, size_t payload_length, unsigned char *px,
    size_t sizeof_px) {
    uint64_t xsum_icmp;
    unsigned xsum_ip;
    unsigned icmp_length;
    unsigned offset_ip  = tmpl->ipv4.offset_ip;
    unsigned offset_tcp = tmpl->ipv4.offset_tcp;
    unsigned r_len      = tmpl->ipv4.offset_app + payload_length;

    if (r_len > sizeof_px) {
        LOG(LEVEL_ERROR,
            "(icmp_echo_create_by_template_ipv4) too much payload\n");
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

    /*set ip header checksum field to zero*/
    U16_TO_BE(px + offset_ip + 10, 0);

    xsum_ip = checksum_ipv4_header(px, offset_ip, tmpl->ipv4.offset_app);

    U16_TO_BE(px + offset_ip + 10, xsum_ip);

    /*
     * Now do the checksum for the higher layer protocols
     */
    U16_TO_BE(px + offset_tcp + 4, identifier);
    U16_TO_BE(px + offset_tcp + 6, sequence);

    icmp_length = r_len - tmpl->ipv4.offset_tcp;
    xsum_icmp   = checksum_ipv4_icmp(px, offset_tcp, icmp_length);
    U16_TO_BE(px + offset_tcp + 2, xsum_icmp);

    return r_len;
}

static size_t icmp_echo_create_by_template_ipv6(
    const TmplPkt *tmpl, ipv6address ip_them, ipv6address ip_me,
    uint16_t identifier, uint16_t sequence, uint8_t ttl, unsigned char *payload,
    size_t payload_length, unsigned char *px, size_t sizeof_px) {
    uint64_t xsum_icmp;
    unsigned icmp_length;
    unsigned offset_ip  = tmpl->ipv6.offset_ip;
    unsigned offset_tcp = tmpl->ipv6.offset_tcp;
    unsigned r_len      = tmpl->ipv6.offset_app + payload_length;

    if (r_len > sizeof_px) {
        LOG(LEVEL_ERROR,
            "(icmp_echo_create_by_template_ipv6) too much payload\n");
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
    icmp_length = r_len - tmpl->ipv6.offset_ip - 40;
    U16_TO_BE(px + offset_ip + 4, icmp_length);

    if (ttl)
        px[offset_ip + 7] = (unsigned char)(ttl);

    U64_TO_BE(px + offset_ip + 8, ip_me.hi);
    U64_TO_BE(px + offset_ip + 16, ip_me.lo);

    U64_TO_BE(px + offset_ip + 24, ip_them.hi);
    U64_TO_BE(px + offset_ip + 32, ip_them.lo);

    U16_TO_BE(px + offset_tcp + 4, identifier);
    U16_TO_BE(px + offset_tcp + 6, sequence);

    /*
     * Now do the checksum for the higher layer protocols
     */
    xsum_icmp = checksum_ipv6_upper(px + offset_ip + 8, px + offset_ip + 24,
                                    IP_PROTO_IPv6_ICMP, r_len - offset_tcp,
                                    px + offset_tcp);
    U16_TO_BE(px + offset_tcp + 2, xsum_icmp);

    return r_len;
}

size_t icmp_echo_create_by_template(const TmplPkt *tmpl, ipaddress ip_them,
                                    ipaddress ip_me, uint16_t identifier,
                                    uint16_t sequence, uint16_t ip_id,
                                    uint8_t ttl, unsigned char *payload,
                                    size_t payload_length, unsigned char *px,
                                    size_t sizeof_px) {
    if (tmpl->tmpl_type != TmplType_ICMP_ECHO) {
        LOG(LEVEL_ERROR, "(icmp_echo_echo_create_by_template) need a "
                         "TmplType_ICMP_ECHO TemplatePacket.\n");
        return 0;
    }

    size_t r_len = 0;

    if (ip_them.version == 4) {
        r_len = icmp_echo_create_by_template_ipv4(
            tmpl, ip_them.ipv4, ip_me.ipv4, identifier, sequence, ip_id, ttl,
            payload, payload_length, px, sizeof_px);
    } else {
        r_len = icmp_echo_create_by_template_ipv6(
            tmpl, ip_them.ipv6, ip_me.ipv6, identifier, sequence, ttl, payload,
            payload_length, px, sizeof_px);
    }
    return r_len;
}

size_t icmp_echo_create_packet(ipaddress ip_them, const ipaddress ip_me,
                               uint16_t identifier, uint16_t sequence,
                               uint16_t ip_id, uint8_t ttl,
                               unsigned char *payload, size_t payload_length,
                               unsigned char *px, size_t sizeof_px) {
    return icmp_echo_create_by_template(
        &global_tmplset->pkts[TmplType_ICMP_ECHO], ip_them, ip_me, identifier,
        sequence, ip_id, ttl, payload, payload_length, px, sizeof_px);
}

static size_t icmp_timestamp_create_by_template_ipv4(
    const TmplPkt *tmpl, ipv4address ip_them, ipv4address ip_me,
    uint16_t identifier, uint16_t sequence, uint16_t ip_id, uint8_t ttl,
    unsigned origin_time, unsigned recv_time, unsigned trans_time,
    unsigned char *px, size_t sizeof_px) {
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum_icmp;
    unsigned xsum_ip;
    unsigned icmp_length;
    unsigned r_len = tmpl->ipv4.length;

    if (sizeof_px < r_len) {
        LOG(LEVEL_ERROR, "(icmp_timestamp_create_by_template_ipv4) buffer too small\n");
        return 0;
    }
    memcpy(px, tmpl->ipv4.packet, r_len);
    offset_ip  = tmpl->ipv4.offset_ip;
    offset_tcp = tmpl->ipv4.offset_tcp;

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

    unsigned ip_len = tmpl->ipv4.length - tmpl->ipv4.offset_ip;
    U16_TO_BE(px + offset_ip + 2, ip_len);
    U16_TO_BE(px + offset_ip + 4, ip_id);

    if (ttl)
        px[offset_ip + 8] = (unsigned char)(ttl);

    U32_TO_BE(px + offset_ip + 12, ip_me);
    U32_TO_BE(px + offset_ip + 16, ip_them);

    /*set ip header checksum to zero*/
    U16_TO_BE(px + offset_ip + 10, 0);

    xsum_ip = checksum_ipv4_header(px, offset_ip, tmpl->ipv4.length);

    U16_TO_BE(px + offset_ip + 10, xsum_ip);

    /*
     * Now do the checksum for the higher layer protocols
     */
    U16_TO_BE(px + offset_tcp + 4, identifier);
    U16_TO_BE(px + offset_tcp + 6, sequence);
    U32_TO_BE(px + offset_tcp + 8, origin_time);
    U32_TO_BE(px + offset_tcp + 12, recv_time);
    U32_TO_BE(px + offset_tcp + 16, trans_time);

    icmp_length = r_len - tmpl->ipv4.offset_tcp;
    xsum_icmp   = checksum_ipv4_icmp(px, offset_tcp, icmp_length);
    U16_TO_BE(px + offset_tcp + 2, xsum_icmp);

    return r_len;
}

size_t icmp_timestamp_create_by_template(const TmplPkt *tmpl, ipaddress ip_them,
                                         ipaddress ip_me, uint16_t identifier,
                                         uint16_t sequence, uint16_t ip_id,
                                         uint8_t ttl, unsigned origin_time,
                                         unsigned recv_time,
                                         unsigned trans_time, unsigned char *px,
                                         size_t sizeof_px) {
    if (tmpl->tmpl_type != TmplType_ICMP_TS) {
        LOG(LEVEL_ERROR, "(icmp_timestamp_create_by_template) need a "
                         "TmplType_ICMP_TS TemplatePacket.\n");
        return 0;
    }

    size_t r_len = 0;

    if (ip_them.version == 4) {
        r_len = icmp_timestamp_create_by_template_ipv4(
            tmpl, ip_them.ipv4, ip_me.ipv4, identifier, sequence, ip_id, ttl,
            origin_time, recv_time, trans_time, px, sizeof_px);
    } else {
        LOG(LEVEL_ERROR,
            "icmp_timestamp_create_by_template: need ipv4 address.\n");
        return 0;
    }
    return r_len;
}

size_t icmp_timestamp_create_packet(ipaddress ip_them, const ipaddress ip_me,
                                    uint16_t identifier, uint16_t sequence,
                                    uint16_t ip_id, uint8_t ttl,
                                    unsigned origin_time, unsigned recv_time,
                                    unsigned trans_time, unsigned char *px,
                                    size_t sizeof_px) {
    return icmp_timestamp_create_by_template(
        &global_tmplset->pkts[TmplType_ICMP_TS], ip_them, ip_me, identifier,
        sequence, ip_id, ttl, origin_time, recv_time, trans_time, px,
        sizeof_px);
}

/***************************************************************************
 ***************************************************************************/
bool parse_icmp_port_unreachable(const unsigned char *transport_px,
                                 unsigned length, ipaddress *r_ip_them,
                                 unsigned *r_port_them, ipaddress *r_ip_me,
                                 unsigned *r_port_me, unsigned *r_icmp_proto) {
    const unsigned char *icmp_ip_px = transport_px + 8;
    unsigned       icmp_payload_len = length - (icmp_ip_px - transport_px);
    unsigned char *trans_header;
    unsigned       trans_len;
    unsigned       ipv4_header_len;

    if (icmp_ip_px[0] >> 4 == 4) {
        /*ipv4*/
        r_ip_them->version = 4;
        r_ip_me->version   = 4;

        r_ip_me->ipv4   = BE_TO_U32(icmp_ip_px + 12);
        r_ip_them->ipv4 = BE_TO_U32(icmp_ip_px + 16);

        *r_icmp_proto = icmp_ip_px[9];
        if (*r_icmp_proto != IP_PROTO_TCP && *r_icmp_proto != IP_PROTO_UDP)
            return false;

        ipv4_header_len = (icmp_ip_px[0] & 0xF) << 2;
        trans_len       = icmp_payload_len - ipv4_header_len;
        trans_header    = (unsigned char *)icmp_ip_px + ipv4_header_len;

    } else if (icmp_ip_px[0] >> 4 == 6) {
        /*ipv6*/
        r_ip_them->version = 6;
        r_ip_me->version   = 6;

        r_ip_me->ipv6.hi   = BE_TO_U64(icmp_ip_px + 8);
        r_ip_me->ipv6.lo   = BE_TO_U64(icmp_ip_px + 16);
        r_ip_them->ipv6.hi = BE_TO_U64(icmp_ip_px + 24);
        r_ip_them->ipv6.lo = BE_TO_U64(icmp_ip_px + 32);

        *r_icmp_proto = icmp_ip_px[6];
        if (*r_icmp_proto != IP_PROTO_TCP && *r_icmp_proto != IP_PROTO_UDP)
            return false;

        /*length of ipv6 header is fixed*/
        trans_header = (unsigned char *)icmp_ip_px + 40;
        trans_len    = icmp_payload_len - 40;
    } else {
        /*invalid ip version*/
        return false;
    }

    if (trans_len < 4)
        return false;

    *r_port_me   = BE_TO_U16(trans_header);
    *r_port_them = BE_TO_U16(trans_header + 2);

    return true;
}

/***************************************************************************
 ***************************************************************************/
unsigned get_icmp_upper_proto(const unsigned char *transport_px) {
    const unsigned char *ip_header_in_icmp = transport_px + 8;

    if (ip_header_in_icmp[0] >> 4 == 4) {
        return ip_header_in_icmp[9];
    } else if (ip_header_in_icmp[0] >> 4 == 6) {
        return ip_header_in_icmp[6];
    }

    return 0;
}