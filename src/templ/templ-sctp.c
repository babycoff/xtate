/**
        SCTP Node A |<-------- Network transport ------->| SCTP Node B
       _____________                                      _____________
      |  SCTP User  |                                    |  SCTP User  |
      | Application |                                    | Application |
      |-------------|                                    |-------------|
      |    SCTP     |                                    |    SCTP     |
      |  Transport  |                                    |  Transport  |
      |   Service   |                                    |   Service   |
      |-------------|                                    |-------------|
      |             |One or more    ----      One or more|             |
      | IP Network  |IP address      \/        IP address| IP Network  |
      |   Service   |appearances     /\       appearances|   Service   |
      |_____________|               ----                 |_____________|

  The SCTP packet format is shown below:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        Common Header                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Chunk #1                             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           ...                                 |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Chunk #n                             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  SCTP Common Header Format

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Source Port Number        |     Destination Port Number   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Verification Tag                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Checksum                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  SCTP common chunk

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Chunk Type  | Chunk  Flags  |        Chunk Length           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       \                                                               \
       /                          Chunk Value                          /
       \                                                               \
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 SCTP INIT chunk
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Type = 1    |  Chunk Flags  |      Chunk Length             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Initiate Tag                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Advertised Receiver Window Credit (a_rwnd)          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Number of Outbound Streams   |  Number of Inbound Streams    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Initial TSN                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       \                                                               \
       /              Optional/Variable-Length Parameters              /
       \                                                               \
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   SCTP INIT ACK chunk

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Type = 2    |  Chunk Flags  |      Chunk Length             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Initiate Tag                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |              Advertised Receiver Window Credit                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Number of Outbound Streams   |  Number of Inbound Streams    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          Initial TSN                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       \                                                               \
       /              Optional/Variable-Length Parameters              /
       \                                                               \
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#include "templ-sctp.h"

#include <string.h>

#include "../globals.h"
#include "../util-out/logger.h"
#include "../util-misc/checksum.h"
#include "../util-data/data-convert.h"

static size_t
sctp_create_by_template_ipv4(const TmplPkt *tmpl, ipv4address ip_them,
                             unsigned port_them, ipv4address ip_me,
                             unsigned port_me, unsigned init_tag, unsigned ttl,
                             unsigned char *px, size_t sizeof_px) {
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum_sctp;
    unsigned xsum_ip;

    unsigned ip_id = ip_them ^ port_them ^ init_tag;
    unsigned r_len = tmpl->ipv4.length;

    if (sizeof_px < r_len) {
        LOG(LEVEL_ERROR, "(sctp_create_by_template_ipv4) buffer too small\n");
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
    unsigned ip_len   = tmpl->ipv4.length - tmpl->ipv4.offset_ip;
    px[offset_ip + 2] = (unsigned char)(ip_len >> 8);
    px[offset_ip + 3] = (unsigned char)(ip_len >> 0);
    U16_TO_BE(px + offset_ip + 4, ip_id);

    if (ttl)
        px[offset_ip + 8] = (unsigned char)(ttl);

    U32_TO_BE(px + offset_ip + 12, ip_me);
    U32_TO_BE(px + offset_ip + 16, ip_them);

    /*set ip header checksum to zero*/
    U16_TO_BE(px + offset_ip + 10, 0);

    xsum_ip = checksum_ipv4_header(px, offset_ip, tmpl->ipv4.offset_app);

    U16_TO_BE(px + offset_ip + 10, xsum_ip);

    U16_TO_BE(px + offset_tcp + 0, port_me);
    U16_TO_BE(px + offset_tcp + 2, port_them);
    U32_TO_BE(px + offset_tcp + 16, init_tag);

    /*
     * Now do the checksum for the higher layer protocols
     */
    xsum_sctp = checksum_sctp(px + offset_tcp, r_len - offset_tcp);
    U32_TO_BE(px + offset_tcp + 8, xsum_sctp);

    return r_len;
}

static size_t
sctp_create_by_template_ipv6(const TmplPkt *tmpl, ipv6address ip_them,
                             unsigned port_them, ipv6address ip_me,
                             unsigned port_me, unsigned init_tag, unsigned ttl,
                             unsigned char *px, size_t sizeof_px) {
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum_sctp;

    unsigned r_len = tmpl->ipv6.length;

    if (sizeof_px < r_len) {
        LOG(LEVEL_ERROR, "(sctp_create_by_template_ipv6) buffer too small\n");
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
    /*
     * Fill in the empty fields in the IP header and then re-calculate
     * the checksum.
     */
    unsigned payload_length = tmpl->ipv6.length - tmpl->ipv6.offset_ip - 40;
    U16_TO_BE(px + offset_ip + 4, payload_length);

    if (ttl)
        px[offset_ip + 7] = (unsigned char)(ttl);

    U64_TO_BE(px + offset_ip + 8, ip_me.hi);
    U64_TO_BE(px + offset_ip + 16, ip_me.lo);

    U64_TO_BE(px + offset_ip + 24, ip_them.hi);
    U64_TO_BE(px + offset_ip + 32, ip_them.lo);

    U16_TO_BE(px + offset_tcp + 0, port_me);
    U16_TO_BE(px + offset_tcp + 2, port_them);
    U32_TO_BE(px + offset_tcp + 16, init_tag);

    xsum_sctp = checksum_sctp(px + offset_tcp, r_len - offset_tcp);
    U32_TO_BE(px + offset_tcp + 8, xsum_sctp);

    return r_len;
}

size_t sctp_create_by_template(const TmplPkt *tmpl, ipaddress ip_them,
                               unsigned port_them, ipaddress ip_me,
                               unsigned port_me, unsigned init_tag,
                               unsigned ttl, unsigned char *px,
                               size_t sizeof_px) {
    if (tmpl->tmpl_type != TmplType_SCTP) {
        LOG(LEVEL_ERROR,
            "sctp_create_by_template: need a TmplType_SCTP TemplatePacket.\n");
        return 0;
    }

    size_t r_len = 0;

    if (ip_them.version == 4) {
        r_len = sctp_create_by_template_ipv4(tmpl, ip_them.ipv4, port_them,
                                             ip_me.ipv4, port_me, init_tag, ttl,
                                             px, sizeof_px);
    } else {
        r_len = sctp_create_by_template_ipv6(tmpl, ip_them.ipv6, port_them,
                                             ip_me.ipv6, port_me, init_tag, ttl,
                                             px, sizeof_px);
    }
    return r_len;
}

size_t sctp_create_packet(ipaddress ip_them, unsigned port_them,
                          ipaddress ip_me, unsigned port_me, unsigned init_tag,
                          unsigned ttl, unsigned char *px, size_t sizeof_px) {
    return sctp_create_by_template(&global_tmplset->pkts[TmplType_SCTP],
                                   ip_them, port_them, ip_me, port_me, init_tag,
                                   ttl, px, sizeof_px);
}