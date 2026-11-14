#include "scan-modules.h"
#include "../probe-modules/probe-modules.h"
#include "../generate-modules/generate-modules.h"

#include <stdlib.h>

#include "../xconf.h"
#include "../stub/stub-pcap-dlt.h"
#include "../target/target-cookie.h"
#include "../templ/templ-icmp.h"
#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

/** echo request and reply ICMP(v4/v6) according to RFC792 and RFC4443.
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-

   We set fields in echo request packets as following:
    1.identifier: cookie of ip_them, ip_me and TTL for identifying response for
    us. TTL is used to avoid same `identifier` for same path.
    2.sequence: TTL. This is for identifying distance.

   NOTE: The IP header wrapped in responsed ICMP payload isn't be totally same
   as what we sent. Especially the TTL in the IP header in ICMP payload. So we
   must save the initial TTL in a field.

   NOTE: Payload of responsed ICMP message can only contains an IP header and
   other 8 bytes data according to RFC(maybe some hosts can contain more data).
   So lenght of our packets should better be less than 8 bytes(no any other
   data). And this makes recursive preprocess being correct.
*/

extern Scanner YarrpEchoScan; /*for internal x-ref*/

struct YarrpEchoConf {
    unsigned record_ttl        : 1;
    unsigned record_ipid       : 1;
    unsigned record_icmp_id    : 1;
    unsigned record_icmp_seqno : 1;
    unsigned record_icmp_ip_me : 1;
};

static struct YarrpEchoConf yarrpecho_conf = {0};

static ConfRes SET_record_icmp_ip_me(void *conf, const char *name,
                                     const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpecho_conf.record_icmp_ip_me = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_icmp_seqno(void *conf, const char *name,
                                     const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpecho_conf.record_icmp_seqno = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_icmp_id(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpecho_conf.record_icmp_id = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpecho_conf.record_ttl = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ipid(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpecho_conf.record_ipid = conf_parse_bool(value);

    return Conf_OK;
}

static ConfParam yarrpecho_parameters[] = {
    {"record-ttl",
     SET_record_ttl,
     Type_FLAG,
     {"ttl", 0},
     "Records TTL for IPv4 or Hop Limit for IPv6."},
    {"record-ipid",
     SET_record_ipid,
     Type_FLAG,
     {"ipid", 0},
     "Records IPID just for IPv4."},
    {"record-icmp-id",
     SET_record_icmp_id,
     Type_FLAG,
     {"icmp-id", 0},
     "Records ICMP identifier number of ttl/hop limit exceeded message."},
    {"record-icmp-seqno",
     SET_record_icmp_seqno,
     Type_FLAG,
     {"icmp-seqno", 0},
     "Records ICMP sequence number of ttl/hop limit exceeded message."},
    {"record-icmp-ip-me",
     SET_record_icmp_ip_me,
     Type_FLAG,
     {"icmp-ip-me", 0},
     "Records source IP in ICMP ttl/hop limit exceeded message. It can be "
     "different from the outside source IP sometimes."},

    {0}};

static bool yarrpecho_init(const XConf *xconf) {
    if (strcmp(xconf->generator->name, "blackrock") != 0) {
        LOG(LEVEL_ERROR, "(yarrp echo) only support default generator\n");
        return false;
    }

    return true;
}

static bool yarrpecho_transmit(uint64_t entropy, ScanTarget *target,
                               unsigned char *px, size_t *len) {
    if (target->target.ip_proto != IP_PROTO_Other)
        return false;

    unsigned ttl    = target->target.port_them;
    unsigned cookie = get_cookie(target->target.ip_them, ttl,
                                 target->target.ip_me, 0, entropy);
    uint16_t id     = cookie & 0xFF;
    uint16_t ipid   = cookie ^ entropy;

    *len =
        icmp_echo_create_packet(target->target.ip_them, target->target.ip_me,
                                id, ttl, ipid, ttl, NULL, 0, px, PKT_BUF_SIZE);

    /*doesn't need timeout*/

    return false;
}

static void yarrpecho_validate(uint64_t entropy, Recved *recved,
                               PreHandle *pre) {
    /*record icmp to my ip*/
    if (recved->parsed.found == FOUND_ICMP && recved->is_myip)
        pre->go_record = 1;
    else
        return;

    /*echo reply*/
    if ((recved->parsed.src_ip.version == 4 &&
         recved->parsed.icmp_type == ICMPv4_TYPE_ECHO_REPLY &&
         recved->parsed.icmp_code == ICMPv4_CODE_ECHO_REPLY) ||
        (recved->parsed.src_ip.version == 6 &&
         recved->parsed.icmp_type == ICMPv6_TYPE_ECHO_REPLY &&
         recved->parsed.icmp_code == ICMPv6_CODE_ECHO_REPLY)) {

        ipaddress ip_them = recved->parsed.src_ip;
        ipaddress ip_me   = recved->parsed.dst_ip;
        unsigned  cookie =
            get_cookie(ip_them, recved->parsed.icmp_seqno, ip_me, 0, entropy);

        if (recved->parsed.icmp_id == (cookie & 0xFF)) {
            /**
             * We must save all echo replys because the one with min initial TTL
             * is not always come back firstly.
             */
            pre->go_dedup        = 1;
            pre->dedup_port_them = recved->parsed.icmp_seqno;
            pre->dedup_port_me   = 0;
        } else {
            /* Not a reply to our probe: do not report it. */
            pre->go_record = 0;
        }

        return;
    }

    /*TTL exceeded*/
    if ((recved->parsed.src_ip.version == 4 &&
         recved->parsed.icmp_type == ICMPv4_TYPE_TTL_EXCEEDED &&
         recved->parsed.icmp_code == ICMPv4_CODE_TTL_EXCEEDED) ||
        (recved->parsed.src_ip.version == 6 &&
         recved->parsed.icmp_type == ICMPv6_TYPE_HOPLIMIT_EXCEEDED &&
         recved->parsed.icmp_code == ICMPv6_CODE_HOPLIMIT_EXCEEDED)) {

        PreInfo info = {0};
        if (preprocess_frame(recved->packet + recved->parsed.app_offset,
                             recved->length - recved->parsed.app_offset,
                             PCAP_DLT_RAW, &info) &&
            info.ip_protocol == IP_PROTO_ICMP) {
            /**
             * NOTE:Must use saved TTL instead of the fake one in IP header from
             * ICMP payload.
             */
            ipaddress ip_them = info.dst_ip;
            ipaddress ip_me   = info.src_ip;
            unsigned  cookie =
                get_cookie(ip_them, info.icmp_seqno, ip_me, 0, entropy);

            if (info.icmp_id == (cookie & 0xFF)) {
                pre->go_dedup = 1;
                /* The outer source is a router, not the original target; use
                 * the quoted destination so results for different targets at
                 * the same hop/TTL do not collide in the dedup table. */
                pre->dedup_ip_them   = info.dst_ip;
                pre->dedup_port_them = info.icmp_seqno;
                pre->dedup_port_me   = 0;
            } else {
                pre->go_record = 0;
            }
        } else {
            /* Cannot parse the quoted packet: not a valid yarrp result. */
            pre->go_record = 0;
        }
    }
}

static void yarrpecho_handle(unsigned th_idx, uint64_t entropy,
                             ValidPacket *valid_pkt, OutItem *item,
                             NetStack *stack) {
    if (valid_pkt->repeats) {
        item->no_output = 1;
        return;
    }
    Recved *recved = &valid_pkt->recved;

    item->target.port_them = 0;
    item->target.port_me   = 0;
    item->no_port          = 1;
    item->level            = OUT_SUCCESS;

    if (yarrpecho_conf.record_ttl)
        dach_set_int(&item->scan_report, "ttl", recved->parsed.ip_ttl);
    if (yarrpecho_conf.record_ipid && recved->parsed.src_ip.version == 4)
        dach_set_int(&item->scan_report, "ipid", recved->parsed.ip_v4_id);

    /*echo reply*/
    if ((recved->parsed.src_ip.version == 4 &&
         recved->parsed.icmp_type == ICMPv4_TYPE_ECHO_REPLY &&
         recved->parsed.icmp_code == ICMPv4_CODE_ECHO_REPLY) ||
        (recved->parsed.src_ip.version == 6 &&
         recved->parsed.icmp_type == ICMPv6_TYPE_ECHO_REPLY &&
         recved->parsed.icmp_code == ICMPv6_CODE_ECHO_REPLY)) {
        ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(item->target.ip_them);
        safe_strcpy(item->reason, OUT_RSN_SIZE, "echo reply");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "destination");
        dach_set_int(&item->scan_report, "distance", recved->parsed.icmp_seqno);
        dach_append_str(&item->scan_report, "destination", ip_them_fmt.string,
                        strlen(ip_them_fmt.string));
    } else {
        /*ttl/hop limit exceeded*/
        PreInfo info = {0};
        if (!preprocess_frame(recved->packet + recved->parsed.app_offset,
                              recved->length - recved->parsed.app_offset,
                              PCAP_DLT_RAW, &info)) {
            /* Cannot parse the quoted datagram: no usable path information. */
            item->no_output = 1;
            return;
        }

        if (yarrpecho_conf.record_icmp_id)
            dach_set_int(&item->scan_report, "icmp id", info.icmp_id);
        if (yarrpecho_conf.record_icmp_seqno)
            dach_set_int(&item->scan_report, "icmp seqno", info.icmp_seqno);
        if (yarrpecho_conf.record_icmp_ip_me) {
            ipaddress_formatted_t icmp_ip_me_fmt = ipaddress_fmt(info.src_ip);
            dach_append_str(&item->scan_report, "icmp ip_me",
                            icmp_ip_me_fmt.string,
                            strlen(icmp_ip_me_fmt.string));
        }

        ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(info.dst_ip);
        safe_strcpy(item->reason, OUT_RSN_SIZE, "ttl exceeded");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "path");
        /**
         * NOTE:Must use saved TTL instead of the fake one in IP header from
         * ICMP payload.
         */
        dach_set_int(&item->scan_report, "distance", info.icmp_seqno);
        dach_append_str(&item->scan_report, "destination", ip_them_fmt.string,
                        strlen(ip_them_fmt.string));
    }
}

Scanner YarrpEchoScan = {
    .name                = "yarrp-echo",
    .required_probe_type = ProbeType_NULL,
    .params              = yarrpecho_parameters,
    /*icmp echo reply and ttl/hop limit exceeded in ipv4 & ipv6*/
    .bpf_filter = "(icmp && ((icmp[0]==0 && icmp[1]==0)||(icmp[0]==11 && "
                  "icmp[1]==0))) || (icmp6 && ((icmp6[0]==129 && "
                  "icmp6[1]==0)||(icmp6[0]==3 && icmp6[1]==0)))",
    .short_desc = "ICMP Ping to trace the route path statelessly.",
    .desc =
        "YarrpEcho sends ICMP ECHO Request packets with different TTL values "
        "to target hosts and expects ICMP Echo Reply or ICMP TTL/Hop Limit "
        "Exceeded message for tracing the route path. This scanner uses the "
        "core idea of the stateless traceroute tool Yarrp, so it sends all "
        "target/ttl combinations in random order. We need to reconstruct the "
        "paths offline from the discrete, stateless results.\n"
        "NOTE1: We need to specify TTL ranges manually by \"Other\" "
        "port type. E.g. `--port o:1-20` means TTL range from 1 to 20.\n"
        "NOTE2: Consider the network pressure on hosts along the path. "
        "Yarrp's completely stateless route-tracing method can hit nearby "
        "hop hosts many times.\n"
        "NOTE3: A proper TTL range matters for both efficiency and network "
        "load on target hosts. A large range can hit target hosts repeatedly.",

    .init_cb     = &yarrpecho_init,
    .transmit_cb = &yarrpecho_transmit,
    .validate_cb = &yarrpecho_validate,
    .handle_cb   = &yarrpecho_handle,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};