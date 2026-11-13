#include "scan-modules.h"
#include "../probe-modules/probe-modules.h"
#include "../generate-modules/generate-modules.h"

#include <stdlib.h>

#include "../xconf.h"
#include "../templ/templ-udp.h"
#include "../templ/templ-icmp.h"
#include "../stub/stub-pcap-dlt.h"
#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

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

   We set fields in echo request packets as following:
    1.destination port: port_them_offset+TTL. This is for identifying distance.
    2.source port: This is for identifying packets and we have two resolutions:
        (1)source port = port_me_offset-TTL, so that:
            dst_port-port_them_offset == port_me_offset-src_port
           This is a tricky way of cookie setting for a UDP packet without data.
        (1)source port = port_me_offset+TTL, so that:
            src_port+(dst_port-port_them_offset) == port_me_offset
           This is a tricky way of cookie setting for a UDP packet without data.


   NOTE: The IP header wrapped in responsed ICMP payload isn't be totally same
   as what we sent. Especially the TTL in the IP header in ICMP payload. So we
   must save the initial TTL in a field.

   NOTE: Payload of responsed ICMP message can only contains an IP header and
   other 8 bytes data according to RFC(maybe some hosts can contain more data).
   So length of our packets should better be less than 8 bytes(no any other
   data). And this makes recursive preprocess being correct.
*/

extern Scanner YarrpUdpScan; /*for internal x-ref*/

#define DEFAULT_INIT_PORT 33434

struct YarrpUdpConf {
    unsigned port_me;
    unsigned port_me_offset;
    unsigned port_them_offset;
    unsigned fixed_port_me_set  : 1;
    unsigned init_port_me_set   : 1;
    unsigned init_port_them_set : 1;
    unsigned record_ttl         : 1;
    unsigned record_ipid        : 1;
    unsigned record_icmp_id     : 1;
    unsigned record_icmp_seqno  : 1;
    unsigned record_icmp_ip_me  : 1;
};

static struct YarrpUdpConf yarrpudp_conf = {0};

static ConfRes SET_record_icmp_ip_me(void *conf, const char *name,
                                     const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpudp_conf.record_icmp_ip_me = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_icmp_seqno(void *conf, const char *name,
                                     const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpudp_conf.record_icmp_seqno = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_icmp_id(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpudp_conf.record_icmp_id = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_port_me(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpudp_conf.port_me           = conf_parse_int(value);
    yarrpudp_conf.fixed_port_me_set = 1;

    return Conf_OK;
}

static ConfRes SET_init_port_me(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpudp_conf.port_me_offset   = conf_parse_int(value) + 1;
    yarrpudp_conf.init_port_me_set = 1;

    return Conf_OK;
}

static ConfRes SET_init_port_them(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpudp_conf.port_them_offset   = conf_parse_int(value) - 1;
    yarrpudp_conf.init_port_them_set = 1;

    return Conf_OK;
}

static ConfRes SET_record_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpudp_conf.record_ttl = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ipid(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    yarrpudp_conf.record_ipid = conf_parse_bool(value);

    return Conf_OK;
}

static ConfParam yarrpudp_parameters[] = {
    {"init-target-port",
     SET_init_port_them,
     Type_ARG,
     {"target-port", 0},
     "Set initial UDP target port for packets we send with TTL of 1. The actual"
     " UDP target port we send packets to would increase by the TTL which we "
     "set in packets. In other word, we set TTL to destination port field of "
     "UDP"
     " packet. Default initial UDP target port is 33434.\n"
     "NOTE: Be careful to the backwind of sum of initial target port and TTL."},
    {"init-source-port",
     SET_init_port_me,
     Type_ARG,
     {"init-src-port", 0},
     "Set initial UDP source port for packets we send with TTL of 1. The actual"
     " UDP source port we send packets to would decrease by the TTL which we "
     "set in packets. Source port is for identifying if the packet is ours. "
     "Default initial UDP source port is random from 40000 to 60000.\n"
     "NOTE: Be careful to the backwind of difference between initial target "
     "port and TTL."},
    {"fixed-source-port",
     SET_port_me,
     Type_ARG,
     {"source-port", "src-port", 0},
     "Set fixed UDP source port for packets we send. Source port is for "
     "identifying if the packet is ours. Default UDP source port varias with "
     "TTL and its initial value is random from 40000 to 60000."},
    {"record-ttl",
     SET_record_ttl,
     Type_FLAG,
     {"ttl", 0},
     "Records TTL for IPv4 or Hop Limit for IPv6 in ICMP Port Unreachable or "
     "ttl/hop limit exceeded response."},
    {"record-ipid",
     SET_record_ipid,
     Type_FLAG,
     {"ipid", 0},
     "Records IPID just for IPv4 of ICMP Port Unreachable or ttl/hop limit "
     "exceeded response."},
    {"record-icmp-id",
     SET_record_icmp_id,
     Type_FLAG,
     {"icmp-id", 0},
     "Records ICMP identifier number."},
    {"record-icmp-seqno",
     SET_record_icmp_seqno,
     Type_FLAG,
     {"icmp-seqno", 0},
     "Records ICMP sequence number."},
    {"record-icmp-ip-me",
     SET_record_icmp_ip_me,
     Type_FLAG,
     {"icmp-ip-me", 0},
     "Records source IP in ICMP messages. It can be different from the outside "
     "source IP sometimes."},

    {0}};

static bool yarrpudp_init(const XConf *xconf) {
    if (strcmp(xconf->generator->name, "blackrock") != 0) {
        LOG(LEVEL_ERROR, "(yarrp udp) only support default generator\n");
        return false;
    }

    if (!yarrpudp_conf.init_port_them_set) {
        yarrpudp_conf.port_them_offset = DEFAULT_INIT_PORT - 1;
    }

    if (!yarrpudp_conf.init_port_me_set) {
        yarrpudp_conf.port_me_offset = 40000 + xconf->seed % 20000 + 1;
    }

    return true;
}

static bool yarrpudp_transmit(uint64_t entropy, ScanTarget *target,
                              unsigned char *px, size_t *len) {
    if (target->target.ip_proto != IP_PROTO_Other)
        return false;

    unsigned ttl       = target->target.port_them;
    unsigned port_them = yarrpudp_conf.port_them_offset + ttl;
    unsigned port_me   = yarrpudp_conf.fixed_port_me_set
                             ? yarrpudp_conf.port_me
                             : yarrpudp_conf.port_me_offset - ttl;

    *len = udp_create_packet(target->target.ip_them, port_them,
                             target->target.ip_me, port_me, ttl, NULL, 0, px,
                             PKT_BUF_SIZE);

    /*doesn't need timeout*/

    return false;
}

static void yarrpudp_validate(uint64_t entropy, Recved *recved,
                              PreHandle *pre) {
    /*record icmp to my ip*/
    if (recved->parsed.found == FOUND_ICMP && recved->is_myip)
        pre->go_record = 1;
    else
        return;

    /*port unreachable or TTL exceeded*/
    if ((recved->parsed.src_ip.version == 4 &&
         recved->parsed.icmp_type == ICMPv4_TYPE_ERR &&
         recved->parsed.icmp_code == ICMPv4_CODE_ERR_PORT_UNREACHABLE) ||
        (recved->parsed.src_ip.version == 6 &&
         recved->parsed.icmp_type == ICMPv6_TYPE_ERR &&
         recved->parsed.icmp_code == ICMPv6_CODE_ERR_PORT_UNREACHABLE) ||
        (recved->parsed.src_ip.version == 4 &&
         recved->parsed.icmp_type == ICMPv4_TYPE_TTL_EXCEEDED &&
         recved->parsed.icmp_code == ICMPv4_CODE_TTL_EXCEEDED) ||
        (recved->parsed.src_ip.version == 6 &&
         recved->parsed.icmp_type == ICMPv6_TYPE_HOPLIMIT_EXCEEDED &&
         recved->parsed.icmp_code == ICMPv6_CODE_HOPLIMIT_EXCEEDED)) {

        PreInfo info = {0};
        if (preprocess_frame(recved->packet + recved->parsed.app_offset,
                             recved->length - recved->parsed.app_offset,
                             PCAP_DLT_RAW, &info) &&
            info.ip_protocol == IP_PROTO_UDP) {
            /**
             * NOTE:Must use saved TTL instead of the fake one in IP header from
             * ICMP payload.
             */
            unsigned port_them = info.port_dst;
            unsigned port_me   = info.port_src;

            if ((yarrpudp_conf.fixed_port_me_set &&
                 port_me == yarrpudp_conf.port_me) ||
                (!yarrpudp_conf.fixed_port_me_set &&
                 yarrpudp_conf.port_me_offset - port_me ==
                     port_them - yarrpudp_conf.port_them_offset)) {
                pre->go_dedup = 1;
                /* The outer source is a router, not the original target; use
                 * the quoted destination so results for different targets at
                 * the same hop/TTL do not collide in the dedup table. */
                pre->dedup_ip_them   = info.dst_ip;
                pre->dedup_port_them = port_them;
                pre->dedup_port_me   = port_me;
            } else {
                /* Port pair does not belong to our probe. */
                pre->go_record = 0;
            }
        } else {
            /* Cannot parse the quoted UDP packet: not a valid yarrp result. */
            pre->go_record = 0;
        }
    } else {
        /* Not a port-unreachable/hop-limit ICMP error. */
        pre->go_record = 0;
    }
}

static void yarrpudp_handle(unsigned th_idx, uint64_t entropy,
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

    PreInfo info = {0};
    if (!preprocess_frame(recved->packet + recved->parsed.app_offset,
                          recved->length - recved->parsed.app_offset,
                          PCAP_DLT_RAW, &info)) {
        /* Cannot parse the quoted datagram: no usable path information. */
        item->no_output = 1;
        return;
    }

    if (yarrpudp_conf.record_ttl)
        dach_set_int(&item->scan_report, "ttl", recved->parsed.ip_ttl);
    if (yarrpudp_conf.record_ipid && recved->parsed.src_ip.version == 4)
        dach_set_int(&item->scan_report, "ipid", recved->parsed.ip_v4_id);
    if (yarrpudp_conf.record_icmp_id)
        dach_set_int(&item->scan_report, "icmp id", info.icmp_id);
    if (yarrpudp_conf.record_icmp_seqno)
        dach_set_int(&item->scan_report, "icmp seqno", info.icmp_seqno);
    if (yarrpudp_conf.record_icmp_ip_me) {
        ipaddress_formatted_t icmp_ip_me_fmt = ipaddress_fmt(info.src_ip);
        dach_append_str(&item->scan_report, "icmp ip_me", icmp_ip_me_fmt.string,
                        strlen(icmp_ip_me_fmt.string));
    }

    /**
     * NOTE:Must use saved TTL instead of the fake one in IP header from
     * ICMP payload.
     */
    unsigned distance = info.port_dst - yarrpudp_conf.port_them_offset;

    ipaddress_formatted_t icmp_ip_them_fmt = ipaddress_fmt(info.dst_ip);
    dach_set_int(&item->scan_report, "distance", distance);
    dach_append_str(&item->scan_report, "destination", icmp_ip_them_fmt.string,
                    strlen(icmp_ip_them_fmt.string));

    /*port unreachable*/
    if ((recved->parsed.src_ip.version == 4 &&
         recved->parsed.icmp_type == ICMPv4_TYPE_ERR &&
         recved->parsed.icmp_code == ICMPv4_CODE_ERR_PORT_UNREACHABLE) ||
        (recved->parsed.src_ip.version == 6 &&
         recved->parsed.icmp_type == ICMPv6_TYPE_ERR &&
         recved->parsed.icmp_code == ICMPv6_CODE_ERR_PORT_UNREACHABLE)) {
        safe_strcpy(item->reason, OUT_RSN_SIZE, "port unreachable");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "destination");
    } else {
        /*ttl/hop limit exceeded*/
        safe_strcpy(item->reason, OUT_RSN_SIZE, "ttl exceeded");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "path");
    }
}

Scanner YarrpUdpScan = {
    .name                = "yarrp-udp",
    .required_probe_type = ProbeType_NULL,
    .params              = yarrpudp_parameters,
    /*icmp port unreachable and ttl/hop limit exceeded in ipv4 & ipv6*/
    .bpf_filter = "(icmp && ((icmp[0]==3 && icmp[1]==3)||(icmp[0]==11 && "
                  "icmp[1]==0))) || (icmp6 && ((icmp6[0]==1 && "
                  "icmp6[1]==4)||(icmp6[0]==3 && icmp6[1]==0)))",
    .short_desc = "UDP scan to trace the route path statelessly.",
    .desc =
        "YarrpUdp sends UDP packets with different TTL values to target hosts "
        "and expects ICMP Port Unreachable or TTL/Hop Limit Exceeded message "
        "for tracing the route path. This scanner uses the core idea of the "
        "stateless traceroute tool Yarrp, so it sends all target/ttl "
        "combinations in random. We need to reconstruct the paths off-linely "
        "with the discrete results of because of stateless.\n"
        "NOTE1: We need to specify TTL ranges manually by \"Other\" "
        "port type. E.g. `--port o:1-20` means TTL range from 1 to 20. The "
        "actual target UDP port is specified by subparam.\n"
        "NOTE2: We should care the network pressure of hosts in the path. "
        "Yarrp's completely stateless route tracing method would make close "
        "hop hosts being hit a lot.\n"
        "NOTE3: Proper TTL range is import both for efficiency and network "
        "pressure of target hosts. A big range may hit target hosts a lot.",

    .init_cb     = &yarrpudp_init,
    .transmit_cb = &yarrpudp_transmit,
    .validate_cb = &yarrpudp_validate,
    .handle_cb   = &yarrpudp_handle,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};