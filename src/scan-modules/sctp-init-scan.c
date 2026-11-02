#include "scan-modules.h"
#include "../probe-modules/probe-modules.h"

#include <stdlib.h>

#include "../target/target-cookie.h"
#include "../templ/templ-sctp.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Scanner SctpInitScan; /*for internal x-ref*/

struct SctpInitConf {
    unsigned record_ttl  : 1;
    unsigned record_ipid : 1;
};

static struct SctpInitConf sctpinit_conf = {0};

static ConfRes SET_record_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    sctpinit_conf.record_ttl = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ipid(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    sctpinit_conf.record_ipid = conf_parse_bool(value);

    return Conf_OK;
}

static ConfParam sctpinit_parameters[] = {
    {"record-ttl",
     SET_record_ttl,
     Type_FLAG,
     {"ttl", 0},
     "Records TTL for IPv4 or Hop Limit for IPv6 in SCTP response."},
    {"record-ipid",
     SET_record_ipid,
     Type_FLAG,
     {"ipid", 0},
     "Records IPID of SCTP response just for IPv4."},

    {0}};
static bool sctpinit_transmit(uint64_t entropy, ScanTarget *target,
                              unsigned char *px, size_t *len) {
    /*we just handle sctp target*/
    if (target->target.ip_proto != IP_PROTO_SCTP)
        return false;

    unsigned cookie =
        get_cookie(target->target.ip_them, target->target.port_them,
                   target->target.ip_me, target->target.port_me, entropy);

    *len = sctp_create_packet(target->target.ip_them, target->target.port_them,
                              target->target.ip_me, target->target.port_me,
                              cookie, 0, px, PKT_BUF_SIZE);

    return false;
}

static void sctpinit_validate(uint64_t entropy, Recved *recved,
                              PreHandle *pre) {
    /*record all sctp to me*/
    if (recved->parsed.found == FOUND_SCTP && recved->is_myip &&
        recved->is_myport)
        pre->go_record = 1;
    else
        return;

    /*packet is too short*/
    if (recved->parsed.transport_offset + 16 > recved->length)
        return;

    ipaddress ip_them   = recved->parsed.src_ip;
    ipaddress ip_me     = recved->parsed.dst_ip;
    unsigned  port_them = recved->parsed.port_src;
    unsigned  port_me   = recved->parsed.port_dst;

    unsigned veri_tag =
        SCTP_VERI_TAG(recved->packet, recved->parsed.transport_offset);
    unsigned cookie = get_cookie(ip_them, port_them, ip_me, port_me, entropy);

    if (cookie != veri_tag)
        return;

    if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
                           SCTP_CHUNK_TYPE_INIT_ACK)) {
        pre->go_dedup = 1;
    } else if (SCTP_IS_CHUNK_TYPE(recved->packet,
                                  recved->parsed.transport_offset,
                                  SCTP_CHUNK_TYPE_ABORT)) {
        pre->go_dedup = 1;
    }
}

static void sctpinit_handle(unsigned th_idx, uint64_t entropy,
                            ValidPacket *valid_pkt, OutItem *item,
                            NetStack *stack) {
    if (valid_pkt->repeats) {
        item->no_output = 1;
        return;
    }
    Recved *recved = &valid_pkt->recved;

    if (SCTP_IS_CHUNK_TYPE(recved->packet, recved->parsed.transport_offset,
                           SCTP_CHUNK_TYPE_INIT_ACK)) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "init-ack");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "open");
    } else if (SCTP_IS_CHUNK_TYPE(recved->packet,
                                  recved->parsed.transport_offset,
                                  SCTP_CHUNK_TYPE_ABORT)) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "abort");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "closed");
    }

    if (sctpinit_conf.record_ttl)
        dach_set_int(&item->scan_report, "ttl", recved->parsed.ip_ttl);
    if (sctpinit_conf.record_ipid && recved->parsed.src_ip.version == 4)
        dach_set_int(&item->scan_report, "ipid", recved->parsed.ip_v4_id);
}

Scanner SctpInitScan = {
    .name                = "sctp-init",
    .required_probe_type = ProbeType_NULL,
    .params              = sctpinit_parameters,
    /*sctp init or init ack in ipv4 & ipv6*/
    .bpf_filter          = "(ip && sctp && (sctp[12]==2 || sctp[12]==6)) "
                           "|| (ip6 && sctp && (ip6[40+12]==2 || ip6[40+12]==6))",
    .short_desc          = "SCTP INIT scan to find open or closed SCTP port.",
    .desc = "SctpInitScan sends an SCTP INIT packet(chunk) to target port. "
            "Expect an INIT ACK response to believe the port is open or an "
            "ABORT for closed in SCTP protocol.",

    .init_cb     = &scan_init_nothing,
    .transmit_cb = &sctpinit_transmit,
    .validate_cb = &sctpinit_validate,
    .handle_cb   = &sctpinit_handle,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};