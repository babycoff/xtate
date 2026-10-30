#include "scan-modules.h"

#include <stdlib.h>

#include "../target/target-cookie.h"
#include "../templ/templ-tcp.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Scanner TcpSynScan; /*for internal x-ref*/

struct TcpSynConf {
    uint8_t  syn_ttl;
    uint8_t  rst_ttl;
    unsigned synack_limit;
    unsigned synack_floor;
    unsigned send_rst        : 1;
    unsigned zero_fail       : 1;
    unsigned record_ttl      : 1;
    unsigned record_ipid     : 1;
    unsigned record_win      : 1;
    unsigned record_mss      : 1;
    unsigned record_seqno    : 1;
    unsigned record_ackno    : 1;
    unsigned no_dedup_synack : 1;
    unsigned no_dedup_rst    : 1;
    unsigned repeat_synack   : 1;
    unsigned repeat_rst      : 1;
};

static struct TcpSynConf tcpsyn_conf = {0};

static ConfRes SET_synack_floor(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.synack_floor = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_synack_limit(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.synack_limit = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_repeat_rst(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.repeat_rst = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_repeat_synack(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.repeat_synack = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_no_dedup_rst(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.no_dedup_rst = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_no_dedup_synack(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.no_dedup_synack = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ackno(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.record_ackno = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_seqno(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.record_seqno = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_syn_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.syn_ttl = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_rst_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.rst_ttl = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_record_mss(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.record_mss = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.record_ttl = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ipid(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.record_ipid = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_win(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.record_win = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_zero_fail(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.zero_fail = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_send_rst(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    tcpsyn_conf.send_rst = conf_parse_bool(value);

    return Conf_OK;
}

static ConfParam tcpsyn_parameters[] = {
    {"send-rst",
     SET_send_rst,
     Type_FLAG,
     {"rst", 0},
     "Actively send an RST if got a SYN-ACK. This is useful when we are in "
     "bypassing mode or working on Windows and don't want to waste connection"
     " resources of targets."},
    {"fail-zerowin",
     SET_zero_fail,
     Type_FLAG,
     {"fail-zero", "zero-fail", 0},
     "Let SYN-ACK responds with zero window setting as failed. Default is "
     "success."},
    {"record-ttl",
     SET_record_ttl,
     Type_FLAG,
     {"ttl", 0},
     "Records TTL for IPv4 or Hop Limit for IPv6 in SYN-ACK or RST."},
    {"record-ipid",
     SET_record_ipid,
     Type_FLAG,
     {"ipid", 0},
     "Records IPID of SYN-ACK or RST just for IPv4."},
    {"record-win",
     SET_record_win,
     Type_FLAG,
     {"win", "window", 0},
     "Records TCP window size of SYN-ACK or RST."},
    {"record-mss",
     SET_record_mss,
     Type_FLAG,
     {"mss", 0},
     "Records TCP MSS option value of SYN-ACK if the option exists."},
    {"record-seqno",
     SET_record_seqno,
     Type_FLAG,
     {"seqno", 0},
     "Records TCP sequence number."},
    {"record-ackno",
     SET_record_ackno,
     Type_FLAG,
     {"ackno", 0},
     "Records TCP acknowledge number."},
    {"syn-ttl",
     SET_syn_ttl,
     Type_ARG,
     {0},
     "Set TTL of SYN segment to specified value instead of global default."},
    {"rst-ttl",
     SET_rst_ttl,
     Type_ARG,
     {0},
     "Set TTL of RST segment to specified value instead of global default."},
    {"no-dedup-synack",
     SET_no_dedup_synack,
     Type_FLAG,
     {0},
     "Just close the deduplication for received SYN-ACK segments. This is "
     "useful to some researches."},
    {"no-dedup-rst",
     SET_no_dedup_rst,
     Type_FLAG,
     {0},
     "Just close the deduplication for received RST segments. This is useful "
     "to some researches."},
    {"repeat-synack",
     SET_repeat_synack,
     Type_FLAG,
     {0},
     "Allow repeated SYN-ACK segments."},
    {"repeat-rst",
     SET_repeat_rst,
     Type_FLAG,
     {0},
     "Allow repeated RST segments."},
    {"synack-limit",
     SET_synack_limit,
     Type_ARG,
     {"limit-synack", 0},
     "Send RST segment to stop SYN-ACK retransmission after received enough "
     "limitation number while using -send-rst and -repeat-synack params. And "
     "exceeded SYN-ACK segments won't be recorded as results."},
    {"synack-floor",
     SET_synack_floor,
     Type_ARG,
     {"floor-synack", 0},
     "Do not record SYN-ACK segments as results if the number is less than the "
     "floor value while using -repeat-synack param."},

    {0}};

static bool tcpsyn_transmit(uint64_t entropy, ScanTarget *target,
                            unsigned char *px, size_t *len) {
    /*we just handle tcp target*/
    if (target->target.ip_proto != IP_PROTO_TCP)
        return false;

    unsigned cookie =
        get_cookie(target->target.ip_them, target->target.port_them,
                   target->target.ip_me, target->target.port_me, entropy);

    *len = tcp_create_packet(target->target.ip_them, target->target.port_them,
                             target->target.ip_me, target->target.port_me,
                             cookie, 0, TCP_FLAG_SYN, tcpsyn_conf.syn_ttl, 0,
                             NULL, 0, px, PKT_BUF_SIZE);

    return false;
}

static void tcpsyn_validate(uint64_t entropy, Recved *recved, PreHandle *pre) {
    /*record tcp packet to our source port*/
    if (recved->parsed.found == FOUND_TCP && recved->is_myip &&
        recved->is_myport)
        pre->go_record = 1;
    else
        return;

    ipaddress ip_them   = recved->parsed.src_ip;
    ipaddress ip_me     = recved->parsed.dst_ip;
    unsigned  port_them = recved->parsed.port_src;
    unsigned  port_me   = recved->parsed.port_dst;
    unsigned  seqno_me =
        TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned cookie = get_cookie(ip_them, port_them, ip_me, port_me, entropy);
    uint8_t  flags_them =
        TCP_FLAGS(recved->packet, recved->parsed.transport_offset);

    /*SYNACK*/
    if (TCP_FLAG_HAS(flags_them, TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        if (cookie == seqno_me - 1) {
            pre->go_dedup = 1;
            pre->no_dedup = tcpsyn_conf.no_dedup_synack;
        }
    }
    /*RST*/
    else if (TCP_FLAG_HAS(flags_them, TCP_FLAG_RST)) {
        /*NOTE: diff from SYNACK*/
        if (cookie == seqno_me - 1 || cookie == seqno_me) {
            pre->go_dedup = 1;
            pre->no_dedup = tcpsyn_conf.no_dedup_rst;
        }
    }
}

static void tcpsyn_handle(unsigned th_idx, uint64_t entropy,
                          ValidPacket *valid_pkt, OutItem *item,
                          NetStack *stack) {
    unsigned mss_them;
    bool     mss_found;
    Recved  *recved = &valid_pkt->recved;

    uint16_t win_them =
        TCP_WIN(recved->packet, recved->parsed.transport_offset);
    unsigned seqno_me =
        TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned seqno_them =
        TCP_SEQNO(recved->packet, recved->parsed.transport_offset);

    /*SYNACK*/
    if (TCP_HAS_FLAG(recved->packet, recved->parsed.transport_offset,
                     TCP_FLAG_SYN | TCP_FLAG_ACK)) {

        if (!tcpsyn_conf.repeat_synack && valid_pkt->repeats) {
            item->no_output = 1;
            return;
        } else if (tcpsyn_conf.repeat_synack) {
            dach_set_int(&item->scan_report, "repeats", valid_pkt->repeats);
        }

        item->level = OUT_SUCCESS;

        if (win_them == 0) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "fake-open");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "zerowin");

            if (tcpsyn_conf.zero_fail)
                item->level = OUT_FAILURE;
        } else {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "open");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "syn-ack");
        }

        if (tcpsyn_conf.send_rst &&
            (!tcpsyn_conf.synack_limit ||
             (tcpsyn_conf.synack_limit &&
              valid_pkt->repeats >= tcpsyn_conf.synack_limit - 1))) {

            PktBuf *pkt_buffer = stack_get_pktbuf(stack);

            pkt_buffer->length = tcp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, recved->parsed.port_dst, seqno_me,
                seqno_them + 1, TCP_FLAG_RST, tcpsyn_conf.rst_ttl, 0, NULL, 0,
                pkt_buffer->px, PKT_BUF_SIZE);

            stack_transmit_pktbuf(stack, pkt_buffer);
        }

        if (tcpsyn_conf.synack_limit &&
            valid_pkt->repeats >= tcpsyn_conf.synack_limit) {
            item->no_output = 1;
            return;
        }

        if (tcpsyn_conf.synack_floor &&
            valid_pkt->repeats < tcpsyn_conf.synack_floor - 1) {
            item->no_output = 1;
            return;
        }

        if (tcpsyn_conf.record_mss) {
            /*comput of mss is not easy*/
            mss_them = tcp_get_mss(recved->packet, recved->length, &mss_found);
            if (mss_found)
                dach_set_int(&item->scan_report, "mss", mss_them);
        }
    }
    /*RST*/
    else {

        if (!tcpsyn_conf.repeat_rst && valid_pkt->repeats) {
            item->no_output = 1;
            return;
        } else if (tcpsyn_conf.repeat_rst) {
            dach_set_int(&item->scan_report, "repeats", valid_pkt->repeats);
        }

        item->level = OUT_FAILURE;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "rst");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "closed");
    }

    if (tcpsyn_conf.record_ttl)
        dach_set_int(&item->scan_report, "ttl", recved->parsed.ip_ttl);
    if (tcpsyn_conf.record_ipid && recved->parsed.src_ip.version == 4)
        dach_set_int(&item->scan_report, "ipid", recved->parsed.ip_v4_id);
    if (tcpsyn_conf.record_win)
        dach_set_int(&item->scan_report, "win", win_them);
    if (tcpsyn_conf.record_seqno) {
        dach_set_int(&item->scan_report, "seqno", seqno_them);
    }
    if (tcpsyn_conf.record_ackno) {
        dach_set_int(&item->scan_report, "ackno", seqno_me);
    }
}

Scanner TcpSynScan = {
    .name                = "tcp-syn",
    .required_probe_type = ProbeType_NULL,
    .params              = tcpsyn_parameters,
    /* is syn-ack or rst in ipv4 & ipv6*/
    .bpf_filter          = "(ip && tcp && (tcp[tcpflags]==(tcp-syn|tcp-ack) || "
                           "tcp[tcpflags]==tcp-rst || "
                           "tcp[tcpflags]==(tcp-rst|tcp-ack))) "
                           "|| (ip6 && tcp && (ip6[40+13]==(tcp-syn|tcp-ack) || "
                           "ip6[40+13]==tcp-rst || "
                           "ip6[40+13]==(tcp-rst|tcp-ack)))",
    .short_desc          = "TCP SYN scan to find open port.",
    .desc = "TcpSynScan sends a TCP SYN packet to target port. Expect a SYNACK "
            "response to believe the port is open or an RST for closed in TCP "
            "protocol.",

    .init_cb     = &scan_init_nothing,
    .transmit_cb = &tcpsyn_transmit,
    .validate_cb = &tcpsyn_validate,
    .handle_cb   = &tcpsyn_handle,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};