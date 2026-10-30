#include "scan-modules.h"

#include <stdlib.h>

#include "../xconf.h"
#include "../target/target-cookie.h"
#include "../templ/templ-tcp.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"
#include "../util-out/logger.h"

#define ZBANNER_DEDUP_TYPE_PORT   0
#define ZBANNER_DEDUP_TYPE_ACK    1
#define ZBANNER_DEDUP_TYPE_BANNER 2

extern Scanner ZBannerScan; /*for internal x-ref*/

struct ZBannerConf {
    uint8_t  syn_ttl;
    uint8_t  ack_ttl;
    uint8_t  rst_ttl;
    uint8_t  probe_ttl;
    uint8_t  ack_banner_ttl;
    unsigned all_banner_limit;
    unsigned all_banner_floor;
    unsigned all_banner      : 1;
    unsigned is_port_success : 1;
    unsigned is_port_failure : 1;
    unsigned is_ack_success  : 1;
    unsigned record_ttl      : 1;
    unsigned record_ipid     : 1;
    unsigned record_win      : 1;
    unsigned record_mss      : 1;
    unsigned record_seqno    : 1;
    unsigned record_ackno    : 1;
    unsigned record_data_len : 1;
    unsigned record_banner   : 1;
    unsigned record_utf8     : 1;
    unsigned record_data     : 1;
    unsigned record_ack      : 1;
    unsigned with_ack        : 1;
    unsigned no_rst          : 1;
    unsigned no_dedup_banner : 1;
    unsigned no_dedup_synack : 1;
    unsigned no_dedup_rst    : 1;
    unsigned no_dedup_ack    : 1;
    unsigned repeat_banner   : 1;
    unsigned repeat_synack   : 1;
    unsigned repeat_rst      : 1;
    unsigned repeat_ack      : 1;
};

static struct ZBannerConf zbanner_conf = {0};

static ConfRes SET_all_banner_floor(void *conf, const char *name,
                                    const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.all_banner_floor = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_all_banner_limit(void *conf, const char *name,
                                    const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.all_banner_limit = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_repeat_ack(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.repeat_ack = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_repeat_rst(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.repeat_rst = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_repeat_synack(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.repeat_synack = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_repeat_banner(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.repeat_banner = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_all_banner(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.all_banner = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ack(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_ack = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_no_dedup_ack(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.no_dedup_ack = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_no_dedup_rst(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.no_dedup_rst = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_no_dedup_synack(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.no_dedup_synack = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_no_dedup_banner(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.no_dedup_banner = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_data(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_data = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_banner(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_banner = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_utf8(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_utf8 = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_data_len(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_data_len = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ackno(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_ackno = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_seqno(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_seqno = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_ack_banner_ttl(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.ack_banner_ttl = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_probe_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.probe_ttl = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_rst_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.rst_ttl = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_ack_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.ack_ttl = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_syn_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.syn_ttl = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_no_rst(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.no_rst = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_with_ack(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.with_ack = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_mss(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_mss = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ttl(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_ttl = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_ipid(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_ipid = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_record_win(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.record_win = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_port_success(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.is_port_success = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_port_failure(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.is_port_failure = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_ack_success(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    zbanner_conf.is_ack_success = conf_parse_bool(value);

    return Conf_OK;
}

static ConfParam zbanner_parameters[] = {
    {"record-banner",
     SET_record_banner,
     Type_FLAG,
     {"banner", 0},
     "Records banner content in escaped text style."},
    {"record-utf8",
     SET_record_utf8,
     Type_FLAG,
     {"utf8", 0},
     "Records banner content with escaped valid utf8 encoding."},
    {"record-data",
     SET_record_data,
     Type_FLAG,
     {"data", 0},
     "Records data content in binary format."},
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
    {"record-data-len",
     SET_record_data_len,
     Type_FLAG,
     {"data-len", "len", 0},
     "Records payload data length of ACK segments if data exists."},
    {"record-ack",
     SET_record_ack,
     Type_FLAG,
     {"ack", 0},
     "Records ACK segments for our probe but without payload data as info."},
    {"port-success",
     SET_port_success,
     Type_FLAG,
     {"success-port", 0},
     "Let port opening(contains zero syn-ack) results as success level."
     "(Default is info level)"},
    {"port-failure",
     SET_port_failure,
     Type_FLAG,
     {"failure-port", "port-fail", "fail-port", 0},
     "Let port closed results as failure level.(Default is info level)"},
    {"ack-success",
     SET_ack_success,
     Type_FLAG,
     {"success-ack", 0},
     "Let ACK semgents without payload for our probe results as success level."
     "(Default is info level)"},
    {"with-ack",
     SET_with_ack,
     Type_FLAG,
     {0},
     "Send an seperate ACK segment after receiving non-zerowin SYNACK segment "
     "from target port. This makes a complete standard TCP 3-way handshake "
     "before sending segment with data(probe) and spends more bandwidth while "
     "scanning. But some servers(not very sure) may only accept this kind of "
     "connections. However, it's the early version of ZBanner and can also be "
     "used for research."},
    {"no-rst",
     SET_no_rst,
     Type_FLAG,
     {0},
     "Do not send RST segment after got banner. It's used for research."},
    {"all-banner",
     SET_all_banner,
     Type_FLAG,
     {"banner-all", 0},
     "Try to get all banner by acknowledging all received segments with "
     "data(deduped by data length) instead of sending RST segment to close the "
     "connection.\n"
     "NOTE1: This could cause some problem while using ProbeModule in "
     "Multi_AfterHandle mode.\n"
     "NOTE2: This may get so many segments with banner data. We can use some "
     "global params to adjust it. (e.g. --tcp-win, --max-packet-len, "
     "--snaplen)"},
    {"all-banner-limit",
     SET_all_banner_limit,
     Type_ARG,
     {"banner-limit", "limit-banner", 0},
     "After received limited number of ACK segments with banner data then send "
     "RST segment to close the connection if the number is enough in "
     "all-banner mode. Exceeded ACK segments with banner data won't be "
     "recorded as results and won't trigger Multi_DynamicNext or "
     "Multi_AfterHandle."},
    {"all-banner-floor",
     SET_all_banner_floor,
     Type_ARG,
     {"banner-floor", "floor-banner", 0},
     "Do not record ACK segments with banner data as results if the number is "
     "less than the floor value while in all-banner mode. And non-recorded "
     "segments won't trigger Multi_DynamicNext or Multi_AfterHandle."},
    {"syn-ttl",
     SET_syn_ttl,
     Type_ARG,
     {0},
     "Set TTL of SYN segment to specified value instead of global default."},
    {"ack-ttl",
     SET_ack_ttl,
     Type_ARG,
     {0},
     "Set TTL of ACK segment during 3-way handshake to specified value instead "
     "of global default."},
    {"rst-ttl",
     SET_rst_ttl,
     Type_ARG,
     {0},
     "Set TTL of RST segment to specified value instead of global default."},
    {"probe-ttl",
     SET_probe_ttl,
     Type_ARG,
     {0},
     "Set TTL of ACK segment with probe data to specified value instead of "
     "global default."},
    {"ack-banner-ttl",
     SET_ack_banner_ttl,
     Type_ARG,
     {"banner-ttl", 0},
     "Set TTL of ACK segment for received banner data to specified value "
     "instead of global default in all-banner mode."},
    {"no-dedup-banner",
     SET_no_dedup_banner,
     Type_FLAG,
     {0},
     "Just close the deduplication for received packets with banner. This is "
     "useful to test the retransmission of target port after tcp connection "
     "established. e.g. we can close banner deduplication and RST sending to "
     "test it. In that case, use global `-nodedup` to close all deduplication "
     "would cause our possible probe retransmission if received multiple "
     "SYN-ACK segments."},
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
    {"no-dedup-ack",
     SET_no_dedup_ack,
     Type_FLAG,
     {0},
     "Just close the deduplication for received ACK segments without payload. "
     "This is useful to some researches."},
    {"repeat-banner",
     SET_repeat_banner,
     Type_FLAG,
     {0},
     "Allow repeated ACK segments with banner data."},
    {"repeat-synack",
     SET_repeat_synack,
     Type_FLAG,
     {0},
     "Allow repeated SYN-ACK segments."},
    {"repeat-ack",
     SET_repeat_ack,
     Type_FLAG,
     {0},
     "Allow repeated ACK segments without data."},
    {"repeat-rst",
     SET_repeat_rst,
     Type_FLAG,
     {0},
     "Allow repeated RST segments."},

    {0}};

/**
 *For calc the conn index.
 * NOTE: We use a trick of src-port to differenciate multi-probes to avoid
 * mutual interference of connections.
 * Be careful to the source port range and probe num. Source port range is 256
 *in default and can be set with flag `--source-port`.
 */
static unsigned src_port_start;

static bool zbanner_init(const XConf *xconf) {
    src_port_start = xconf->nic.src.port.first;

    return true;
}

static bool zbanner_transmit(uint64_t entropy, ScanTarget *target,
                             unsigned char *px, size_t *len) {
    /*we just handle tcp target*/
    if (target->target.ip_proto != IP_PROTO_TCP)
        return false;

    unsigned seqno = get_cookie(target->target.ip_them,
                                target->target.port_them, target->target.ip_me,
                                src_port_start + target->index, entropy);

    *len = tcp_create_packet(
        target->target.ip_them, target->target.port_them, target->target.ip_me,
        src_port_start + target->index, seqno, 0, TCP_FLAG_SYN,
        zbanner_conf.syn_ttl, 0, NULL, 0, px, PKT_BUF_SIZE);

    /*multi-probe Multi_Direct*/
    if (ZBannerScan.probe->multi_mode == Multi_Direct &&
        target->index + 1 < ZBannerScan.probe->multi_num)
        return true;

    return false;
}

static void zbanner_validate(uint64_t entropy, Recved *recved, PreHandle *pre) {
    if (recved->parsed.found == FOUND_TCP && recved->is_myip &&
        recved->is_myport)
        pre->go_record = 1;
    else
        return;

    unsigned seqno_me =
        TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned cookie =
        get_cookie(recved->parsed.src_ip, recved->parsed.port_src,
                   recved->parsed.dst_ip, recved->parsed.port_dst, entropy);
    uint8_t flags_them =
        TCP_FLAGS(recved->packet, recved->parsed.transport_offset);

    /* A response is only meaningful for a probe slot we actually used. The
     * source-port range is wider than multi_num, so reject out-of-range
     * slots before handing an index to a probe. */
    unsigned index = recved->parsed.port_dst - src_port_start;
    if (index >= ZBannerScan.probe->multi_num) {
        pre->go_record = 0;
        return;
    }

    /*rst for syn (a little different)*/
    if (TCP_FLAG_HAS(flags_them, TCP_FLAG_RST)) {
        if (seqno_me == cookie + 1 || seqno_me == cookie) {
            pre->go_dedup   = 1;
            pre->dedup_type = ZBANNER_DEDUP_TYPE_PORT;
            pre->no_dedup   = zbanner_conf.no_dedup_rst;
        }
    }
    /*syn-ack*/
    else if (TCP_FLAG_HAS(flags_them, TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        if (cookie == seqno_me - 1) {
            pre->go_dedup   = 1;
            pre->dedup_type = ZBANNER_DEDUP_TYPE_PORT;
            pre->no_dedup   = zbanner_conf.no_dedup_synack;
        }
    }
    /*
    * First packet with reponsed banner data.

    * We could recv Response DATA with some combinations of TCP flags
    * 1.[ACK]: maybe more data
    * 2.[PSH, ACK]: no more data
    * 3.[FIN, PSH, ACK]: no more data and disconnecting
    */
    else if (TCP_FLAG_HAS(flags_them, TCP_FLAG_ACK) &&
             !TCP_FLAG_HAS(flags_them, TCP_FLAG_RST) &&
             recved->parsed.app_length) {
        ProbeTarget ptarget = {
            .target.ip_proto  = recved->parsed.ip_protocol,
            .target.ip_them   = recved->parsed.src_ip,
            .target.ip_me     = recved->parsed.dst_ip,
            .target.port_them = recved->parsed.port_src,
            .target.port_me   = recved->parsed.port_dst,
            .cookie           = 0, /*zbanner can recognize reponse by itself*/
            .index            = index,
        };

        size_t payload_len;
        payload_len = ZBannerScan.probe->get_payload_length_cb(&ptarget);

        if (seqno_me == cookie + payload_len + 1) {
            pre->go_dedup   = 1;
            pre->dedup_type = ZBANNER_DEDUP_TYPE_BANNER;
            pre->no_dedup   = zbanner_conf.no_dedup_banner;
        }
    }
    /*
     * ACK for our probe without payload.
     */
    else if (TCP_FLAG_HAS(flags_them, TCP_FLAG_ACK) &&
             !TCP_FLAG_HAS(flags_them, TCP_FLAG_RST) &&
             !recved->parsed.app_length && zbanner_conf.record_ack) {
        ProbeTarget ptarget = {
            .target.ip_proto  = recved->parsed.ip_protocol,
            .target.ip_them   = recved->parsed.src_ip,
            .target.ip_me     = recved->parsed.dst_ip,
            .target.port_them = recved->parsed.port_src,
            .target.port_me   = recved->parsed.port_dst,
            .cookie           = 0, /*zbanner can recognize reponse by itself*/
            .index            = index,
        };

        size_t payload_len;
        payload_len = ZBannerScan.probe->get_payload_length_cb(&ptarget);

        if (seqno_me == cookie + payload_len + 1) {
            pre->go_dedup   = 1;
            pre->dedup_type = ZBANNER_DEDUP_TYPE_ACK;
            pre->no_dedup   = zbanner_conf.no_dedup_ack;
        }
    }
}

static void zbanner_handle(unsigned th_idx, uint64_t entropy,
                           ValidPacket *valid_pkt, OutItem *item,
                           NetStack *stack) {
    Recved *recved = &valid_pkt->recved;

    unsigned mss_them;
    bool     mss_found;
    uint16_t win_them;

    unsigned seqno_me =
        TCP_ACKNO(recved->packet, recved->parsed.transport_offset);
    unsigned seqno_them =
        TCP_SEQNO(recved->packet, recved->parsed.transport_offset);
    uint8_t flags_them =
        TCP_FLAGS(recved->packet, recved->parsed.transport_offset);

    /* Defense in depth: validate() normally drops out-of-range slots. */
    unsigned index = recved->parsed.port_dst - src_port_start;
    if (index >= ZBannerScan.probe->multi_num)
        return;

    /*SYNACK*/
    if (TCP_FLAG_HAS(flags_them, TCP_FLAG_SYN | TCP_FLAG_ACK)) {

        if (!zbanner_conf.repeat_synack && valid_pkt->repeats) {
            item->no_output = 1;
            return;
        } else if (zbanner_conf.repeat_synack) {
            dach_set_int(&item->scan_report, "repeats", valid_pkt->repeats);
        }

        /*zerowin could be a kind of port open*/
        if (zbanner_conf.is_port_success) {
            item->level = OUT_SUCCESS;
        }

        win_them = TCP_WIN(recved->packet, recved->parsed.transport_offset);

        if (zbanner_conf.record_ttl)
            dach_set_int(&item->scan_report, "ttl", recved->parsed.ip_ttl);
        if (zbanner_conf.record_ipid && recved->parsed.src_ip.version == 4)
            dach_set_int(&item->scan_report, "ipid", recved->parsed.ip_v4_id);
        if (zbanner_conf.record_win)
            dach_set_int(&item->scan_report, "win", win_them);
        if (zbanner_conf.record_mss) {
            /*comput of mss is not easy*/
            mss_them = tcp_get_mss(recved->packet, recved->length, &mss_found);
            if (!mss_found)
                mss_them = 0;
            dach_set_int(&item->scan_report, "mss", mss_them);
        }
        if (zbanner_conf.record_seqno) {
            dach_set_int(&item->scan_report, "seqno", seqno_them);
        }
        if (zbanner_conf.record_ackno) {
            dach_set_int(&item->scan_report, "ackno", seqno_me);
        }

        if (win_them == 0) {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "fake-open");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "zerowin");
        } else {
            safe_strcpy(item->classification, OUT_CLS_SIZE, "open");
            safe_strcpy(item->reason, OUT_RSN_SIZE, "syn-ack");

            /*stack(send) ack with probe*/
            ProbeTarget ptarget = {
                .target.ip_proto  = recved->parsed.ip_protocol,
                .target.ip_them   = recved->parsed.src_ip,
                .target.ip_me     = recved->parsed.dst_ip,
                .target.port_them = recved->parsed.port_src,
                .target.port_me   = recved->parsed.port_dst,
                /*zbanner can recognize reponse by itself*/
                .cookie           = 0,
                .index            = recved->parsed.port_dst - src_port_start,
            };

            unsigned char payload[PM_PAYLOAD_SIZE];
            size_t        payload_len = 0;

            payload_len = ZBannerScan.probe->make_payload_cb(&ptarget, payload);

            /**
             * Use a complete standard TCP 3-way handshake
             */
            if (payload_len > 0 && zbanner_conf.with_ack) {
                PktBuf *pkt_buffer_ack = stack_get_pktbuf(stack);

                pkt_buffer_ack->length = tcp_create_packet(
                    recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, recved->parsed.port_dst, seqno_me,
                    seqno_them + 1, TCP_FLAG_ACK, zbanner_conf.ack_ttl, 0, NULL,
                    0, pkt_buffer_ack->px, PKT_BUF_SIZE);

                stack_transmit_pktbuf(stack, pkt_buffer_ack);
            }

            PktBuf *pkt_buffer = stack_get_pktbuf(stack);

            pkt_buffer->length = tcp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, recved->parsed.port_dst, seqno_me,
                seqno_them + 1, TCP_FLAG_ACK, zbanner_conf.probe_ttl, 0,
                payload, payload_len, pkt_buffer->px, PKT_BUF_SIZE);

            if (pkt_buffer->length == 0) {
                LOG(LEVEL_WARN,
                    "zbanner: probe payload does not fit the packet buffer; "
                    "the ACK with payload is not sent\n");
                stack_release_pktbuf(stack, pkt_buffer);
            } else {
                stack_transmit_pktbuf(stack, pkt_buffer);
            }

            /*multi-probe Multi_IfOpen*/
            if (ZBannerScan.probe->multi_mode == Multi_IfOpen &&
                recved->parsed.port_dst == src_port_start) {
                for (unsigned idx = 1; idx < ZBannerScan.probe->multi_num;
                     idx++) {
                    unsigned cookie = get_cookie(
                        recved->parsed.src_ip, recved->parsed.port_src,
                        recved->parsed.dst_ip, src_port_start + idx, entropy);

                    PktBuf *pkt_buffer = stack_get_pktbuf(stack);

                    pkt_buffer->length = tcp_create_packet(
                        recved->parsed.src_ip, recved->parsed.port_src,
                        recved->parsed.dst_ip, src_port_start + idx, cookie, 0,
                        TCP_FLAG_SYN, zbanner_conf.syn_ttl, 0, NULL, 0,
                        pkt_buffer->px, PKT_BUF_SIZE);

                    stack_transmit_pktbuf(stack, pkt_buffer);
                }
            }
        }
    }
    /*RST*/
    else if (TCP_FLAG_HAS(flags_them, TCP_FLAG_RST)) {

        if (!zbanner_conf.repeat_rst && valid_pkt->repeats) {
            item->no_output = 1;
            return;
        } else if (zbanner_conf.repeat_rst) {
            dach_set_int(&item->scan_report, "repeats", valid_pkt->repeats);
        }

        win_them = TCP_WIN(recved->packet, recved->parsed.transport_offset);

        if (zbanner_conf.record_ttl)
            dach_set_int(&item->scan_report, "ttl", recved->parsed.ip_ttl);
        if (zbanner_conf.record_ipid && recved->parsed.src_ip.version == 4)
            dach_set_int(&item->scan_report, "ipid", recved->parsed.ip_v4_id);
        if (zbanner_conf.record_win)
            dach_set_int(&item->scan_report, "win", win_them);
        if (zbanner_conf.record_seqno) {
            dach_set_int(&item->scan_report, "seqno", seqno_them);
        }
        if (zbanner_conf.record_ackno) {
            dach_set_int(&item->scan_report, "ackno", seqno_me);
        }

        safe_strcpy(item->reason, OUT_RSN_SIZE, "rst");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "closed");

        if (zbanner_conf.is_port_failure) {
            item->level = OUT_FAILURE;
        }
    }
    /*Banner*/
    else if (recved->parsed.app_length) {

        if (!zbanner_conf.repeat_banner && !zbanner_conf.all_banner &&
            valid_pkt->repeats) {
            item->no_output = 1;
            return;
        } else if (zbanner_conf.repeat_banner) {
            dach_set_int(&item->scan_report, "repeats", valid_pkt->repeats);
        } else if (zbanner_conf.all_banner) {
            dach_set_int(&item->scan_report, "banner idx", valid_pkt->repeats);
        }

        if (!zbanner_conf.no_rst &&
            (!zbanner_conf.all_banner ||
             (zbanner_conf.all_banner && zbanner_conf.all_banner_limit &&
              valid_pkt->repeats >= zbanner_conf.all_banner_limit - 1))) {
            PktBuf *pkt_buffer = stack_get_pktbuf(stack);

            pkt_buffer->length = tcp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, recved->parsed.port_dst, seqno_me,
                seqno_them + 1, TCP_FLAG_RST, zbanner_conf.rst_ttl, 0, NULL, 0,
                pkt_buffer->px, PKT_BUF_SIZE);

            stack_transmit_pktbuf(stack, pkt_buffer);
        }

        if (zbanner_conf.all_banner && zbanner_conf.all_banner_limit &&
            valid_pkt->repeats >= zbanner_conf.all_banner_limit) {
            item->no_output = 1;
            return;
        }

        if (zbanner_conf.all_banner && zbanner_conf.all_banner_floor &&
            valid_pkt->repeats < zbanner_conf.all_banner_floor - 1) {
            item->no_output = 1;
            return;
        }

        /*acknowledge data if set all-banner*/
        if (zbanner_conf.all_banner) {
            PktBuf *pkt_buffer = stack_get_pktbuf(stack);

            pkt_buffer->length = tcp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, recved->parsed.port_dst, seqno_me,
                seqno_them + recved->parsed.app_length, TCP_FLAG_ACK,
                zbanner_conf.ack_banner_ttl, 0, NULL, 0, pkt_buffer->px,
                PKT_BUF_SIZE);

            stack_transmit_pktbuf(stack, pkt_buffer);
        }

        ProbeTarget ptarget = {
            .target.ip_proto  = recved->parsed.ip_protocol,
            .target.ip_them   = recved->parsed.src_ip,
            .target.ip_me     = recved->parsed.dst_ip,
            .target.port_them = recved->parsed.port_src,
            .target.port_me   = recved->parsed.port_dst,
            .cookie           = 0, /*zbanner can recognize reponse by itself*/
            .index            = recved->parsed.port_dst - src_port_start,
        };

        unsigned is_multi = ZBannerScan.probe->handle_response_cb(
            th_idx, &ptarget, &recved->packet[recved->parsed.app_offset],
            recved->parsed.app_length, item);

        if (zbanner_conf.record_ttl)
            dach_set_int(&item->scan_report, "ttl", recved->parsed.ip_ttl);
        if (zbanner_conf.record_ipid && recved->parsed.src_ip.version == 4)
            dach_set_int(&item->scan_report, "ipid", recved->parsed.ip_v4_id);
        if (zbanner_conf.record_seqno) {
            dach_set_int(&item->scan_report, "seqno", seqno_them);
        }
        if (zbanner_conf.record_ackno) {
            dach_set_int(&item->scan_report, "ackno", seqno_me);
        }
        if (zbanner_conf.record_data_len) {
            dach_set_int(&item->scan_report, "data len",
                         recved->parsed.app_length);
        }
        if (zbanner_conf.record_data)
            dach_append_bin(&item->scan_report, "data",
                            &recved->packet[recved->parsed.app_offset],
                            recved->parsed.app_length);
        if (zbanner_conf.record_utf8)
            dach_append_utf8(&item->scan_report, "utf8",
                             &recved->packet[recved->parsed.app_offset],
                             recved->parsed.app_length);
        if (zbanner_conf.record_banner)
            dach_append_banner(&item->scan_report, "banner",
                               &recved->packet[recved->parsed.app_offset],
                               recved->parsed.app_length);

        /*multi-probe Multi_AfterHandle*/
        if (ZBannerScan.probe->multi_mode == Multi_AfterHandle && is_multi &&
            recved->parsed.port_dst == src_port_start) {
            for (unsigned idx = 1; idx < ZBannerScan.probe->multi_num; idx++) {
                unsigned cookie = get_cookie(
                    recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, src_port_start + idx, entropy);

                PktBuf *pkt_buffer = stack_get_pktbuf(stack);

                pkt_buffer->length = tcp_create_packet(
                    recved->parsed.src_ip, recved->parsed.port_src,
                    recved->parsed.dst_ip, src_port_start + idx, cookie, 0,
                    TCP_FLAG_SYN, zbanner_conf.syn_ttl, 0, NULL, 0,
                    pkt_buffer->px, PKT_BUF_SIZE);

                stack_transmit_pktbuf(stack, pkt_buffer);
            }
        }
        /*multi-probe Multi_DynamicNext*/
        else if (ZBannerScan.probe->multi_mode == Multi_DynamicNext &&
                 is_multi) {
            unsigned cookie = get_cookie(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, src_port_start + is_multi - 1, entropy);

            PktBuf *pkt_buffer = stack_get_pktbuf(stack);

            pkt_buffer->length = tcp_create_packet(
                recved->parsed.src_ip, recved->parsed.port_src,
                recved->parsed.dst_ip, src_port_start + is_multi - 1, cookie, 0,
                TCP_FLAG_SYN, zbanner_conf.syn_ttl, 0, NULL, 0, pkt_buffer->px,
                PKT_BUF_SIZE);

            stack_transmit_pktbuf(stack, pkt_buffer);
        }

        /**
         * Complement reason and classification if Probe module didn't set.
         */
        if (item->classification[0] == 0) {
            safe_strcpy(item->reason, OUT_RSN_SIZE, "ack with data");
            safe_strcpy(item->classification, OUT_CLS_SIZE, "responsed");
        }
    }
    /*ACK for our probe without payload*/
    else {

        if (!zbanner_conf.repeat_ack && valid_pkt->repeats) {
            item->no_output = 1;
            return;
        } else if (zbanner_conf.repeat_ack) {
            dach_set_int(&item->scan_report, "repeats", valid_pkt->repeats);
        }

        win_them = TCP_WIN(recved->packet, recved->parsed.transport_offset);

        if (zbanner_conf.record_ttl)
            dach_set_int(&item->scan_report, "ttl", recved->parsed.ip_ttl);
        if (zbanner_conf.record_ipid && recved->parsed.src_ip.version == 4)
            dach_set_int(&item->scan_report, "ipid", recved->parsed.ip_v4_id);
        if (zbanner_conf.record_win)
            dach_set_int(&item->scan_report, "win", win_them);
        if (zbanner_conf.record_seqno) {
            dach_set_int(&item->scan_report, "seqno", seqno_them);
        }
        if (zbanner_conf.record_ackno) {
            dach_set_int(&item->scan_report, "ackno", seqno_me);
        }

        safe_strcpy(item->reason, OUT_RSN_SIZE, "ack");
        safe_strcpy(item->classification, OUT_CLS_SIZE, "acknowledged");

        if (zbanner_conf.is_ack_success) {
            item->level = OUT_SUCCESS;
        }
    }
}

Scanner ZBannerScan = {
    .name                = "zbanner",
    .required_probe_type = ProbeType_TCP,
    .params              = zbanner_parameters,
    /*is rst or with ack in ipv4 & ipv6*/
    .bpf_filter =
        "(ip && tcp && (tcp[tcpflags]&tcp-ack!=0 || tcp[tcpflags]==tcp-rst)) "
        "|| (ip6 && tcp && (ip6[40+13]&tcp-ack!=0 || ip6[40+13]==tcp-rst))",
    .short_desc = "Stateless TCP scan with specified ProbeModule.",
    .desc =
        "ZBannerScan tries to contruct TCP conn with target port and send data "
        "from specified ProbeModule. Data in first reponse packet will be "
        "handled by specified ProbeModule.\n"
        "What important is the whole process was done in completely stateless. "
        "So ZBannerScan is very fast for large-scale probing like banner "
        "grabbing, service identification and etc.\n"
        "By the way, ZBanner support `timeout` just for banner response and "
        "port openness(syn-ack).\n"
        "NOTE1: Must specify a TcpType ProbeModule for ZBannerScan like:\n"
        "    `--probe-module xxx`\n"
        "NOTE2: ZBannerScan will construct complete TCP conns. So must avoid "
        "Linux system sending RST automatically by adding iptable rules "
        "displayed in `firewall` directory.\n"
        "NOTE3: Slow send rate may cause target host's retransmition.",

    .init_cb     = &zbanner_init,
    .transmit_cb = &zbanner_transmit,
    .validate_cb = &zbanner_validate,
    .handle_cb   = &zbanner_handle,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};