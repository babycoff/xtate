#include "probe-modules.h"
#include "../output-modules/output-modules.h"

#include <stdio.h>
#include <string.h>

#include "../proto/proto-dns.h"
#include "../xconf.h"
#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-misc/misc.h"

extern Probe DotProbe;

struct DotConf {
    char           *req_name;
    dns_record_type req_type;
    unsigned        recursive_desired : 1;
    unsigned        dnssec            : 1;
    unsigned        edns_size;
};

static struct DotConf dot_conf = {0};

static ConfRes SET_req_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || !value[0])
        return Conf_ERR;
    FREE(dot_conf.req_name);
    dot_conf.req_name = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_req_type(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || !value[0])
        return Conf_ERR;
    dot_conf.req_type = dns_str_to_record_type(value);
    return dot_conf.req_type == DNS_REC_INVALID ? Conf_ERR : Conf_OK;
}

static ConfRes SET_rd(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    dot_conf.recursive_desired = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_dnssec(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    dot_conf.dnssec = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_edns_size(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = (unsigned)strtoul(value, NULL, 0);
    if (v < 512 || v > 65535)
        return Conf_ERR;
    dot_conf.edns_size = v;
    return Conf_OK;
}

static ConfParam dot_parameters[] = {
    {"req-name", SET_req_name, Type_ARG, {"name", 0}, "DNS name to query."},
    {"req-type", SET_req_type, Type_ARG, {"type", 0},
     "DNS record type, for example A, AAAA or DNSKEY."},
    {"recursive-desired", SET_rd, Type_FLAG, {"recursive", "rd", 0},
     "Set RD in the DNS query."},
    {"dnssec", SET_dnssec, Type_FLAG, {"do", 0},
     "Send EDNS0 OPT with DO=1 and report DNSSEC evidence."},
    {"edns-size", SET_edns_size, Type_ARG, {"udp-size", 0},
     "EDNS0 UDP payload size, default 1232."},
    {0}};

static bool dot_init(const XConf *xconf) {
    if (!dot_conf.req_name) {
        LOG(LEVEL_ERROR, "dot requires --req-name.\\n");
        return false;
    }
    if (dot_conf.req_type == 0)
        dot_conf.req_type = DNS_REC_A;
    return true;
}

static size_t dot_build_query(ProbeTarget *target, unsigned char *out) {
    int n = dns_question_create(out + 2, dot_conf.req_name, dot_conf.req_type,
                                target->cookie & 0xffff);
    if (n <= 0)
        return 0;
    if (dot_conf.recursive_desired)
        dns_buf_set_rd(out + 2, true);
    if (dot_conf.dnssec) {
        unsigned char *p = out + 2 + n;
        p[0] = 0;
        p[1] = 0x00; p[2] = 0x29;
        unsigned sz = dot_conf.edns_size ? dot_conf.edns_size : 1232;
        p[3] = (unsigned char)(sz >> 8); p[4] = (unsigned char)sz;
        p[5] = 0; p[6] = 0; p[7] = 0x80; p[8] = 0; p[9] = 0;
        p[10] = 0; p[11] = 0;
        n += 11;
        out[2 + 10] = 0; out[2 + 11] = 1;
    }
    if (n <= 0 || n > 0xFFFF)
        return 0;
    out[0] = (unsigned char)(n >> 8);
    out[1] = (unsigned char)n;
    return (size_t)n + 2;
}

static void dot_make_hello(DataPass *pass, ProbeState *state,
                           ProbeTarget *target) {
    UNUSEDPARM(state);
    unsigned char buf[2048];
    size_t n = dot_build_query(target, buf);
    if (!n) {
        pass->is_close = 1;
        return;
    }
    datapass_set_data(pass, buf, n, true);
}

static unsigned dot_handle(ProbeTarget *target, const unsigned char *px,
                           unsigned sizeof_px, OutItem *item) {
    UNUSEDPARM(target);
    if (sizeof_px < 14 || px[0] || px[1] == 0) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "dot");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "bad dns length");
        return 0;
    }
    unsigned dns_len = ((unsigned)px[0] << 8) | px[1];
    if (dns_len + 2 > sizeof_px || dns_len < 12) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "dot");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "truncated dns");
        return 0;
    }
    dns_pkt_t pkt;
    if (!dns_parse_reply((uint8_t *)(px + 2), dns_len, &pkt)) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "dot");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "dns parse failed");
        return 0;
    }
    dach_set_int(&item->probe_report, "dot_dns_len", dns_len);
    dach_set_int(&item->probe_report, "dot_rcode", pkt.head.header.rcode);
    dach_set_bool(&item->probe_report, "dot_ad", pkt.head.header.ad);
    if (pkt.head.header.ans_count > 0) {
        char answer[256];
        dns_raw_record_data2str(&pkt.body.ans[0], (uint8_t *)(px + 2),
                                (uint8_t *)(px + 2 + dns_len), false, answer,
                                sizeof(answer));
        dach_append_str(&item->probe_report, "dot_answer", answer,
                        strlen(answer));
    }
    unsigned sig = 0, key = 0, ds = 0, nsec = 0;
    for (unsigned i = 0; i < pkt.head.header.ans_count + pkt.head.header.auth_count +
                                pkt.head.header.add_count; i++) {
        dns_record_t *r;
        if (i < pkt.head.header.ans_count)
            r = &pkt.body.ans[i];
        else if (i < pkt.head.header.ans_count + pkt.head.header.auth_count)
            r = &pkt.body.auth[i - pkt.head.header.ans_count];
        else
            r = &pkt.body.add[i - pkt.head.header.ans_count - pkt.head.header.auth_count];
        if (r->type == 46) sig++;
        else if (r->type == 48) key++;
        else if (r->type == 43) ds++;
        else if (r->type == 47 || r->type == 50) nsec++;
    }
    dach_set_int(&item->probe_report, "dot_rrsig_count", sig);
    dach_set_int(&item->probe_report, "dot_dnskey_count", key);
    dach_set_int(&item->probe_report, "dot_ds_count", ds);
    dach_set_int(&item->probe_report, "dot_nsec_count", nsec);
    dach_set_bool(&item->probe_report, "dot_dnssec_present",
                  sig || key || ds || nsec);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "dot");
    safe_strcpy(item->reason, OUT_RSN_SIZE,
                dns_rcode2str(pkt.head.header.rcode));
    item->level = OUT_SUCCESS;
    return 0;
}

static unsigned dot_parse(DataPass *pass, ProbeState *state, OutConf *out,
                          ProbeTarget *target, const unsigned char *px,
                          unsigned sizeof_px) {
    if (state->state)
        return 0;
    state->state = 1;
    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = target->target.port_me,
    };
    dot_handle(target, px, sizeof_px, &item);
    output_result(out, &item);
    pass->is_close = 1;
    return 0;
}

Probe DotProbe = {
    .name       = "dot",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "DNS over TLS (DoT) inside tls-state.",
    .desc = "Stateful DNS-over-TLS client for `-scan tcp-state -probe tls-state "
            "-alpn dot -subprobe dot`. Sends a two-byte-length-prefixed DNS "
            "query and parses the DNS response. TLS is handled by tls-state. "
            "State probe.",
    .params            = dot_parameters,
    .init_cb           = &dot_init,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &dot_make_hello,
    .parse_response_cb = &dot_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
