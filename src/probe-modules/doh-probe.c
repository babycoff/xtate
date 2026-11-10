#include "probe-modules.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "../proto/proto-dns.h"
#include "../xconf.h"
#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe DohProbe;

struct DohConf {
    char           *req_name;
    dns_record_type req_type;
    char           *doh_path;
    char           *doh_host;
    unsigned        recursive_desired : 1;
    unsigned        dnssec            : 1;
    unsigned        edns_size;
};

static struct DohConf doh_conf = {
    .doh_path = "/dns-query",
};

static ConfRes SET_req_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    if (!value || !value[0]) return Conf_ERR;
    FREE(doh_conf.req_name); doh_conf.req_name = STRDUP(value);
    return Conf_OK;
}
static ConfRes SET_req_type(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    if (!value || !value[0]) return Conf_ERR;
    doh_conf.req_type = dns_str_to_record_type(value);
    return doh_conf.req_type == DNS_REC_INVALID ? Conf_ERR : Conf_OK;
}
static ConfRes SET_path(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    if (!value || value[0] != '/') return Conf_ERR;
    FREE(doh_conf.doh_path); doh_conf.doh_path = STRDUP(value);
    return Conf_OK;
}
static ConfRes SET_host(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    if (!value || !value[0]) return Conf_ERR;
    FREE(doh_conf.doh_host); doh_conf.doh_host = STRDUP(value);
    return Conf_OK;
}
static ConfRes SET_rd(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    doh_conf.recursive_desired = conf_parse_bool(value); return Conf_OK;
}
static ConfRes SET_dnssec(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    doh_conf.dnssec = conf_parse_bool(value); return Conf_OK;
}
static ConfRes SET_edns_size(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    unsigned v = (unsigned)strtoul(value, NULL, 0);
    if (v < 512 || v > 65535) return Conf_ERR;
    doh_conf.edns_size = v; return Conf_OK;
}

static ConfParam doh_parameters[] = {
    {"req-name", SET_req_name, Type_ARG, {"name", 0}, "DNS name to query."},
    {"req-type", SET_req_type, Type_ARG, {"type", 0}, "DNS type, default A."},
    {"doh-path", SET_path, Type_ARG, {"path", 0},
     "HTTP path, default /dns-query."},
    {"doh-host", SET_host, Type_ARG, {"host", 0},
     "HTTP Host header; required by most DoH servers."},
    {"recursive-desired", SET_rd, Type_FLAG, {"recursive", "rd", 0}, "Set RD."},
    {"dnssec", SET_dnssec, Type_FLAG, {"do", 0}, "Send EDNS0 DO=1."},
    {"edns-size", SET_edns_size, Type_ARG, {"udp-size", 0},
     "EDNS0 UDP size, default 1232."},
    {0}};

static bool doh_init(const XConf *xconf) {
    if (!doh_conf.req_name) {
        LOG(LEVEL_ERROR, "doh requires --req-name.\\n");
        return false;
    }
    if (doh_conf.req_type == 0) doh_conf.req_type = DNS_REC_A;
    return true;
}

static size_t doh_dns_query(ProbeTarget *target, unsigned char *out) {
    int n = dns_question_create(out, doh_conf.req_name, doh_conf.req_type,
                                target->cookie & 0xffff);
    if (n <= 0) return 0;
    if (doh_conf.recursive_desired) dns_buf_set_rd(out, true);
    if (doh_conf.dnssec) {
        unsigned char *p = out + n;
        p[0]=0; p[1]=0x00; p[2]=0x29;
        unsigned sz = doh_conf.edns_size ? doh_conf.edns_size : 1232;
        p[3]=(unsigned char)(sz>>8); p[4]=(unsigned char)sz;
        p[5]=0; p[6]=0; p[7]=0x80; p[8]=0; p[9]=0;
        p[10]=0; p[11]=0; n += 11;
        out[10]=0; out[11]=1;
    }
    return n > 0 ? (size_t)n : 0;
}

struct DohState {
    unsigned char buf[8192];
    size_t        len;
};

static bool doh_conn_init(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    state->data = CALLOC(1, sizeof(struct DohState));
    return state->data != NULL;
}
static void doh_conn_close(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target); FREE(state->data); state->data = NULL;
}

static void doh_make_hello(DataPass *pass, ProbeState *state,
                           ProbeTarget *target) {
    UNUSEDPARM(state);
    unsigned char dns[2048];
    size_t dns_len = doh_dns_query(target, dns);
    if (!dns_len) { pass->is_close = 1; return; }
    ipaddress_formatted_t host_fmt = ipaddress_fmt(target->target.ip_them);
    const char *host = doh_conf.doh_host ? doh_conf.doh_host : host_fmt.string;
    char head[1024];
    int n = snprintf(head, sizeof(head),
                     "POST %s HTTP/1.1\r\nHost: %s\r\n"
                     "Content-Type: application/dns-message\r\n"
                     "Accept: application/dns-message\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                     doh_conf.doh_path, host, dns_len);
    if (n <= 0 || (size_t)n + dns_len > 4096) { pass->is_close = 1; return; }
    unsigned char *req = MALLOC((size_t)n + dns_len);
    if (!req) { pass->is_close = 1; return; }
    memcpy(req, head, (size_t)n);
    memcpy(req + n, dns, dns_len);
    datapass_set_data(pass, req, (size_t)n + dns_len, true);
}

static const char *find_header(const char *headers, const char *name) {
    size_t nlen = strlen(name);
    const char *p = headers;
    while (p && *p) {
        const char *e = strstr(p, "\r\n");
        if (!e) break;
        if ((size_t)(e - p) > nlen && strncasecmp(p, name, nlen) == 0 &&
            p[nlen] == ':') {
            p += nlen + 1;
            while (*p == ' ' || *p == '\\t') p++;
            return p;
        }
        p = e + 2;
    }
    return NULL;
}

static void doh_handle(OutItem *item, const unsigned char *dns, size_t len) {
    dns_pkt_t pkt;
    if (!dns_parse_reply((uint8_t *)dns, len, &pkt)) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "doh");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "dns parse failed");
        return;
    }
    dach_set_int(&item->probe_report, "doh_dns_len", (unsigned)len);
    dach_set_int(&item->probe_report, "doh_rcode", pkt.head.header.rcode);
    dach_set_bool(&item->probe_report, "doh_ad", pkt.head.header.ad);
    if (pkt.head.header.ans_count > 0) {
        char answer[256];
        dns_raw_record_data2str(&pkt.body.ans[0], (uint8_t *)dns,
                                (uint8_t *)(dns + len), false, answer,
                                sizeof(answer));
        dach_append_str(&item->probe_report, "doh_answer", answer,
                        strlen(answer));
    }
    unsigned sig=0, key=0, ds=0, nsec=0;
    for (unsigned i=0; i<pkt.head.header.ans_count+pkt.head.header.auth_count+
                              pkt.head.header.add_count; i++) {
        dns_record_t *r;
        if (i < pkt.head.header.ans_count) r=&pkt.body.ans[i];
        else if (i < pkt.head.header.ans_count+pkt.head.header.auth_count)
            r=&pkt.body.auth[i-pkt.head.header.ans_count];
        else r=&pkt.body.add[i-pkt.head.header.ans_count-pkt.head.header.auth_count];
        if (r->type==46) sig++; else if (r->type==48) key++;
        else if (r->type==43) ds++; else if (r->type==47||r->type==50) nsec++;
    }
    dach_set_int(&item->probe_report, "doh_rrsig_count", sig);
    dach_set_int(&item->probe_report, "doh_dnskey_count", key);
    dach_set_int(&item->probe_report, "doh_ds_count", ds);
    dach_set_int(&item->probe_report, "doh_nsec_count", nsec);
    dach_set_bool(&item->probe_report, "doh_dnssec_present", sig||key||ds||nsec);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "doh");
    safe_strcpy(item->reason, OUT_RSN_SIZE, dns_rcode2str(pkt.head.header.rcode));
    item->level = OUT_SUCCESS;
}

static unsigned doh_parse(DataPass *pass, ProbeState *state, OutConf *out,
                          ProbeTarget *target, const unsigned char *px,
                          unsigned sizeof_px) {
    struct DohState *st = state->data;
    if (!st) return 0;
    size_t room = sizeof(st->buf) - st->len;
    if (sizeof_px < room) room = sizeof_px;
    memcpy(st->buf + st->len, px, room); st->len += room;
    char *hdr_end = strstr((char *)st->buf, "\r\n\r\n");
    if (!hdr_end) return 0;
    char *body = hdr_end + 4;
    if (st->len < (size_t)(body - (char *)st->buf)) return 0;
    int status = 0;
    const char *sp = strchr((char *)st->buf, ' ');
    if (!sp) { pass->is_close = 1; return 0; }
    status = (int)strtoul(sp + 1, NULL, 10);
    size_t body_len = st->len - (size_t)(body - (char *)st->buf);
    const char *cl = find_header((char *)st->buf, "Content-Length");
    if (cl) {
        size_t want = (size_t)strtoul(cl, NULL, 10);
        if (want < body_len) body_len = want;
        if (body_len < want) return 0;
    }
    OutItem item = {
        .target.ip_proto=target->target.ip_proto, .target.ip_them=target->target.ip_them,
        .target.ip_me=target->target.ip_me, .target.port_them=target->target.port_them,
        .target.port_me=target->target.port_me,
    };
    dach_set_int(&item.probe_report, "doh_status", status);
    const char *ct = find_header((char *)st->buf, "Content-Type");
    if (ct) {
        const char *e = strstr(ct, "\r\n");
        if (e) dach_append_str(&item.probe_report, "doh_content_type", ct,
                               (size_t)(e - ct));
    }
    if (status != 200) {
        item.level = OUT_FAILURE;
        safe_strcpy(item.classification, OUT_CLS_SIZE, "doh");
        safe_strcpy(item.reason, OUT_RSN_SIZE, "http error");
        output_result(out, &item);
    } else {
        doh_handle(&item, (const unsigned char *)body, body_len);
        output_result(out, &item);
    }
    pass->is_close = 1;
    return 0;
}

Probe DohProbe = {
    .name = "doh",
    .type = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "DNS over HTTPS (DoH), HTTP/1.1 inside tls-state.",
    .desc = "Stateful DoH client for `-scan tcp-state -probe tls-state "
            "-alpn http/1.1 -subprobe doh`. Sends an HTTP/1.1 POST with "
            "application/dns-message and parses the DNS response. TLS is "
            "handled by tls-state. State probe.",
    .params = doh_parameters,
    .init_cb = &doh_init,
    .conn_init_cb = &doh_conn_init,
    .make_hello_cb = &doh_make_hello,
    .parse_response_cb = &doh_parse,
    .conn_close_cb = &doh_conn_close,
    .close_cb = &probe_close_nothing,
};
