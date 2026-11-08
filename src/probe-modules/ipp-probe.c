#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe IppProbe;
extern Probe IppStateProbe;

static size_t ipp_put_attr(unsigned char *p, unsigned tag, const char *name,
                           const char *value) {
    size_t n = 0;
    p[n++] = (unsigned char)tag;
    size_t nlen = strlen(name);
    p[n++] = (unsigned char)(nlen >> 8);
    p[n++] = (unsigned char)nlen;
    memcpy(p + n, name, nlen);
    n += nlen;
    size_t vlen = strlen(value);
    p[n++] = (unsigned char)(vlen >> 8);
    p[n++] = (unsigned char)vlen;
    memcpy(p + n, value, vlen);
    n += vlen;
    return n;
}

static size_t ipp_make(ProbeTarget *target, unsigned char *buf) {
    UNUSEDPARM(target);
    char body[512];
    size_t bn = 0;
    body[bn++] = 0x01;
    body[bn++] = 0x01;
    body[bn++] = 0x00;
    body[bn++] = 0x0b; /* Get-Printer-Attributes */
    body[bn++] = 0x00;
    body[bn++] = 0x00;
    body[bn++] = 0x00;
    body[bn++] = 0x01;
    bn += ipp_put_attr((unsigned char *)body + bn, 0x47,
                       "attributes-charset", "utf-8");
    bn += ipp_put_attr((unsigned char *)body + bn, 0x48,
                       "attributes-natural-language", "en");
    bn += ipp_put_attr((unsigned char *)body + bn, 0x45, "printer-uri",
                       "ipp://127.0.0.1/ipp/print");

    char head[256];
    int hn = snprintf(head, sizeof(head),
                      "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                      "Content-Type: application/ipp\r\n"
                      "Content-Length: %u\r\nConnection: close\r\n\r\n",
                      (unsigned)bn);
    memcpy(buf, head, (size_t)hn);
    memcpy(buf + hn, body, bn);
    return (size_t)hn + bn;
}

static size_t ipp_len(ProbeTarget *target) {
    unsigned char tmp[PM_PAYLOAD_SIZE];
    return ipp_make(target, tmp);
}

static unsigned ipp_handle(unsigned th_idx, ProbeTarget *target,
                           const unsigned char *px, unsigned sizeof_px,
                           OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (sizeof_px < 8 || memcmp(px, "HTTP/", 5) != 0) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ipp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not http response");
        return 0;
    }
    unsigned http_status = 0;
    for (unsigned i = 0; i + 2 < sizeof_px; i++) {
        if (px[i] == ' ' && i + 3 < sizeof_px) {
            http_status = (unsigned)(px[i + 1] - '0') * 100 +
                          (unsigned)(px[i + 2] - '0') * 10 +
                          (unsigned)(px[i + 3] - '0');
            break;
        }
    }
    dach_set_int(&item->probe_report, "ipp_http_status", http_status);
    unsigned sep = 0;
    for (unsigned i = 0; i + 3 < sizeof_px; i++) {
        if (px[i] == '\r' && px[i + 1] == '\n' && px[i + 2] == '\r' &&
            px[i + 3] == '\n') {
            sep = i + 4;
            break;
        }
    }
    if (sep && sep + 8 <= sizeof_px) {
        const unsigned char *ip = px + sep;
        dach_set_int(&item->probe_report, "ipp_status_code",
                     ((unsigned)ip[2] << 8) | ip[3]);
        dach_set_int(&item->probe_report, "ipp_request_id",
                     ((unsigned)ip[4] << 24) | ((unsigned)ip[5] << 16) |
                         ((unsigned)ip[6] << 8) | ip[7]);
    }
    dach_append_banner(&item->probe_report, "ipp_response", px, sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "ipp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "ipp response");
    item->level = OUT_SUCCESS;
    return 0;
}

static void ipp_state_hello(DataPass *pass, ProbeState *state,
                            ProbeTarget *target) {
    UNUSEDPARM(state);
    unsigned char req[PM_PAYLOAD_SIZE];
    size_t n = ipp_make(target, req);
    datapass_set_data(pass, req, n, true);
}

static unsigned ipp_state_parse(DataPass *pass, ProbeState *state, OutConf *out,
                                ProbeTarget *target, const unsigned char *px,
                                unsigned sizeof_px) {
    UNUSEDPARM(pass);
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
    ipp_handle(0, target, px, sizeof_px, &item);
    output_result(out, &item);
    return 0;
}

Probe IppProbe = {
    .name       = "ipp",
    .type       = ProbeType_TCP,
    .short_desc = "IPP Get-Printer-Attributes over HTTP.",
    .desc = "Send an unauthenticated IPP Get-Printer-Attributes request over "
            "HTTP and parse the IPP status code. No printing, job creation or "
            "authentication. Single slot; ipp-state supports TLS composition.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &ipp_make,
    .get_payload_length_cb = &ipp_len,
    .handle_response_cb    = &ipp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe IppStateProbe = {
    .name       = "ipp-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "IPP over HTTP, composable with tls-state.",
    .desc = "Stateful IPP Get-Printer-Attributes probe. Run over tcp-state or "
            "tls-state for HTTPS; no authentication or printing. State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &ipp_state_hello,
    .parse_response_cb = &ipp_state_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
