#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe PptpProbe;
extern Probe PptpStateProbe;

static unsigned pptp_u16(const unsigned char *p) {
    return ((unsigned)p[0] << 8) | p[1];
}

static size_t pptp_make(ProbeTarget *target, unsigned char *buf) {
    UNUSEDPARM(target);
    memset(buf, 0, 156);
    buf[0] = 0;
    buf[1] = 156;
    buf[2] = 0;
    buf[3] = 1; /* Start-Control-Connection-Request */
    buf[4] = 0x1a;
    buf[5] = 0x2b;
    buf[6] = 0x3c;
    buf[7] = 0x4d;
    buf[8] = 0;
    buf[9] = 1;
    buf[12] = 0x01;
    buf[13] = 0x00;
    buf[16] = 0;
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 1;
    buf[20] = 0;
    buf[21] = 0;
    buf[22] = 0;
    buf[23] = 1;
    memcpy(buf + 28, "xtate", 5);
    memcpy(buf + 92, "xtate", 5);
    return 156;
}

static size_t pptp_len(ProbeTarget *target) {
    UNUSEDPARM(target);
    return 156;
}

static unsigned pptp_handle(unsigned th_idx, ProbeTarget *target,
                            const unsigned char *px, unsigned sizeof_px,
                            OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (sizeof_px < 28 || px[0] != 0 || px[1] != sizeof_px || px[3] != 2) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "pptp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not sccrp");
        return 0;
    }
    dach_set_int(&item->probe_report, "pptp_version", pptp_u16(px + 12));
    dach_set_int(&item->probe_report, "pptp_result_code", px[14]);
    dach_set_int(&item->probe_report, "pptp_error_code", px[15]);
    dach_set_int(&item->probe_report, "pptp_framing_capability",
                 ((unsigned)px[16] << 24) | ((unsigned)px[17] << 16) |
                     ((unsigned)px[18] << 8) | px[19]);
    dach_set_int(&item->probe_report, "pptp_bearer_capability",
                 ((unsigned)px[20] << 24) | ((unsigned)px[21] << 16) |
                     ((unsigned)px[22] << 8) | px[23]);
    dach_append_banner(&item->probe_report, "pptp_response", px, sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "pptp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "sccrp");
    item->level = OUT_SUCCESS;
    return 0;
}

static void pptp_state_hello(DataPass *pass, ProbeState *state,
                             ProbeTarget *target) {
    UNUSEDPARM(state);
    unsigned char req[156];
    pptp_make(target, req);
    datapass_set_data(pass, req, sizeof(req), true);
}

static unsigned pptp_state_parse(DataPass *pass, ProbeState *state,
                                 OutConf *out, ProbeTarget *target,
                                 const unsigned char *px, unsigned sizeof_px) {
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
    pptp_handle(0, target, px, sizeof_px, &item);
    output_result(out, &item);
    pass->is_close = 1;
    return 0;
}

Probe PptpProbe = {
    .name       = "pptp",
    .type       = ProbeType_TCP,
    .short_desc = "PPTP Start-Control-Connection-Request.",
    .desc = "Send a PPTP Start-Control-Connection-Request and parse the "
            "Start-Control-Connection-Reply result/version. No GRE, no tunnel "
            "or authentication. Single slot; pptp-state supports TLS "
            "composition.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &pptp_make,
    .get_payload_length_cb = &pptp_len,
    .handle_response_cb    = &pptp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe PptpStateProbe = {
    .name       = "pptp-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "PPTP control connection over tcp-state.",
    .desc = "Stateful PPTP Start-Control-Connection-Request probe. No GRE or "
            "authentication. State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &pptp_state_hello,
    .parse_response_cb = &pptp_state_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
