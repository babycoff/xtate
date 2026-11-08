#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe Socks5Probe;

static const unsigned char socks5_greeting[] = {0x05, 0x01, 0x00};

static void socks5_make_hello(DataPass *pass, ProbeState *state,
                              ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
    datapass_set_data(pass, (unsigned char *)socks5_greeting,
                      sizeof(socks5_greeting), false);
}

static unsigned socks5_parse(DataPass *pass, ProbeState *state, OutConf *out,
                             ProbeTarget *target, const unsigned char *px,
                             unsigned sizeof_px) {
    UNUSEDPARM(pass);
    UNUSEDPARM(target);
    if (state->state)
        return 0;
    state->state = 1;

    OutItem item = {
        .level             = OUT_SUCCESS,
        .target.ip_proto   = target->target.ip_proto,
        .target.ip_them    = target->target.ip_them,
        .target.ip_me      = target->target.ip_me,
        .target.port_them  = target->target.port_them,
        .target.port_me    = target->target.port_me,
    };

    if (sizeof_px >= 2 && px[0] == 0x05) {
        char method[32];
        snprintf(method, sizeof(method), "0x%02x", px[1]);
        dach_set_int(&item.probe_report, "socks5_version", px[0]);
        dach_set_int(&item.probe_report, "socks5_method", px[1]);
        dach_append_str(&item.probe_report, "socks5_auth_method", method,
                        strlen(method));
        safe_strcpy(item.classification, OUT_CLS_SIZE, "socks5");
        safe_strcpy(item.reason, OUT_RSN_SIZE, "method");
    } else {
        item.level = OUT_FAILURE;
        safe_strcpy(item.classification, OUT_CLS_SIZE, "socks5");
        safe_strcpy(item.reason, OUT_RSN_SIZE, "invalid method selection");
    }

    output_result(out, &item);
    return 0;
}

Probe Socks5Probe = {
    .name       = "socks5",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "SOCKS5 greeting and method selection.",
    .desc = "Send a SOCKS5 greeting offering no-authentication, parse the "
            "server method selection, and report the chosen method. It does "
            "not perform a CONNECT or authenticate. State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &socks5_make_hello,
    .parse_response_cb = &socks5_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
