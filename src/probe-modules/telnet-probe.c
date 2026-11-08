#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe TelnetProbe;

static void telnet_make_hello(DataPass *pass, ProbeState *state,
                              ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
    /* Wait for the server's initial IAC/banner; no client bytes needed. */
    datapass_set_data(pass, NULL, 0, false);
}

static void telnet_option(char *dst, size_t dst_size, unsigned cmd,
                          unsigned opt) {
    const char *cn = cmd == 251 ? "WILL" : cmd == 252 ? "WONT"
                     : cmd == 253 ? "DO" : cmd == 254 ? "DONT"
                                                        : "?";
    snprintf(dst, dst_size, "IAC %s %u", cn, opt);
}

static unsigned telnet_parse(DataPass *pass, ProbeState *state, OutConf *out,
                             ProbeTarget *target, const unsigned char *px,
                             unsigned sizeof_px) {
    UNUSEDPARM(pass);
    if (state->state)
        return 0;
    state->state = 1;

    OutItem item = {
        .level            = OUT_SUCCESS,
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = target->target.port_me,
    };

    if (sizeof_px)
        dach_append_banner(&item.probe_report, "telnet_banner", px,
                           sizeof_px);

    char options[512] = {0};
    size_t used = 0;
    for (unsigned i = 0; i + 2 < sizeof_px && used < sizeof(options); i++) {
        if (px[i] != 0xff || px[i + 1] < 251 || px[i + 1] > 254)
            continue;
        char one[48];
        telnet_option(one, sizeof(one), px[i + 1], px[i + 2]);
        int n = snprintf(options + used, sizeof(options) - used, "%s%s",
                         used ? "; " : "", one);
        if (n > 0)
            used += (size_t)n;
        i += 2;
    }
    if (used)
        dach_append_str(&item.probe_report, "telnet_options", options, used);

    safe_strcpy(item.classification, OUT_CLS_SIZE, "telnet");
    safe_strcpy(item.reason, OUT_RSN_SIZE, sizeof_px ? "banner" : "empty");
    output_result(out, &item);
    return 0;
}

Probe TelnetProbe = {
    .name       = "telnet",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "Read the initial Telnet banner and IAC negotiation.",
    .desc = "Wait for the server's initial Telnet data and report the banner "
            "plus the first IAC WILL/WONT/DO/DONT options. It does not send "
            "terminal negotiation replies. State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &telnet_make_hello,
    .parse_response_cb = &telnet_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
