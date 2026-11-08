#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe Pop3Probe;
extern Probe Pop3StateProbe;

static bool pop3_starts(const unsigned char *px, unsigned len, const char *s) {
    unsigned n = (unsigned)strlen(s);
    return len >= n && memcmp(px, s, n) == 0;
}

static void pop3_banner(const unsigned char *px, unsigned len, OutItem *item) {
    dach_append_banner(&item->probe_report, "pop3_banner", px, len);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "pop3");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "banner");
    item->level = OUT_SUCCESS;
}

static unsigned pop3_tcp_handle(unsigned th_idx, ProbeTarget *target,
                                const unsigned char *px, unsigned sizeof_px,
                                OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (!pop3_starts(px, sizeof_px, "+OK") &&
        !pop3_starts(px, sizeof_px, "-ERR")) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "pop3");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not pop3 banner");
        return 0;
    }
    pop3_banner(px, sizeof_px, item);
    return 0;
}

static bool pop3_conn_init(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    state->data = CALLOC(1, 1024);
    return true;
}

static void pop3_conn_close(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    FREE(state->data);
    state->data = NULL;
}

static void pop3_hello(DataPass *pass, ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
    datapass_set_data(pass, NULL, 0, false);
}

static void pop3_append_caps(const unsigned char *px, unsigned len, char *caps,
                             size_t cap_size) {
    size_t used = strlen(caps);
    unsigned i = 0;
    while (i < len && used + 1 < cap_size) {
        unsigned start = i;
        while (i < len && px[i] != '\r' && px[i] != '\n')
            i++;
        if (i > start && !pop3_starts(px + start, i - start, "+OK") &&
            !pop3_starts(px + start, i - start, ".")) {
            int n = snprintf(caps + used, cap_size - used, "%s%.*s",
                             used ? "; " : "", (int)(i - start),
                             px + start);
            if (n > 0) used += (size_t)n;
        }
        while (i < len && (px[i] == '\r' || px[i] == '\n'))
            i++;
    }
}

static unsigned pop3_parse(DataPass *pass, ProbeState *state, OutConf *out,
                           ProbeTarget *target, const unsigned char *px,
                           unsigned sizeof_px) {
    char *banner = state->data;
    if (state->state == 0) {
        if (!pop3_starts(px, sizeof_px, "+OK"))
            return 0;
        if (banner) {
            unsigned n = sizeof_px < 1023 ? sizeof_px : 1023;
            memcpy(banner, px, n);
            banner[n] = 0;
        }
        state->state = 1;
        datapass_set_data(pass, (unsigned char *)"CAPA\r\n", 6, false);
        return 0;
    }

    if (state->state == 1) {
        state->state = 2;
        OutItem item = {
            .target.ip_proto  = target->target.ip_proto,
            .target.ip_them   = target->target.ip_them,
            .target.ip_me     = target->target.ip_me,
            .target.port_them = target->target.port_them,
            .target.port_me   = target->target.port_me,
        };
        char caps[768] = {0};
        pop3_append_caps(px, sizeof_px, caps, sizeof(caps));
        if (banner && banner[0])
            dach_append_banner(&item.probe_report, "pop3_banner",
                               (unsigned char *)banner, strlen(banner));
        dach_append_str(&item.probe_report, "pop3_capabilities", caps,
                        strlen(caps));
        dach_set_bool(&item.probe_report, "pop3_stls",
                      strstr(caps, "STLS") != NULL);
        safe_strcpy(item.classification, OUT_CLS_SIZE, "pop3");
        safe_strcpy(item.reason, OUT_RSN_SIZE, "capa");
        item.level = OUT_SUCCESS;
        output_result(out, &item);
        pass->is_close = 1;
    }
    return 0;
}

Probe Pop3Probe = {
    .name       = "pop3",
    .type       = ProbeType_TCP,
    .short_desc = "Read the POP3 +OK banner (stateless).",
    .desc = "Wait for the POP3 +OK greeting and report the banner. No CAPA "
            "command or authentication is sent. Single slot; use pop3-state "
            "for capabilities/STLS.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &probe_make_no_payload,
    .get_payload_length_cb = &probe_no_payload_length,
    .handle_response_cb    = &pop3_tcp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe Pop3StateProbe = {
    .name       = "pop3-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "POP3 greeting and CAPA probe.",
    .desc = "Read the POP3 +OK greeting, send `CAPA`, parse capabilities and "
            "report STLS availability. No USER/PASS or authentication. State "
            "probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &pop3_conn_init,
    .make_hello_cb     = &pop3_hello,
    .parse_response_cb = &pop3_parse,
    .conn_close_cb     = &pop3_conn_close,
    .close_cb          = &probe_close_nothing,
};
