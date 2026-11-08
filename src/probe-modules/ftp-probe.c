#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe FtpProbe;
extern Probe FtpStateProbe;

static bool ftp_after_tls;
static ConfRes SET_ftp_after_tls(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    ftp_after_tls = conf_parse_bool(value);
    return Conf_OK;
}
static ConfParam ftp_state_parameters[] = {
    {"after-tls", SET_ftp_after_tls, Type_FLAG, {"post-tls", 0},
     "Run inside an already-established TLS/STARTTLS stream: skip the greeting and send the capability command immediately."},
    {0}};

static bool ftp_starts(const unsigned char *px, unsigned len, const char *s) {
    unsigned n = (unsigned)strlen(s);
    return len >= n && memcmp(px, s, n) == 0;
}

static void ftp_banner(const unsigned char *px, unsigned len, OutItem *item) {
    dach_append_banner(&item->probe_report, "ftp_banner", px, len);
    dach_set_int(&item->probe_report, "ftp_code",
                 len >= 3 ? (px[0] - '0') * 100 + (px[1] - '0') * 10 +
                                (px[2] - '0')
                          : 0);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "ftp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "banner");
    item->level = OUT_SUCCESS;
}

static unsigned ftp_tcp_handle(unsigned th_idx, ProbeTarget *target,
                               const unsigned char *px, unsigned sizeof_px,
                               OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (!ftp_starts(px, sizeof_px, "220")) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "ftp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not ftp banner");
        return 0;
    }
    ftp_banner(px, sizeof_px, item);
    return 0;
}

static bool ftp_conn_init(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    state->data = CALLOC(1, 1024);
    return true;
}

static void ftp_conn_close(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    FREE(state->data);
    state->data = NULL;
}

static void ftp_hello(DataPass *pass, ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    if (ftp_after_tls) {
        state->state = 1;
        datapass_set_data(pass, (unsigned char *)"FEAT\r\n", 8, false);
    } else {
        datapass_set_data(pass, NULL, 0, false);
    }
}

static void ftp_append_caps(const unsigned char *px, unsigned len, char *caps,
                            size_t cap_size) {
    size_t used = strlen(caps);
    unsigned i = 0;
    while (i < len && used + 1 < cap_size) {
        unsigned start = i;
        while (i < len && px[i] != '\r' && px[i] != '\n')
            i++;
        if (i > start &&
            !ftp_starts(px + start, i - start, "211-") &&
            !ftp_starts(px + start, i - start, "211 ")) {
            int n = snprintf(caps + used, cap_size - used, "%s%.*s",
                             used ? "; " : "", (int)(i - start),
                             px + start);
            if (n > 0) used += (size_t)n;
        }
        while (i < len && (px[i] == '\r' || px[i] == '\n'))
            i++;
    }
}

static unsigned ftp_parse(DataPass *pass, ProbeState *state, OutConf *out,
                          ProbeTarget *target, const unsigned char *px,
                          unsigned sizeof_px) {
    char *banner = state->data;
    if (state->state == 0) {
        if (!ftp_starts(px, sizeof_px, "220"))
            return 0;
        if (banner) {
            unsigned n = sizeof_px < 1023 ? sizeof_px : 1023;
            memcpy(banner, px, n);
            banner[n] = 0;
        }
        state->state = 1;
        datapass_set_data(pass, (unsigned char *)"FEAT\r\n", 6, false);
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
        ftp_append_caps(px, sizeof_px, caps, sizeof(caps));
        if (banner && banner[0])
            dach_append_banner(&item.probe_report, "ftp_banner",
                               (unsigned char *)banner, strlen(banner));
        dach_append_str(&item.probe_report, "ftp_capabilities", caps,
                        strlen(caps));
        dach_set_bool(&item.probe_report, "ftp_auth_tls",
                      strstr(caps, "AUTH TLS") != NULL);
        safe_strcpy(item.classification, OUT_CLS_SIZE, "ftp");
        safe_strcpy(item.reason, OUT_RSN_SIZE, "feat");
        item.level = OUT_SUCCESS;
        output_result(out, &item);
        pass->is_close = 1;
    }
    return 0;
}

Probe FtpProbe = {
    .name       = "ftp",
    .type       = ProbeType_TCP,
    .short_desc = "Read the FTP 220 banner (stateless).",
    .desc = "Wait for the FTP 220 greeting and report the banner/code. No "
            "FEAT or AUTH is sent. Single slot; use ftp-state for features and "
            "AUTH TLS.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &probe_make_no_payload,
    .get_payload_length_cb = &probe_no_payload_length,
    .handle_response_cb    = &ftp_tcp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe FtpStateProbe = {
    .name       = "ftp-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "FTP greeting and FEAT capability probe.",
    .params     = ftp_state_parameters,
    .desc = "Read the 220 greeting, send `FEAT`, parse multiline 211 features "
            "and report AUTH TLS availability. No USER/PASS or authentication. "
            "State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &ftp_conn_init,
    .make_hello_cb     = &ftp_hello,
    .parse_response_cb = &ftp_parse,
    .conn_close_cb     = &ftp_conn_close,
    .close_cb          = &probe_close_nothing,
};
