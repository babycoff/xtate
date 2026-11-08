#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe SmtpProbe;
extern Probe SmtpStateProbe;

static bool smtp_after_tls;
static ConfRes SET_smtp_after_tls(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    smtp_after_tls = conf_parse_bool(value);
    return Conf_OK;
}
static ConfParam smtp_state_parameters[] = {
    {"after-tls", SET_smtp_after_tls, Type_FLAG, {"post-tls", 0},
     "Run inside an already-established TLS/STARTTLS stream: skip the greeting and send EHLO immediately."},
    {0}};

static bool smtp_starts(const unsigned char *px, unsigned len, const char *s) {
    unsigned n = (unsigned)strlen(s);
    return len >= n && memcmp(px, s, n) == 0;
}

static void smtp_banner(const unsigned char *px, unsigned len,
                        OutItem *item) {
    dach_append_banner(&item->probe_report, "smtp_banner", px, len);
    dach_set_int(&item->probe_report, "smtp_code",
                 len >= 3 ? (px[0] - '0') * 100 + (px[1] - '0') * 10 +
                                (px[2] - '0')
                          : 0);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "smtp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "banner");
    item->level = OUT_SUCCESS;
}

static unsigned smtp_tcp_handle(unsigned th_idx, ProbeTarget *target,
                                const unsigned char *px, unsigned sizeof_px,
                                OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (!smtp_starts(px, sizeof_px, "220")) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "smtp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not smtp banner");
        return 0;
    }
    smtp_banner(px, sizeof_px, item);
    return 0;
}

static bool smtp_conn_init(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    state->data = CALLOC(1, 1024);
    return true;
}

static void smtp_conn_close(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    FREE(state->data);
    state->data = NULL;
}

static void smtp_state_hello(DataPass *pass, ProbeState *state,
                             ProbeTarget *target) {
    UNUSEDPARM(target);
    if (smtp_after_tls) {
        state->state = 1;
        datapass_set_data(pass, (unsigned char *)"EHLO xtate\r\n", 12, false);
    } else {
        datapass_set_data(pass, NULL, 0, false);
    }
}

static void smtp_append_caps(const unsigned char *px, unsigned len,
                             char *caps, size_t cap_size) {
    size_t used = strlen(caps);
    unsigned i = 0;
    while (i < len && used + 1 < cap_size) {
        unsigned start = i;
        while (i < len && px[i] != '\r' && px[i] != '\n')
            i++;
        if (i > start + 4 && smtp_starts(px + start, i - start, "250-")) {
            int n = snprintf(caps + used, cap_size - used, "%s%.*s",
                             used ? "; " : "", (int)(i - start - 4),
                             px + start + 4);
            if (n > 0) used += (size_t)n;
        } else if (i > start + 4 && smtp_starts(px + start, i - start, "250 ")) {
            int n = snprintf(caps + used, cap_size - used, "%s%.*s",
                             used ? "; " : "", (int)(i - start - 4),
                             px + start + 4);
            if (n > 0) used += (size_t)n;
        }
        while (i < len && (px[i] == '\r' || px[i] == '\n'))
            i++;
    }
}

static unsigned smtp_state_parse(DataPass *pass, ProbeState *state,
                                 OutConf *out, ProbeTarget *target,
                                 const unsigned char *px, unsigned sizeof_px) {
    char *banner = state->data;
    if (state->state == 0) {
        if (!smtp_starts(px, sizeof_px, "220"))
            return 0;
        if (banner) {
            unsigned n = sizeof_px < 1023 ? sizeof_px : 1023;
            memcpy(banner, px, n);
            banner[n] = 0;
        }
        state->state = 1;
        datapass_set_data(pass, (unsigned char *)"EHLO xtate\r\n", 12, false);
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
        smtp_append_caps(px, sizeof_px, caps, sizeof(caps));
        if (banner && banner[0])
            dach_append_banner(&item.probe_report, "smtp_banner",
                               (unsigned char *)banner, strlen(banner));
        dach_append_str(&item.probe_report, "smtp_capabilities", caps,
                        strlen(caps));
        dach_set_bool(&item.probe_report, "smtp_starttls",
                      strstr(caps, "STARTTLS") != NULL);
        dach_set_bool(&item.probe_report, "smtp_auth",
                      strstr(caps, "AUTH") != NULL);
        safe_strcpy(item.classification, OUT_CLS_SIZE, "smtp");
        safe_strcpy(item.reason, OUT_RSN_SIZE, "ehlo");
        item.level = OUT_SUCCESS;
        output_result(out, &item);
        pass->is_close = 1;
    }
    return 0;
}

Probe SmtpProbe = {
    .name       = "smtp",
    .type       = ProbeType_TCP,
    .short_desc = "Read the SMTP 220 banner (stateless).",
    .desc = "Wait for the SMTP 220 greeting and report the banner/code. No "
            "EHLO, STARTTLS or AUTH is sent. Single slot; use smtp-state for "
            "EHLO capabilities.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &probe_make_no_payload,
    .get_payload_length_cb = &probe_no_payload_length,
    .handle_response_cb    = &smtp_tcp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe SmtpStateProbe = {
    .name       = "smtp-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "SMTP greeting and EHLO capability probe.",
    .desc = "Read the 220 greeting, send `EHLO xtate`, parse multiline 250 "
            "capabilities and report STARTTLS/AUTH availability. No AUTH or "
            "mail commands. Use --after-tls when composed inside tls-state "
            "(implicit TLS or STARTTLS). State probe.",
    .params     = smtp_state_parameters,
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &smtp_conn_init,
    .make_hello_cb     = &smtp_state_hello,
    .parse_response_cb = &smtp_state_parse,
    .conn_close_cb     = &smtp_conn_close,
    .close_cb          = &probe_close_nothing,
};
