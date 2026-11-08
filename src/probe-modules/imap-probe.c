#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe ImapProbe;
extern Probe ImapStateProbe;

static bool imap_starts(const unsigned char *px, unsigned len, const char *s) {
    unsigned n = (unsigned)strlen(s);
    return len >= n && memcmp(px, s, n) == 0;
}

static void imap_banner(const unsigned char *px, unsigned len, OutItem *item) {
    dach_append_banner(&item->probe_report, "imap_banner", px, len);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "imap");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "banner");
    item->level = OUT_SUCCESS;
}

static unsigned imap_tcp_handle(unsigned th_idx, ProbeTarget *target,
                                const unsigned char *px, unsigned sizeof_px,
                                OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (!imap_starts(px, sizeof_px, "* OK") &&
        !imap_starts(px, sizeof_px, "* PREAUTH")) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "imap");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not imap banner");
        return 0;
    }
    imap_banner(px, sizeof_px, item);
    return 0;
}

static bool imap_conn_init(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    state->data = CALLOC(1, 1024);
    return true;
}

static void imap_conn_close(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    FREE(state->data);
    state->data = NULL;
}

static void imap_hello(DataPass *pass, ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
    datapass_set_data(pass, NULL, 0, false);
}

static unsigned imap_parse(DataPass *pass, ProbeState *state, OutConf *out,
                           ProbeTarget *target, const unsigned char *px,
                           unsigned sizeof_px) {
    char *banner = state->data;
    if (state->state == 0) {
        if (!imap_starts(px, sizeof_px, "* OK") &&
            !imap_starts(px, sizeof_px, "* PREAUTH"))
            return 0;
        if (banner) {
            unsigned n = sizeof_px < 1023 ? sizeof_px : 1023;
            memcpy(banner, px, n);
            banner[n] = 0;
        }
        state->state = 1;
        datapass_set_data(pass, (unsigned char *)"a1 CAPABILITY\r\n", 15,
                          false);
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
        const char *needle = "* CAPABILITY ";
        const unsigned char *p = px;
        for (unsigned i = 0; i + 13 < sizeof_px; i++) {
            if (memcmp(px + i, needle, 13) == 0) {
                unsigned j = i + 13;
                unsigned start = j;
                while (j < sizeof_px && px[j] != '\r' && px[j] != '\n')
                    j++;
                unsigned n = j - start;
                if (n >= sizeof(caps))
                    n = sizeof(caps) - 1;
                memcpy(caps, px + start, n);
                caps[n] = 0;
                break;
            }
        }
        if (banner && banner[0])
            dach_append_banner(&item.probe_report, "imap_banner",
                               (unsigned char *)banner, strlen(banner));
        dach_append_str(&item.probe_report, "imap_capabilities", caps,
                        strlen(caps));
        dach_set_bool(&item.probe_report, "imap_starttls",
                      strstr(caps, "STARTTLS") != NULL);
        safe_strcpy(item.classification, OUT_CLS_SIZE, "imap");
        safe_strcpy(item.reason, OUT_RSN_SIZE, "capability");
        item.level = OUT_SUCCESS;
        output_result(out, &item);
        pass->is_close = 1;
    }
    return 0;
}

Probe ImapProbe = {
    .name       = "imap",
    .type       = ProbeType_TCP,
    .short_desc = "Read the IMAP greeting (stateless).",
    .desc = "Wait for the IMAP `* OK`/`* PREAUTH` greeting and report the "
            "banner. No CAPABILITY command or authentication is sent. Single "
            "slot; use imap-state for capabilities.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &probe_make_no_payload,
    .get_payload_length_cb = &probe_no_payload_length,
    .handle_response_cb    = &imap_tcp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe ImapStateProbe = {
    .name       = "imap-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "IMAP greeting and CAPABILITY probe.",
    .desc = "Read the IMAP greeting, send `a1 CAPABILITY`, parse the "
            "capability list and report STARTTLS availability. No LOGIN or "
            "authentication. State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &imap_conn_init,
    .make_hello_cb     = &imap_hello,
    .parse_response_cb = &imap_parse,
    .conn_close_cb     = &imap_conn_close,
    .close_cb          = &probe_close_nothing,
};
