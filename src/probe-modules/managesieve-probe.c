#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe ManageSieveProbe;
extern Probe ManageSieveStateProbe;

static bool sieve_after_tls;
static ConfRes SET_sieve_after_tls(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    sieve_after_tls = conf_parse_bool(value);
    return Conf_OK;
}
static ConfParam sieve_state_parameters[] = {
    {"after-tls", SET_sieve_after_tls, Type_FLAG, {"post-tls", 0},
     "Lab/compatibility wake-up only: send NOOP so the server-first capability greeting is delivered inside TLS. It is not a replacement for a normal ManageSieve handshake and may be rejected by strict servers."},
    {0}};

static void sieve_banner(const unsigned char *px, unsigned len, OutItem *item) {
    dach_append_banner(&item->probe_report, "sieve_banner", px, len);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "managesieve");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "banner");
    item->level = OUT_SUCCESS;
}

static unsigned sieve_tcp_handle(unsigned th_idx, ProbeTarget *target,
                                 const unsigned char *px, unsigned sizeof_px,
                                 OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (sizeof_px < 2 || px[0] != '"') {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "managesieve");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not sieve banner");
        return 0;
    }
    sieve_banner(px, sizeof_px, item);
    return 0;
}

static void sieve_parse_caps(const unsigned char *px, unsigned len, OutItem *item) {
    char caps[768] = {0};
    size_t used = 0;
    unsigned i = 0;
    while (i < len && used + 1 < sizeof(caps)) {
        while (i < len && px[i] != '"') i++;
        if (i >= len) break;
        unsigned start = ++i;
        while (i < len && px[i] != '"' && px[i] != '\r' && px[i] != '\n') i++;
        unsigned n = i - start;
        if (n && used + n + 3 < sizeof(caps)) {
            int w = snprintf(caps + used, sizeof(caps) - used, "%s%.*s",
                             used ? " " : "", (int)n, px + start);
            if (w > 0) used += (size_t)w;
        }
    }
    dach_append_str(&item->probe_report, "sieve_capabilities", caps, strlen(caps));
    dach_set_bool(&item->probe_report, "sieve_starttls",
                  strstr(caps, "STARTTLS") != NULL);
    dach_set_bool(&item->probe_report, "sieve_sasl",
                  strstr(caps, "SASL") != NULL);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "managesieve");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "capabilities");
    item->level = OUT_SUCCESS;
}

static void sieve_hello(DataPass *pass, ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
    if (sieve_after_tls)
        datapass_set_data(pass, (unsigned char *)"NOOP\r\n", 6, false);
    else
        datapass_set_data(pass, NULL, 0, false);
}

static unsigned sieve_state_parse(DataPass *pass, ProbeState *state,
                                  OutConf *out, ProbeTarget *target,
                                  const unsigned char *px, unsigned sizeof_px) {
    UNUSEDPARM(pass);
    if (state->state)
        return 0;
    state->state = 1;
    if (sizeof_px < 2 || px[0] != '"')
        return 0;
    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = target->target.port_me,
    };
    sieve_banner(px, sizeof_px, &item);
    sieve_parse_caps(px, sizeof_px, &item);
    output_result(out, &item);
    return 0;
}

Probe ManageSieveProbe = {
    .name       = "managesieve",
    .type       = ProbeType_TCP,
    .short_desc = "Read the ManageSieve capability greeting (stateless).",
    .desc = "Wait for the ManageSieve quoted-string capability greeting and "
            "report the banner. No STARTTLS or authentication. Single slot; "
            "use managesieve-state for parsed capabilities.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &probe_make_no_payload,
    .get_payload_length_cb = &probe_no_payload_length,
    .handle_response_cb    = &sieve_tcp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe ManageSieveStateProbe = {
    .name       = "managesieve-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "ManageSieve capability greeting probe.",
    .params     = sieve_state_parameters,
    .desc = "Read the ManageSieve capability greeting, parse quoted capability "
            "strings and report STARTTLS/SASL availability. No authentication. "
            "State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &sieve_hello,
    .parse_response_cb = &sieve_state_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
