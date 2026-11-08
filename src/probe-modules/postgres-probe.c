#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe PostgresProbe;
extern Probe PostgresStateProbe;

static bool postgres_after_tls;
static ConfRes SET_postgres_after_tls(void *conf, const char *name,
                                      const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    postgres_after_tls = conf_parse_bool(value);
    return Conf_OK;
}
static ConfParam postgres_state_parameters[] = {
    {"after-tls", SET_postgres_after_tls, Type_FLAG, {"post-tls", 0},
     "Run inside an already-established TLS stream: skip SSLRequest and send StartupMessage directly."},
    {0}};

static const unsigned char pg_ssl_request[] = {
    0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f};

/* startup: length, protocol 196608, user=xtate, database=xtate */
static const unsigned char pg_startup[] = {
    0x00, 0x00, 0x00, 0x21, 0x00, 0x03, 0x00, 0x00,
    0x75, 0x73, 0x65, 0x72, 0x00, 0x78, 0x74, 0x61,
    0x74, 0x65, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62,
    0x61, 0x73, 0x65, 0x00, 0x78, 0x74, 0x61, 0x74,
    0x65, 0x00, 0x00};

static void pg_out_ssl(OutItem *item, unsigned char c) {
    dach_set_bool(&item->probe_report, "postgres_ssl_supported", c == 'S');
    dach_set_int(&item->probe_report, "postgres_ssl_byte", c);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "postgres");
    safe_strcpy(item->reason, OUT_RSN_SIZE, c == 'S' ? "ssl supported"
                                                     : "ssl refused");
    item->level = OUT_SUCCESS;
}

static unsigned pg_tcp_handle(unsigned th_idx, ProbeTarget *target,
                              const unsigned char *px, unsigned sizeof_px,
                              OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (sizeof_px < 1 || (px[0] != 'S' && px[0] != 'N')) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "postgres");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not ssl response");
        return 0;
    }
    pg_out_ssl(item, px[0]);
    return 0;
}

static size_t pg_tcp_make(ProbeTarget *target, unsigned char *buf) {
    UNUSEDPARM(target);
    memcpy(buf, pg_ssl_request, sizeof(pg_ssl_request));
    return sizeof(pg_ssl_request);
}

static size_t pg_tcp_len(ProbeTarget *target) {
    UNUSEDPARM(target);
    return sizeof(pg_ssl_request);
}

static void pg_state_hello(DataPass *pass, ProbeState *state,
                           ProbeTarget *target) {
    UNUSEDPARM(target);
    if (postgres_after_tls) {
        state->state = 1;
        datapass_set_data(pass, (unsigned char *)pg_startup,
                          sizeof(pg_startup), false);
    } else {
        datapass_set_data(pass, (unsigned char *)pg_ssl_request,
                          sizeof(pg_ssl_request), false);
    }
}

static void pg_report_error(OutItem *item, const unsigned char *px,
                            unsigned sizeof_px) {
    dach_append_banner(&item->probe_report, "postgres_response", px,
                       sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "postgres");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "error/authentication");
    item->level = OUT_SUCCESS;
}

static unsigned pg_state_parse(DataPass *pass, ProbeState *state, OutConf *out,
                               ProbeTarget *target, const unsigned char *px,
                               unsigned sizeof_px) {
    UNUSEDPARM(target);

    if (state->state == 0) {
        if (sizeof_px < 1)
            return 0;
        if (px[0] == 'S') {
            state->state = 2;
            OutItem item = {
                .target.ip_proto  = target->target.ip_proto,
                .target.ip_them   = target->target.ip_them,
                .target.ip_me     = target->target.ip_me,
                .target.port_them = target->target.port_them,
                .target.port_me   = target->target.port_me,
            };
            pg_out_ssl(&item, px[0]);
            output_result(out, &item);
            pass->is_close = 1;
            return 0;
        }
        if (px[0] == 'N') {
            state->state = 1;
            datapass_set_data(pass, (unsigned char *)pg_startup,
                              sizeof(pg_startup), false);
            return 0;
        }
        return 0;
    }

    if (state->state == 1) {
        state->state = 2;
        if (sizeof_px < 5) {
            return 0;
        }
        OutItem item = {
            .target.ip_proto  = target->target.ip_proto,
            .target.ip_them   = target->target.ip_them,
            .target.ip_me     = target->target.ip_me,
            .target.port_them = target->target.port_them,
            .target.port_me   = target->target.port_me,
        };
        if (px[0] == 'R' && sizeof_px >= 9) {
            unsigned auth = ((unsigned)px[5] << 24) | ((unsigned)px[6] << 16) |
                            ((unsigned)px[7] << 8) | px[8];
            dach_set_int(&item.probe_report, "postgres_auth_type", auth);
            dach_set_bool(&item.probe_report, "postgres_auth_required", true);
            safe_strcpy(item.classification, OUT_CLS_SIZE, "postgres");
            safe_strcpy(item.reason, OUT_RSN_SIZE, "authentication required");
            item.level = OUT_SUCCESS;
        } else if (px[0] == 'E') {
            pg_report_error(&item, px, sizeof_px);
        } else {
            dach_append_banner(&item.probe_report, "postgres_response", px,
                               sizeof_px);
            safe_strcpy(item.classification, OUT_CLS_SIZE, "postgres");
            safe_strcpy(item.reason, OUT_RSN_SIZE, "response");
            item.level = OUT_SUCCESS;
        }
        output_result(out, &item);
        pass->is_close = 1;
    }
    return 0;
}

Probe PostgresProbe = {
    .name       = "postgres",
    .type       = ProbeType_TCP,
    .short_desc = "PostgreSQL SSLRequest capability check.",
    .desc = "Send a PostgreSQL SSLRequest and report whether the server "
            "accepts TLS (S) or refuses it (N). It does not send StartupMessage, "
            "credentials or queries. Use postgres-state for auth/error detail. "
            "Single slot.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &pg_tcp_make,
    .get_payload_length_cb = &pg_tcp_len,
    .handle_response_cb    = &pg_tcp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe PostgresStateProbe = {
    .name       = "postgres-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "PostgreSQL SSLRequest and auth-boundary probe.",
    .params     = postgres_state_parameters,
    .desc = "Send SSLRequest; if TLS is refused, send a StartupMessage with "
            "user/database `xtate` and report the authentication method or "
            "error code, then close. It never sends a password, query or "
            "authenticated startup. State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &pg_state_hello,
    .parse_response_cb = &pg_state_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
