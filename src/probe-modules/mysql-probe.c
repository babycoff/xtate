#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe MysqlProbe;
extern Probe MysqlStateProbe;

static unsigned mysql_read_le16(const unsigned char *p) {
    return p[0] | ((unsigned)p[1] << 8);
}

static unsigned mysql_read_le32(const unsigned char *p) {
    return p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) |
           ((unsigned)p[3] << 24);
}

static unsigned mysql_read_le24(const unsigned char *p) {
    return p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16);
}

static bool mysql_parse_greeting(const unsigned char *px, unsigned len,
                                 OutItem *item) {
    if (len < 5 || px[0] != 10)
        return false;

    unsigned i = 1;
    unsigned vstart = i;
    while (i < len && px[i] != 0)
        i++;
    if (i == vstart || i >= len)
        return false;
    dach_append_str(&item->probe_report, "mysql_version", px + vstart,
                    i - vstart);
    i++;
    if (i + 4 > len)
        return false;
    unsigned conn_id = mysql_read_le32(px + i);
    dach_set_int(&item->probe_report, "mysql_protocol", px[0]);
    dach_set_int(&item->probe_report, "mysql_connection_id", conn_id);
    i += 4 + 8 + 1;
    if (i + 2 + 1 + 2 > len)
        return false;
    unsigned caps_lo = mysql_read_le16(px + i);
    i += 2;
    dach_set_int(&item->probe_report, "mysql_charset", px[i]);
    i += 1 + 2;
    unsigned caps_hi = mysql_read_le16(px + i);
    i += 2;
    dach_set_int(&item->probe_report, "mysql_capabilities",
                 caps_lo | (caps_hi << 16));

    if (i + 1 + 10 <= len) {
        i += 1 + 10;
        if (i < len) {
            unsigned start = i;
            while (i < len && px[i] != 0)
                i++;
            if (i > start)
                dach_append_str(&item->probe_report, "mysql_auth_plugin",
                                px + start, i - start);
        }
    }

    safe_strcpy(item->classification, OUT_CLS_SIZE, "mysql");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "greeting");
    item->level = OUT_SUCCESS;
    return true;
}

static unsigned mysql_tcp_handle(unsigned th_idx, ProbeTarget *target,
                                 const unsigned char *px, unsigned sizeof_px,
                                 OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (sizeof_px < 4) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "mysql");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "short greeting");
        return 0;
    }
    unsigned plen = mysql_read_le24(px);
    if (plen + 4 > sizeof_px)
        plen = sizeof_px - 4;
    if (!mysql_parse_greeting(px + 4, plen, item)) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "mysql");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "invalid greeting");
    }
    return 0;
}

static void mysql_state_hello(DataPass *pass, ProbeState *state,
                              ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
    datapass_set_data(pass, NULL, 0, false);
}

static unsigned mysql_state_parse(DataPass *pass, ProbeState *state,
                                  OutConf *out, ProbeTarget *target,
                                  const unsigned char *px, unsigned sizeof_px) {
    UNUSEDPARM(pass);
    UNUSEDPARM(target);
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
    if (sizeof_px < 4)
        goto fail;
    unsigned plen = mysql_read_le24(px);
    if (plen + 4 > sizeof_px)
        plen = sizeof_px - 4;
    if (mysql_parse_greeting(px + 4, plen, &item)) {
        output_result(out, &item);
        return 0;
    }
fail:
    item.level = OUT_FAILURE;
    safe_strcpy(item.classification, OUT_CLS_SIZE, "mysql");
    safe_strcpy(item.reason, OUT_RSN_SIZE, "invalid greeting");
    output_result(out, &item);
    return 0;
}

Probe MysqlProbe = {
    .name       = "mysql",
    .type       = ProbeType_TCP,
    .short_desc = "Read the MySQL server greeting (stateless).",
    .desc = "Wait for the MySQL server greeting and parse protocol version, "
            "server version, connection id, capability flags, charset and auth "
            "plugin. It sends no client response and no credentials. Single "
            "slot; for capability/auth follow-up use mysql-state.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &probe_make_no_payload,
    .get_payload_length_cb = &probe_no_payload_length,
    .handle_response_cb    = &mysql_tcp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe MysqlStateProbe = {
    .name       = "mysql-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "Read the MySQL server greeting over tcp-state.",
    .desc = "Stateful variant of mysql: wait for the server greeting, parse "
            "the same fields, then close without sending auth. Use tcp-state. "
            "No credentials or queries are sent.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &mysql_state_hello,
    .parse_response_cb = &mysql_state_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
