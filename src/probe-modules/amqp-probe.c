#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe AmqpProbe;
extern Probe AmqpStateProbe;

static const unsigned char amqp_header[] = {
    'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01};

static size_t amqp_make(ProbeTarget *target, unsigned char *buf) {
    UNUSEDPARM(target);
    memcpy(buf, amqp_header, sizeof(amqp_header));
    return sizeof(amqp_header);
}

static size_t amqp_len(ProbeTarget *target) {
    UNUSEDPARM(target);
    return sizeof(amqp_header);
}

static unsigned amqp_handle(unsigned th_idx, ProbeTarget *target,
                            const unsigned char *px, unsigned sizeof_px,
                            OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (sizeof_px < 13 || px[0] != 1 || px[8] != 10 || px[10] != 10) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "amqp");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not connection.start");
        return 0;
    }
    dach_append_str(&item->probe_report, "amqp_protocol", "AMQP 0-9-1", 10);
    if (sizeof_px > 9) {
        dach_set_int(&item->probe_report, "amqp_version_major", px[11]);
        dach_set_int(&item->probe_report, "amqp_version_minor", px[12]);
    }
    dach_append_banner(&item->probe_report, "amqp_response", px, sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "amqp");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "connection.start");
    item->level = OUT_SUCCESS;
    return 0;
}

static void amqp_state_hello(DataPass *pass, ProbeState *state,
                             ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
    datapass_set_data(pass, (unsigned char *)amqp_header, sizeof(amqp_header),
                      false);
}

static unsigned amqp_state_parse(DataPass *pass, ProbeState *state,
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
    amqp_handle(0, target, px, sizeof_px, &item);
    output_result(out, &item);
    pass->is_close = 1;
    return 0;
}

Probe AmqpProbe = {
    .name       = "amqp",
    .type       = ProbeType_TCP,
    .short_desc = "AMQP 0-9-1 protocol header and Connection.Start.",
    .desc = "Send the AMQP 0-9-1 protocol header and parse the Connection.Start "
            "version. No authentication or channel opening. Single slot; "
            "amqp-state supports tls-state composition.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &amqp_make,
    .get_payload_length_cb = &amqp_len,
    .handle_response_cb    = &amqp_handle,
    .close_cb              = &probe_close_nothing,
};

Probe AmqpStateProbe = {
    .name       = "amqp-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "AMQP Connection.Start over tcp-state/TLS.",
    .desc = "Stateful AMQP 0-9-1 header probe for tcp-state or tls-state. No "
            "authentication or channel opening. State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &amqp_state_hello,
    .parse_response_cb = &amqp_state_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
