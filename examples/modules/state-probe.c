#include "../../src/probe-modules/probe-modules.h"
#include "../../src/output-modules/output-modules.h"
#include "../../src/util-data/safe-string.h"
#include "../../src/util-misc/misc.h"

#include <string.h>

static const unsigned char EXAMPLE_HELLO[] = "PING\r\n";

static bool example_state_conn_init(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    state->state = 0;
    return true;
}

static void example_state_make_hello(DataPass *pass, ProbeState *state,
                                     ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
    datapass_set_data(pass, (unsigned char *)EXAMPLE_HELLO,
                      sizeof(EXAMPLE_HELLO) - 1, false);
}

static unsigned example_state_parse(DataPass *pass, ProbeState *state,
                                    OutConf *out, ProbeTarget *target,
                                    const unsigned char *px,
                                    unsigned sizeof_px) {
    UNUSEDPARM(state);
    OutItem item = {
        .level = OUT_SUCCESS,
        .target.ip_proto = target->target.ip_proto,
        .target.ip_them = target->target.ip_them,
        .target.ip_me = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me = target->target.port_me,
    };
    dach_append_banner(&item.probe_report, "banner", px, sizeof_px);
    safe_strcpy(item.classification, OUT_CLS_SIZE, "example");
    safe_strcpy(item.reason, OUT_RSN_SIZE, "state reply");
    output_result(out, &item);
    pass->is_close = 1;
    return 0;
}

static void example_state_conn_close(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
}

Probe ExampleStateProbe = {
    .name = "example-state",
    .type = ProbeType_STATE,
    .desc = "Compile-tested HLTCP state-probe template.",
    .init_cb = &probe_init_nothing,
    .conn_init_cb = &example_state_conn_init,
    .make_hello_cb = &example_state_make_hello,
    .parse_response_cb = &example_state_parse,
    .conn_close_cb = &example_state_conn_close,
    .close_cb = &probe_close_nothing,
};
