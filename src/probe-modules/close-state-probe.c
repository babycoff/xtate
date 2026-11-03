#include "probe-modules.h"

#include <string.h>
#include <stdio.h>

#include "../output-modules/output-modules.h"

/*for internal x-ref*/
extern Probe CloseStateProbe;

static void closestate_make_hello(DataPass *pass, ProbeState *state,
                                  ProbeTarget *target) {
    pass->is_close = 1;
}

static unsigned closestate_parse_response(DataPass *pass, ProbeState *state,
                                          OutConf *out, ProbeTarget *target,
                                          const unsigned char *px,
                                          unsigned             sizeof_px) {
    pass->is_close = 1;
    return 0;
}

Probe CloseStateProbe = {
    .name       = "close-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .params     = NULL,
    .short_desc = "Send nothing and just close lower-layer connection in "
                  "stateful TCP scan.",
    .desc =
        "CloseState Probe does nothing but close after lower level connection "
        "established. It's useful when we just want to obtain some information "
        "of connection by lower level module.",

    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &closestate_make_hello,
    .parse_response_cb = &closestate_parse_response,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};