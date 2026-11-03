#include "probe-modules.h"

/*for internal x-ref*/
extern Probe NullProbe;

Probe NullProbe = {
    .name       = "null",
    .type       = ProbeType_TCP,
    .params     = NULL,
    .short_desc =
        "Send nothing and just wait for response in stateless TCP scan.",
    .desc =
        "NullProbe does not send any data to target port. It just wait banner "
        "from server. However, waiting is the cheapest thing while we are in "
        "stateless mode.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &probe_make_no_payload,
    .get_payload_length_cb = &probe_no_payload_length,
    .handle_response_cb    = &probe_just_report_banner,
    .close_cb              = &probe_close_nothing,
};