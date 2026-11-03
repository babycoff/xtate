#include "../../src/probe-modules/probe-modules.h"
#include "../../src/util-data/safe-string.h"
#include "../../src/util-misc/misc.h"

#include <stdio.h>

static size_t example_tcp_make(ProbeTarget *target, unsigned char *buf) {
    UNUSEDPARM(target);
    return (size_t)snprintf((char *)buf, PM_PAYLOAD_SIZE, "PING\r\n");
}

static size_t example_tcp_len(ProbeTarget *target) {
    UNUSEDPARM(target);
    return 6;
}

static unsigned example_tcp_handle(unsigned th_idx, ProbeTarget *target,
                                   const unsigned char *px,
                                   unsigned sizeof_px, OutItem *item) {
    UNUSEDPARM(th_idx);
    dach_set_int(&item->probe_report, "example_slot", target->index + 1);
    dach_append_banner(&item->probe_report, "banner", px, sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "example");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "reply");
    item->level = OUT_SUCCESS;
    return 0;
}

Probe ExampleTcpProbe = {
    .name = "example-tcp",
    .type = ProbeType_TCP,
    .slots = {.count = 1, .trigger = ProbeSlot_None, .continue_cb = NULL},
    .desc = "Compile-tested single-slot TCP probe template.",
    .init_cb = &probe_init_nothing,
    .make_payload_cb = &example_tcp_make,
    .get_payload_length_cb = &example_tcp_len,
    .handle_response_cb = &example_tcp_handle,
    .close_cb = &probe_close_nothing,
};
