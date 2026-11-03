#include "../../src/probe-modules/probe-modules.h"
#include "../../src/util-data/safe-string.h"
#include "../../src/util-misc/misc.h"

#include <stdio.h>

static size_t example_udp_make(ProbeTarget *target, unsigned char *buf) {
    UNUSEDPARM(target);
    return (size_t)snprintf((char *)buf, PM_PAYLOAD_SIZE, "PING\r\n");
}

static unsigned example_udp_handle(unsigned th_idx, ProbeTarget *target,
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

Probe ExampleUdpProbe = {
    .name = "example-udp",
    .type = ProbeType_UDP,
    .slots = {.count = 1, .trigger = ProbeSlot_None, .continue_cb = NULL},
    .desc = "Compile-tested UDP probe template.",
    .init_cb = &probe_init_nothing,
    .make_payload_cb = &example_udp_make,
    .validate_response_cb = &probe_all_response_valid,
    .handle_response_cb = &example_udp_handle,
    .close_cb = &probe_close_nothing,
};
