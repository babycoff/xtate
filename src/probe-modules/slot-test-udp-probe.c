#include "probe-modules.h"

#include <stdio.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

/*
 * Developer example: ProbeSlot_Always with three independent UDP flows.
 * UDP has no handshake, so the only natural plan here is Always; all three
 * datagrams are sent from consecutive source ports and matched back by the
 * destination port.
 */

static size_t slot_test_udp_make_payload(ProbeTarget   *target,
                                         unsigned char *payload_buf) {
    return (size_t)snprintf((char *)payload_buf, PM_PAYLOAD_SIZE, "slot:%u\n",
                            target->index + 1);
}

static unsigned slot_test_udp_handle(unsigned th_idx, ProbeTarget *target,
                                     const unsigned char *px,
                                     unsigned sizeof_px, OutItem *item) {
    UNUSEDPARM(th_idx);

    dach_set_int(&item->probe_report, "slot_test_slot", target->index + 1);
    dach_append_banner(&item->probe_report, "slot_test_payload", px,
                       sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "slot");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "echo");
    item->level = OUT_SUCCESS;
    return 0;
}

Probe SlotTestUdpProbe = {
    .name       = "slot-test-udp",
    .type       = ProbeType_UDP,
    .slots      = {.count = 3,
                   .trigger = ProbeSlot_Always,
                   .continue_cb = NULL},
    .short_desc = "Three-slot UDP ProbeSlot_Always example.",
    .desc = "Send `slot:<n>\\n` on three independent UDP flows and report the "
            "slot number and received bytes. This is a developer example and "
            "test fixture for ProbeSlot_Always.\n"
            "No dependency.",

    .init_cb              = &probe_init_nothing,
    .make_payload_cb      = &slot_test_udp_make_payload,
    .validate_response_cb = &probe_all_response_valid,
    .handle_response_cb   = &slot_test_udp_handle,
    .close_cb             = &probe_close_nothing,
};
