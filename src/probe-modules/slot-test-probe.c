#include "probe-modules.h"

#include <stdio.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

/*
 * Developer example: ProbeSlot_Always with three independent TCP flows.
 * Every slot sends "slot:<one-based index>\n".  The handler reports both the
 * slot number and the received bytes.  This probe is intentionally trivial so
 * it can be used as a test fixture and as a copyable example.
 */

static size_t slot_test_make_payload(ProbeTarget   *target,
                                     unsigned char *payload_buf) {
    return (size_t)snprintf((char *)payload_buf, PM_PAYLOAD_SIZE, "slot:%u\n",
                            target->index + 1);
}

static size_t slot_test_payload_length(ProbeTarget *target) {
    char buf[32];
    return (size_t)snprintf(buf, sizeof(buf), "slot:%u\n", target->index + 1);
}

static unsigned slot_test_handle(unsigned th_idx, ProbeTarget *target,
                                 const unsigned char *px, unsigned sizeof_px,
                                 OutItem *item) {
    UNUSEDPARM(th_idx);

    dach_set_int(&item->probe_report, "slot_test_slot", target->index + 1);
    dach_append_banner(&item->probe_report, "slot_test_payload", px,
                       sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "slot");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "echo");
    item->level = OUT_SUCCESS;
    return 0;
}

Probe SlotTestProbe = {
    .name       = "slot-test",
    .type       = ProbeType_TCP,
    .slots      = {.count = 3,
                   .trigger = ProbeSlot_Always,
                   .continue_cb = NULL},
    .short_desc = "Three-slot TCP ProbeSlot_Always example.",
    .desc = "Send `slot:<n>\\n` on three independent TCP flows and report the "
            "slot number and received bytes. This is a developer example and "
            "test fixture for ProbeSlot_Always.\n"
            "No dependency.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &slot_test_make_payload,
    .get_payload_length_cb = &slot_test_payload_length,
    .handle_response_cb    = &slot_test_handle,
    .close_cb              = &probe_close_nothing,
};
