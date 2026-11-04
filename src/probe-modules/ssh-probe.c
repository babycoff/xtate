#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

#define SSH_HELLO "SSH-2.0-Xtate_1.0\r\n"

static size_t ssh_make_payload(ProbeTarget *target, unsigned char *payload_buf) {
    UNUSEDPARM(target);
    memcpy(payload_buf, SSH_HELLO, sizeof(SSH_HELLO) - 1);
    return sizeof(SSH_HELLO) - 1;
}

static size_t ssh_payload_length(ProbeTarget *target) {
    UNUSEDPARM(target);
    return sizeof(SSH_HELLO) - 1;
}

static unsigned ssh_handle(unsigned th_idx, ProbeTarget *target,
                           const unsigned char *px, unsigned sizeof_px,
                           OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);

    if (sizeof_px < 4 || memcmp(px, "SSH-", 4) != 0) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not ssh");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "invalid banner");
        return 0;
    }

    const char *line_end = memchr(px, '\n', sizeof_px);
    size_t      line_len = line_end ? (size_t)(line_end - (const char *)px)
                                    : sizeof_px;
    if (line_len && px[line_len - 1] == '\r')
        line_len--;

    dach_append_banner(&item->probe_report, "ssh_banner", px, line_len);
    dach_append_str(&item->probe_report, "ssh_protocol", px,
                    line_len < 7 ? line_len : 7);

    /* "SSH-2.0-OpenSSH_9.6" -> software after the protocol prefix. */
    if (line_len > 8) {
        dach_append_banner(&item->probe_report, "ssh_software", px + 8,
                           line_len - 8);
    }

    safe_strcpy(item->classification, OUT_CLS_SIZE, "ssh");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "banner");
    item->level = OUT_SUCCESS;
    return 0;
}

Probe SshProbe = {
    .name       = "ssh",
    .type       = ProbeType_TCP,
    .slots      = {.count = 1, .trigger = ProbeSlot_None, .continue_cb = NULL},
    .short_desc = "Read the SSH identification banner.",
    .desc = "Send an SSH identification string and report the server banner, "
            "protocol prefix and software string. This is a single-slot probe.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &ssh_make_payload,
    .get_payload_length_cb = &ssh_payload_length,
    .handle_response_cb    = &ssh_handle,
    .close_cb              = &probe_close_nothing,
};
