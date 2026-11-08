#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe MemcachedProbe;

static const char memcached_request[] = "version\r\n";

static size_t memcached_make_payload(ProbeTarget *target,
                                     unsigned char *payload_buf) {
    UNUSEDPARM(target);
    size_t len = sizeof(memcached_request) - 1;
    memcpy(payload_buf, memcached_request, len);
    return len;
}

static size_t memcached_payload_length(ProbeTarget *target) {
    UNUSEDPARM(target);
    return sizeof(memcached_request) - 1;
}

static unsigned memcached_handle(unsigned th_idx, ProbeTarget *target,
                                 const unsigned char *px, unsigned sizeof_px,
                                 OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);

    if (sizeof_px == 0) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "memcached");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "empty response");
        return 0;
    }

    dach_append_banner(&item->probe_report, "memcached_response", px,
                       sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "memcached");

    if (sizeof_px >= 8 && memcmp(px, "VERSION ", 8) == 0) {
        unsigned end = 8;
        while (end < sizeof_px && px[end] != '\r' && px[end] != '\n')
            end++;
        dach_append_str(&item->probe_report, "memcached_version", px + 8,
                        end - 8);
        item->level = OUT_SUCCESS;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "version");
    } else {
        item->level = OUT_FAILURE;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "unexpected response");
    }
    return 0;
}

Probe MemcachedProbe = {
    .name       = "memcached",
    .type       = ProbeType_TCP,
    .short_desc = "Identify Memcached with the version command.",
    .desc = "Send `version\r\n` and parse the version line returned by "
            "Memcached. It is a read-only identification probe. Single slot.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &memcached_make_payload,
    .get_payload_length_cb = &memcached_payload_length,
    .handle_response_cb    = &memcached_handle,
    .close_cb              = &probe_close_nothing,
};
