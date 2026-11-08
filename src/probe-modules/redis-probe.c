#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe RedisProbe;

static const char redis_request[] = "INFO server\r\n";

static size_t redis_make_payload(ProbeTarget *target,
                                 unsigned char *payload_buf) {
    UNUSEDPARM(target);
    size_t len = sizeof(redis_request) - 1;
    memcpy(payload_buf, redis_request, len);
    return len;
}

static size_t redis_payload_length(ProbeTarget *target) {
    UNUSEDPARM(target);
    return sizeof(redis_request) - 1;
}

static const char *redis_find_value(const unsigned char *px, unsigned len,
                                    const char *name, char *out,
                                    size_t out_size) {
    size_t nlen = strlen(name);
    for (unsigned i = 0; i + nlen < len; i++) {
        if (memcmp(px + i, name, nlen) != 0)
            continue;
        if (i + nlen >= len || px[i + nlen] != ':')
            continue;
        unsigned start = i + nlen + 1;
        unsigned end = start;
        while (end < len && px[end] != '\r' && px[end] != '\n')
            end++;
        size_t n = end - start;
        if (n >= out_size)
            n = out_size - 1;
        memcpy(out, px + start, n);
        out[n] = '\0';
        return out;
    }
    return NULL;
}

static unsigned redis_handle(unsigned th_idx, ProbeTarget *target,
                             const unsigned char *px, unsigned sizeof_px,
                             OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);

    if (sizeof_px == 0) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "redis");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "empty response");
        return 0;
    }

    dach_append_banner(&item->probe_report, "redis_response", px, sizeof_px);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "redis");

    if (px[0] == '-' || (px[0] == '\r' && sizeof_px > 1 && px[1] == '\n')) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->reason, OUT_RSN_SIZE, "error response");
        return 0;
    }

    char value[256];
    if (redis_find_value(px, sizeof_px, "redis_version", value,
                         sizeof(value))) {
        dach_append_str(&item->probe_report, "redis_version", value,
                        strlen(value));
    }
    if (redis_find_value(px, sizeof_px, "redis_mode", value, sizeof(value))) {
        dach_append_str(&item->probe_report, "redis_mode", value,
                        strlen(value));
    }
    if (redis_find_value(px, sizeof_px, "os", value, sizeof(value))) {
        dach_append_str(&item->probe_report, "redis_os", value, strlen(value));
    }
    if (redis_find_value(px, sizeof_px, "role", value, sizeof(value))) {
        dach_append_str(&item->probe_report, "redis_role", value,
                        strlen(value));
    }

    item->level = OUT_SUCCESS;
    safe_strcpy(item->reason, OUT_RSN_SIZE, "response");
    return 0;
}

Probe RedisProbe = {
    .name       = "redis",
    .type       = ProbeType_TCP,
    .short_desc = "Identify Redis with INFO server.",
    .desc = "Send `INFO server\r\n` to a Redis endpoint and parse redis_version, "
            "redis_mode, os and role. It is an unauthenticated identification "
            "probe; no commands that mutate data are sent. Single slot.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &redis_make_payload,
    .get_payload_length_cb = &redis_payload_length,
    .handle_response_cb    = &redis_handle,
    .close_cb              = &probe_close_nothing,
};
