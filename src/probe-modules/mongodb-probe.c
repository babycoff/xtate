#include "probe-modules.h"
#include "../output-modules/output-modules.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

extern Probe MongodbProbe;

static const unsigned char mongodb_hello[] = {
    0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xdd, 0x07, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00,
    0x00, 0x10, 'h', 'e', 'l', 'l', 'o', 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, '$', 'd', 'b', 0x00, 0x05, 0x00, 0x00,
    0x00, 'a', 'd', 'm', 'i', 'n', 0x00, 0x00};

static unsigned bson_i32(const unsigned char *p) {
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) |
           ((unsigned)p[3] << 24);
}

static bool bson_skip(const unsigned char *d, unsigned len, unsigned *off,
                      unsigned type) {
    if (*off >= len)
        return false;
    switch (type) {
        case 0x01:
            *off += 8;
            return *off <= len;
        case 0x02:
            if (*off + 4 > len)
                return false;
            *off += bson_i32(d + *off);
            return *off <= len;
        case 0x03:
        case 0x04:
            if (*off + 4 > len)
                return false;
            *off += bson_i32(d + *off);
            return *off <= len;
        case 0x05:
            if (*off + 4 > len)
                return false;
            *off += 4 + bson_i32(d + *off);
            return *off <= len;
        case 0x07:
            *off += 12;
            return *off <= len;
        case 0x08:
            *off += 1;
            return *off <= len;
        case 0x09:
            *off += 8;
            return *off <= len;
        case 0x0a:
            return true;
        case 0x10:
        case 0x12:
            *off += 4;
            return *off <= len;
        case 0x11:
            *off += 8;
            return *off <= len;
        case 0x13:
            *off += 16;
            return *off <= len;
        default:
            return false;
    }
}

static bool bson_cstring(const unsigned char *d, unsigned len, unsigned *off,
                         char *out, size_t out_size) {
    unsigned start = *off;
    while (*off < len && d[*off] != 0)
        (*off)++;
    if (*off >= len)
        return false;
    unsigned n = *off - start;
    if (n >= out_size)
        n = out_size - 1;
    memcpy(out, d + start, n);
    out[n] = '\0';
    (*off)++;
    return true;
}

static void mongodb_parse_bson(const unsigned char *d, unsigned len,
                               OutItem *item) {
    if (len < 5)
        return;
    unsigned end = bson_i32(d);
    if (end > len)
        end = len;
    unsigned off = 4;
    while (off + 1 < end && d[off] != 0) {
        unsigned type = d[off++];
        char key[64];
        if (!bson_cstring(d, end, &off, key, sizeof(key)))
            return;
        unsigned vstart = off;
        if (strcmp(key, "ok") == 0) {
            bool ok = false;
            if (type == 0x08 && off < end) {
                ok = d[off] != 0;
            } else if (type == 0x10 && off + 4 <= end) {
                ok = bson_i32(d + off) != 0;
            } else if (type == 0x01 && off + 8 <= end) {
                ok = d[off + 7] != 0;
            }
            dach_set_bool(&item->probe_report, "mongodb_ok", ok);
        } else if (strcmp(key, "maxWireVersion") == 0 && type == 0x10 &&
                   off + 4 <= end) {
            dach_set_int(&item->probe_report, "mongodb_wire_version",
                         bson_i32(d + off));
        } else if (strcmp(key, "version") == 0 && type == 0x02 &&
                   off + 4 <= end) {
            unsigned slen = bson_i32(d + off);
            /* The 4-byte length prefix precedes the string bytes; the length
             * includes the trailing NUL, so slen-1 bytes are payload. */
            if (slen > 1 && slen - 1 <= end - (off + 4)) {
                dach_append_str(&item->probe_report, "mongodb_version",
                                d + off + 4, slen - 1);
            }
        } else if (strcmp(key, "isWritablePrimary") == 0 && type == 0x08 &&
                   off < end) {
            dach_set_bool(&item->probe_report, "mongodb_is_writable_primary",
                          d[off] != 0);
        }
        if (!bson_skip(d, end, &off, type))
            return;
        (void)vstart;
    }
}

static size_t mongodb_make(ProbeTarget *target, unsigned char *buf) {
    UNUSEDPARM(target);
    memcpy(buf, mongodb_hello, sizeof(mongodb_hello));
    return sizeof(mongodb_hello);
}

static size_t mongodb_len(ProbeTarget *target) {
    UNUSEDPARM(target);
    return sizeof(mongodb_hello);
}

static unsigned mongodb_handle(unsigned th_idx, ProbeTarget *target,
                               const unsigned char *px, unsigned sizeof_px,
                               OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);
    if (sizeof_px < 21 || px[12] != 0xdd || px[13] != 0x07) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "mongodb");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not op_msg");
        return 0;
    }
    unsigned off = 20;
    if (px[off] == 1)
        off++;
    if (off >= sizeof_px) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "mongodb");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "truncated op_msg");
        return 0;
    }
    if (px[off] != 0) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "mongodb");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "unsupported section");
        return 0;
    }
    off++;
    dach_set_int(&item->probe_report, "mongodb_response_len", sizeof_px);
    mongodb_parse_bson(px + off, sizeof_px - off, item);
    safe_strcpy(item->classification, OUT_CLS_SIZE, "mongodb");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "hello response");
    item->level = OUT_SUCCESS;
    return 0;
}

static void mongodb_state_hello(DataPass *pass, ProbeState *state,
                                ProbeTarget *target) {
    UNUSEDPARM(state);
    UNUSEDPARM(target);
    datapass_set_data(pass, (unsigned char *)mongodb_hello,
                      sizeof(mongodb_hello), false);
}

static unsigned mongodb_state_parse(DataPass *pass, ProbeState *state,
                                    OutConf *out, ProbeTarget *target,
                                    const unsigned char *px,
                                    unsigned sizeof_px) {
    if (state->state)
        return 0;
    state->state = 1;
    OutItem item = {
        .target.ip_proto  = target->target.ip_proto,
        .target.ip_them   = target->target.ip_them,
        .target.ip_me     = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me   = target->target.port_me,
    };
    mongodb_handle(0, target, px, sizeof_px, &item);
    output_result(out, &item);
    pass->is_close = 1;
    return 0;
}

Probe MongodbProbe = {
    .name       = "mongodb",
    .type       = ProbeType_TCP,
    .short_desc = "MongoDB OP_MSG hello and BSON identification.",
    .desc = "Send an unauthenticated OP_MSG `hello` command and parse the BSON "
            "response for ok, maxWireVersion, server version and primary "
            "status. No authentication or database writes. Single slot.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &mongodb_make,
    .get_payload_length_cb = &mongodb_len,
    .handle_response_cb    = &mongodb_handle,
    .close_cb              = &probe_close_nothing,
};

Probe MongodbStateProbe = {
    .name       = "mongodb-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .short_desc = "MongoDB hello/BSON probe for tls-state composition.",
    .desc = "Stateful MongoDB OP_MSG hello probe. It can run directly over "
            "tcp-state or inside tls-state for implicit TLS. No authentication "
            "or writes. State probe.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &probe_conn_init_nothing,
    .make_hello_cb     = &mongodb_state_hello,
    .parse_response_cb = &mongodb_state_parse,
    .conn_close_cb     = &probe_conn_close_nothing,
    .close_cb          = &probe_close_nothing,
};
