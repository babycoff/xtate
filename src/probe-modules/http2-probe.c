#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_SETTINGS_MAX 256

struct Http2Conf {
    unsigned char settings[H2_SETTINGS_MAX];
    size_t        settings_len;
    unsigned char ping[8];
    size_t        ping_len;
    unsigned      ping_enabled    : 1;
    unsigned      all_frames      : 1;
    unsigned      record_settings : 1;
    unsigned      record_raw      : 1;
    unsigned      max_frames;
};

static struct Http2Conf http2_conf = {
    .settings_len = 0,
    .ping = "Xtate/29",
    .ping_len = 8,
    .ping_enabled = 1,
    .all_frames = 0,
    .record_settings = 1,
    .record_raw = 0,
    .max_frames = 4,
};

static bool http2_parse_hex(const char *value, unsigned char *out,
                            size_t out_size, size_t *out_len) {
    size_t len = 0;
    unsigned high = 0;
    bool     have_high = false;
    for (const char *p = value; p && *p; p++) {
        if (*p == ' ' || *p == ':' || *p == '-')
            continue;
        unsigned v;
        if (*p >= '0' && *p <= '9')
            v = (unsigned)(*p - '0');
        else if (*p >= 'a' && *p <= 'f')
            v = (unsigned)(*p - 'a' + 10);
        else if (*p >= 'A' && *p <= 'F')
            v = (unsigned)(*p - 'A' + 10);
        else
            return false;
        if (!have_high) {
            high = v;
            have_high = true;
        } else {
            if (len >= out_size)
                return false;
            out[len++] = (unsigned char)((high << 4) | v);
            have_high = false;
        }
    }
    if (have_high)
        return false;
    *out_len = len;
    return true;
}

static ConfRes SET_settings_hex(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    size_t len = 0;
    if (!http2_parse_hex(value, http2_conf.settings,
                        sizeof(http2_conf.settings), &len))
        return Conf_ERR;
    http2_conf.settings_len = len;
    return Conf_OK;
}

static ConfRes SET_ping_hex(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    size_t len = 0;
    if (!http2_parse_hex(value, http2_conf.ping, sizeof(http2_conf.ping), &len))
        return Conf_ERR;
    http2_conf.ping_len = len;
    http2_conf.ping_enabled = len > 0;
    return Conf_OK;
}

static ConfRes SET_no_ping(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    http2_conf.ping_enabled = !conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_all_frames(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    http2_conf.all_frames = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_max_frames(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    http2_conf.max_frames = conf_parse_int(value);
    if (http2_conf.max_frames < 1)
        http2_conf.max_frames = 1;
    return Conf_OK;
}

static ConfRes SET_no_settings(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    http2_conf.record_settings = !conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_record_raw(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    http2_conf.record_raw = conf_parse_bool(value);
    return Conf_OK;
}

static ConfParam http2_parameters[] = {
    {"settings-hex",
     SET_settings_hex,
     Type_ARG,
     {"settings", 0},
     "Hex payload for the client SETTINGS frame (excluding the 9-byte frame "
     "header). Default is empty. This is the main controlled knob for client "
     "settings; the HTTP/2 preface itself is fixed by RFC 9113."},
    {"ping-hex",
     SET_ping_hex,
     Type_ARG,
     {"ping", 0},
     "Hex payload for the client PING frame (up to 8 bytes). Default is "
     "`Xtate/29`; this is an overt, adjustable client fingerprint."},
    {"no-ping",
     SET_no_ping,
     Type_FLAG,
     {0},
     "Do not send the client PING frame."},
    {"all-frames",
     SET_all_frames,
     Type_FLAG,
     {0},
     "Parse and report every server frame in the captured segment, not only "
     "the first one."},
    {"max-frames",
     SET_max_frames,
     Type_ARG,
     {0},
     "Maximum server frames to parse when --all-frames is used (default 4)."},
    {"no-settings",
     SET_no_settings,
     Type_FLAG,
     {0},
     "Do not record the raw SETTINGS payload."},
    {"record-raw",
     SET_record_raw,
     Type_FLAG,
     {0},
     "Record the complete raw server response as a binary field."},
    {0}};

static size_t http2_make_payload(ProbeTarget *target, unsigned char *payload_buf) {
    UNUSEDPARM(target);
    size_t off = 0;
    size_t preface_len = sizeof(H2_PREFACE) - 1;
    memcpy(payload_buf, H2_PREFACE, preface_len);
    off += preface_len;

    unsigned len = (unsigned)http2_conf.settings_len;
    payload_buf[off++] = (unsigned char)(len >> 16);
    payload_buf[off++] = (unsigned char)(len >> 8);
    payload_buf[off++] = (unsigned char)len;
    payload_buf[off++] = 4; /* SETTINGS */
    payload_buf[off++] = 0; /* flags */
    payload_buf[off++] = 0;
    payload_buf[off++] = 0;
    payload_buf[off++] = 0;
    payload_buf[off++] = 0;
    if (len)
        memcpy(payload_buf + off, http2_conf.settings, len);
    off += len;

    if (http2_conf.ping_enabled && http2_conf.ping_len) {
        payload_buf[off++] = 0;
        payload_buf[off++] = 0;
        payload_buf[off++] = (unsigned char)http2_conf.ping_len;
        payload_buf[off++] = 6; /* PING */
        payload_buf[off++] = 0;
        payload_buf[off++] = 0;
        payload_buf[off++] = 0;
        payload_buf[off++] = 0;
        payload_buf[off++] = 0;
        memcpy(payload_buf + off, http2_conf.ping, http2_conf.ping_len);
        off += http2_conf.ping_len;
    }
    return off;
}

static size_t http2_payload_length(ProbeTarget *target) {
    UNUSEDPARM(target);
    return sizeof(H2_PREFACE) - 1 + 9 + http2_conf.settings_len +
           (http2_conf.ping_enabled ? 9 + http2_conf.ping_len : 0);
}

static void http2_frame_fields(OutItem *item, const char *prefix,
                               unsigned length, unsigned type, unsigned flags,
                               unsigned stream_id) {
    char name[32];
    snprintf(name, sizeof(name), "%s_type", prefix);
    dach_set_int(&item->probe_report, name, type);
    snprintf(name, sizeof(name), "%s_length", prefix);
    dach_set_int(&item->probe_report, name, length);
    snprintf(name, sizeof(name), "%s_flags", prefix);
    dach_set_int(&item->probe_report, name, flags);
    snprintf(name, sizeof(name), "%s_stream_id", prefix);
    dach_set_int(&item->probe_report, name, stream_id);
}

static void http2_settings_fields(OutItem *item, const unsigned char *data,
                                  unsigned length) {
    unsigned count = length / 6;
    dach_set_int(&item->probe_report, "http2_settings_count", count);
    for (unsigned i = 0; i < count; i++) {
        unsigned id = ((unsigned)data[i * 6] << 8) | data[i * 6 + 1];
        unsigned value = ((unsigned)data[i * 6 + 2] << 24) |
                         ((unsigned)data[i * 6 + 3] << 16) |
                         ((unsigned)data[i * 6 + 4] << 8) |
                         (unsigned)data[i * 6 + 5];
        char name[32];
        snprintf(name, sizeof(name), "http2_set_%u", id);
        dach_set_int(&item->probe_report, name, value);
    }
}

static unsigned http2_handle(unsigned th_idx, ProbeTarget *target,
                             const unsigned char *px, unsigned sizeof_px,
                             OutItem *item) {
    UNUSEDPARM(th_idx);
    UNUSEDPARM(target);

    size_t   off = 0;
    unsigned frames = 0;
    unsigned first_type = 0;
    bool     first_settings = false;

    while (off + 9 <= sizeof_px && frames < http2_conf.max_frames) {
        unsigned length = ((unsigned)px[off] << 16) |
                          ((unsigned)px[off + 1] << 8) | px[off + 2];
        unsigned type = px[off + 3];
        unsigned flags = px[off + 4];
        unsigned stream_id = (((unsigned)px[off + 5] & 0x7f) << 24) |
                             ((unsigned)px[off + 6] << 16) |
                             ((unsigned)px[off + 7] << 8) | px[off + 8];
        if (off + 9 + length > sizeof_px)
            break;

        if (frames == 0) {
            first_type = type;
            http2_frame_fields(item, "http2_frame", length, type, flags,
                               stream_id);
            if (type == 4 && http2_conf.record_settings && length > 0) {
                dach_append_bin(&item->probe_report, "http2_settings",
                                px + off + 9, length);
                first_settings = true;
            }
        }
        if (http2_conf.all_frames) {
            char prefix[24];
            snprintf(prefix, sizeof(prefix), "http2_f%u", frames + 1);
            http2_frame_fields(item, prefix, length, type, flags, stream_id);
        }
        if (type == 4 && length >= 6 && length % 6 == 0)
            http2_settings_fields(item, px + off + 9, length);

        off += 9 + length;
        frames++;
    }

    if (frames == 0) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not http/2");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "no complete frame");
        return 0;
    }

    dach_set_int(&item->probe_report, "http2_frame_count", frames);
    if (http2_conf.record_raw)
        dach_append_bin(&item->probe_report, "http2_raw", px, sizeof_px);

    if (first_type == 4 && first_settings)
        safe_strcpy(item->reason, OUT_RSN_SIZE, "settings");
    else if (first_type == 7)
        safe_strcpy(item->reason, OUT_RSN_SIZE, "goaway");
    else
        safe_strcpy(item->reason, OUT_RSN_SIZE, "frame");

    safe_strcpy(item->classification, OUT_CLS_SIZE, "http/2");
    item->level = OUT_SUCCESS;
    return 0;
}

Probe Http2Probe = {
    .name       = "http2",
    .type       = ProbeType_TCP,
    .slots      = {.count = 1, .trigger = ProbeSlot_None, .continue_cb = NULL},
    .params     = http2_parameters,
    .short_desc = "Send an HTTP/2 preface and parse server frames/settings.",
    .desc = "Send the HTTP/2 client preface plus a configurable SETTINGS frame "
            "and report server frame headers, SETTINGS entries and optionally "
            "raw frames. Use --settings-hex, --all-frames, --max-frames, "
            "--no-settings, --record-raw, --ping-hex and --no-ping. The "
            "default PING payload is an overt Xtate fingerprint, adjustable "
            "or disabled. This is a capability/framing probe, not a full "
            "HTTP/2 client.",
    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &http2_make_payload,
    .get_payload_length_cb = &http2_payload_length,
    .handle_response_cb    = &http2_handle,
    .close_cb              = &probe_close_nothing,
};
