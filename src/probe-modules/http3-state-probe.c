#ifdef HAVE_NGTCP2

/*
 * Minimal HTTP/3 probe on top of quic-state.
 *
 * It deliberately implements only a single request with static QPACK/literal
 * field names, no dynamic table, no push and no server-initiated streams.
 * This is the first application child of the QUIC transport; unsupported
 * QPACK/HTTP/3 features are reported as failures, not guessed.
 */

#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../scan-modules/quic-state-api.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

extern Probe Http3StateProbe;

#define H3_MAX_FRAME 65536
#define H3_MAX_BODY 4096

struct Http3State {
    char    *path;
    char    *authority;
    uint64_t request_stream;
    unsigned max_body;
    unsigned record_body : 1;
    int      status;
    unsigned header_count;
    unsigned body_len;
    unsigned reported : 1;
    unsigned failed : 1;
    unsigned qpack_partial : 1;
    unsigned char buf[H3_MAX_FRAME];
    size_t        buf_len;
    char          body[H3_MAX_BODY + 1];
};

static struct Http3Conf {
    char    *path;
    char    *authority;
    char    *method;
    unsigned max_body;
    unsigned record_body : 1;
} h3_conf = {.path = NULL, .authority = NULL, .method = NULL,
             .max_body = H3_MAX_BODY, .record_body = 1};

static ConfRes SET_h3_path(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || !*value || strlen(value) > 512) {
        LOG(LEVEL_ERROR, "http3 path must be 1..512 bytes\n");
        return Conf_ERR;
    }
    FREE(h3_conf.path);
    h3_conf.path = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_h3_authority(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (strlen(value) > 255) {
        LOG(LEVEL_ERROR, "http3 authority must be <= 255 bytes\n");
        return Conf_ERR;
    }
    FREE(h3_conf.authority);
    h3_conf.authority = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_h3_method(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!conf_equals(value, "GET")) {
        LOG(LEVEL_ERROR, "http3 method currently supports GET only\n");
        return Conf_ERR;
    }
    FREE(h3_conf.method);
    h3_conf.method = STRDUP("GET");
    return Conf_OK;
}

static ConfRes SET_h3_max_body(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = conf_parse_int(value);
    if (v < 1 || v > H3_MAX_BODY) {
        LOG(LEVEL_ERROR, "http3 max-body must be 1..%d\n", H3_MAX_BODY);
        return Conf_ERR;
    }
    h3_conf.max_body = v;
    return Conf_OK;
}

static ConfRes SET_h3_record_body(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    h3_conf.record_body = conf_parse_bool(value);
    return Conf_OK;
}

static ConfParam h3_parameters[] = {
    {"path", SET_h3_path, Type_ARG, {"url", 0},
     "HTTP/3 request :path. Default /."},
    {"authority", SET_h3_authority, Type_ARG, {"host", 0},
     "HTTP/3 request :authority. Default empty, which uses the target IP "
     "(IPv6 in brackets)."},
    {"method", SET_h3_method, Type_ARG, {"verb", 0},
     "HTTP/3 request method. Only GET is implemented in this milestone."},
    {"max-body", SET_h3_max_body, Type_ARG, {"body-limit", 0},
     "Maximum HTTP/3 DATA bytes to retain in the result; default 4096."},
    {"record-body", SET_h3_record_body, Type_FLAG, {"body", 0},
     "Include retained response body bytes in output; default on."},
    {0}};

static void h3_put_varint(unsigned char *p, size_t *off, uint64_t v) {
    if (v < 64) {
        p[(*off)++] = (unsigned char)v;
    } else if (v < 16384) {
        p[(*off)++] = (unsigned char)((v >> 8) | 0x40);
        p[(*off)++] = (unsigned char)v;
    } else if (v < 1073741824ULL) {
        p[(*off)++] = (unsigned char)((v >> 24) | 0x80);
        p[(*off)++] = (unsigned char)(v >> 16);
        p[(*off)++] = (unsigned char)(v >> 8);
        p[(*off)++] = (unsigned char)v;
    } else {
        p[(*off)++] = (unsigned char)((v >> 56) | 0xC0);
        p[(*off)++] = (unsigned char)(v >> 48);
        p[(*off)++] = (unsigned char)(v >> 40);
        p[(*off)++] = (unsigned char)(v >> 32);
        p[(*off)++] = (unsigned char)(v >> 24);
        p[(*off)++] = (unsigned char)(v >> 16);
        p[(*off)++] = (unsigned char)(v >> 8);
        p[(*off)++] = (unsigned char)v;
    }
}

static int h3_get_varint(const unsigned char *p, size_t len, size_t *off,
                         uint64_t *v) {
    if (*off >= len)
        return 0;
    unsigned first = p[(*off)++];
    unsigned prefix = first >> 6;
    unsigned bytes = 1u << prefix;
    uint64_t value = first & 0x3f;
    if (bytes - 1 > len - *off)
        return 0;
    for (unsigned i = 1; i < bytes; i++)
        value = (value << 8) | p[(*off)++];
    *v = value;
    return 1;
}

static void h3_put_literal_name(unsigned char *p, size_t *off, const char *name,
                                size_t name_len, const char *value,
                                size_t value_len) {
    /* Literal Field Line with Literal Name: 001 N H + 3-bit name length. */
    size_t n = name_len;
    p[(*off)++] = (unsigned char)(0x20 | (n < 7 ? n : 7));
    if (n >= 7) {
        n -= 7;
        while (n >= 128) {
            p[(*off)++] = (unsigned char)((n & 0x7f) | 0x80);
            n >>= 7;
        }
        p[(*off)++] = (unsigned char)n;
    }
    memcpy(p + *off, name, name_len);
    *off += name_len;

    /* String literal, 7-bit length, H=0. */
    size_t v = value_len;
    if (v < 127) {
        p[(*off)++] = (unsigned char)v;
    } else {
        p[(*off)++] = 127;
        v -= 127;
        while (v >= 128) {
            p[(*off)++] = (unsigned char)((v & 0x7f) | 0x80);
            v >>= 7;
        }
        p[(*off)++] = (unsigned char)v;
    }
    memcpy(p + *off, value, value_len);
    *off += value_len;
}

static const char *h3_static_name(int idx) {
    switch (idx) {
        case 0: return ":authority";
        case 1: return ":path";
        case 2: return "age";
        case 3: return "content-disposition";
        case 4: return "content-length";
        case 5: return "cookie";
        case 6: return "date";
        case 7: return "etag";
        case 8: return "if-modified-since";
        case 9: return "if-none-match";
        case 10: return "last-modified";
        case 11: return "link";
        case 12: return "location";
        case 13: return "referer";
        case 14: return "set-cookie";
        case 15: return ":method";
        case 16: return ":method";
        case 17: return ":method";
        case 18: return ":method";
        case 19: return ":method";
        case 20: return ":method";
        case 21: return ":method";
        case 22: return ":scheme";
        case 23: return ":scheme";
        case 24: return ":status";
        case 25: return ":status";
        case 26: return ":status";
        case 27: return ":status";
        case 28: return ":status";
        case 29: return "accept";
        case 30: return "accept";
        case 31: return "accept-encoding";
        case 32: return "accept-ranges";
        case 33: return "access-control-allow-headers";
        case 34: return "access-control-allow-headers";
        case 35: return "access-control-allow-origin";
        case 36: return "cache-control";
        case 37: return "cache-control";
        case 38: return "cache-control";
        case 39: return "cache-control";
        case 40: return "cache-control";
        case 41: return "cache-control";
        case 42: return "content-encoding";
        case 43: return "content-encoding";
        case 44: return "content-type";
        case 45: return "content-type";
        case 46: return "content-type";
        case 47: return "content-type";
        case 48: return "content-type";
        case 49: return "content-type";
        case 50: return "content-type";
        case 51: return "content-type";
        case 52: return "content-type";
        case 53: return "content-type";
        case 54: return "content-type";
        case 55: return "range";
        case 92: return "server";
        default: return "";
    }
}

static const char *h3_static_value(int idx) {
    switch (idx) {
        case 24: return "103";
        case 25: return "200";
        case 26: return "304";
        case 27: return "404";
        case 28: return "503";
        case 29: return "*/*";
        case 30: return "application/dns-message";
        case 31: return "gzip, deflate, br";
        case 32: return "bytes";
        case 33: return "cache-control";
        case 34: return "content-type";
        case 35: return "*";
        case 36: return "max-age=0";
        case 37: return "max-age=2592000";
        case 38: return "max-age=604800";
        case 39: return "no-cache";
        case 40: return "no-store";
        case 42: return "br";
        case 43: return "gzip";
        case 44: return "application/dns-message";
        case 45: return "application/javascript";
        case 46: return "application/json";
        case 47: return "application/x-www-form-urlencoded";
        case 48: return "image/gif";
        case 49: return "image/jpeg";
        case 50: return "image/png";
        case 51: return "text/css";
        case 52: return "text/html; charset=utf-8";
        case 53: return "text/plain";
        case 54: return "text/plain;charset=utf-8";
        default: return "";
    }
}

static int h3_get_prefixed(const unsigned char *p, size_t len, size_t *off,
                           unsigned prefix, uint64_t *v) {
    if (*off >= len)
        return 0;
    unsigned mask = (1u << prefix) - 1;
    unsigned first = p[(*off)++];
    uint64_t value = first & mask;
    if (value < mask) {
        *v = value;
        return 1;
    }
    unsigned shift = 0;
    while (*off < len) {
        unsigned b = p[(*off)++];
        value += (uint64_t)(b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) {
            *v = value;
            return 1;
        }
        if (shift > 56)
            return -1;
    }
    return 0;
}

static int h3_get_string(const unsigned char *p, size_t len, size_t *off,
                         const unsigned char **s, size_t *slen) {
    if (*off >= len)
        return 0;
    if (p[*off] & 0x80)
        return -1; /* Huffman is not implemented in this milestone. */
    uint64_t n;
    int rv = h3_get_prefixed(p, len, off, 7, &n);
    if (rv <= 0)
        return rv;
    if (n > len - *off)
        return 0;
    *s = p + *off;
    *slen = (size_t)n;
    *off += (size_t)n;
    return 1;
}

static int h3_qpack_headers(struct Http3State *h, const unsigned char *p,
                            size_t len) {
    size_t off = 0;
    uint64_t ric, base;
    if (h3_get_prefixed(p, len, &off, 8, &ric) <= 0 ||
        h3_get_prefixed(p, len, &off, 7, &base) <= 0)
        return -1;
    if (ric != 0)
        return -1; /* no dynamic table in this milestone */
    (void)base;

    while (off < len) {
        unsigned first = p[off];
        if (first & 0x80) {
            uint64_t idx;
            if (h3_get_prefixed(p, len, &off, 6, &idx) <= 0)
                return -1;
            if (!(first & 0x40)) /* T=0 dynamic */
                return -1;
            h->header_count++;
            if (strcmp(h3_static_name((int)idx), ":status") == 0)
                h->status = atoi(h3_static_value((int)idx));
            continue;
        }
        if ((first & 0xc0) == 0x40) {
            uint64_t idx;
            if (h3_get_prefixed(p, len, &off, 4, &idx) <= 0)
                return -1;
            if (!(first & 0x08)) /* T=0 dynamic */
                return -1;
            const unsigned char *v;
            size_t vlen;
            if (h3_get_string(p, len, &off, &v, &vlen) <= 0)
                return -1;
            h->header_count++;
            if (strcmp(h3_static_name((int)idx), ":status") == 0) {
                char tmp[16];
                size_t n = vlen < sizeof(tmp) - 1 ? vlen : sizeof(tmp) - 1;
                memcpy(tmp, v, n);
                tmp[n] = '\0';
                h->status = atoi(tmp);
            }
            continue;
        }
        if ((first & 0xe0) == 0x20) {
            if (first & 0x10) /* Huffman name unsupported */
                return -1;
            const unsigned char *name;
            size_t name_len;
            const unsigned char *value;
            size_t value_len;
            /* Skip the 3-bit name length prefix; read the string with the
             * remaining 3-bit prefix is not directly supported by
             * h3_get_string, so decode it explicitly. */
            uint64_t nlen;
            if (h3_get_prefixed(p, len, &off, 3, &nlen) <= 0)
                return -1;
            if (nlen > len - off)
                return -1;
            name = p + off;
            name_len = (size_t)nlen;
            off += name_len;
            if (h3_get_string(p, len, &off, &value, &value_len) <= 0)
                return -1;
            h->header_count++;
            if (name_len == 7 && memcmp(name, ":status", 7) == 0) {
                char tmp[16];
                size_t n = value_len < sizeof(tmp) - 1 ? value_len
                                                       : sizeof(tmp) - 1;
                memcpy(tmp, value, n);
                tmp[n] = '\0';
                h->status = atoi(tmp);
            }
            continue;
        }
        return -1; /* post-base/dynamic forms unsupported */
    }
    return 0;
}

static void h3_report(struct Http3State *h, OutItem *item) {
    if (!item || h->reported)
        return;
    h->reported = 1;
    item->no_output = 0;
    item->level = h->failed ? OUT_FAILURE : OUT_SUCCESS;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "http3");
    safe_strcpy(item->reason, OUT_RSN_SIZE,
                h->failed ? "http3 decode failed" : "http3 response");
    dach_set_int(&item->probe_report, "http3_status", h->status);
    dach_set_int(&item->probe_report, "http3_header_count", h->header_count);
    dach_set_int(&item->probe_report, "http3_body_len", h->body_len);
    if (h->qpack_partial)
        dach_set_int(&item->probe_report, "http3_qpack_partial", 1);
    if (h3_conf.record_body && h->body_len)
        dach_append_str(&item->probe_report, "http3_body", h->body,
                        h->body_len);
}

static void h3_parse_frames(struct Http3State *h, OutItem *item) {
    size_t off = 0;
    while (off < h->buf_len) {
        size_t save = off;
        uint64_t type, len;
        int rv = h3_get_varint(h->buf, h->buf_len, &off, &type);
        if (rv <= 0) {
            off = save;
            break;
        }
        rv = h3_get_varint(h->buf, h->buf_len, &off, &len);
        if (rv <= 0) {
            off = save;
            break;
        }
        if (len > h->buf_len - off) {
            off = save;
            break;
        }
        if (type == 0) { /* DATA */
            size_t n = (size_t)len;
            if (n > h3_conf.max_body - h->body_len)
                n = h3_conf.max_body - h->body_len;
            if (n) {
                memcpy(h->body + h->body_len, h->buf + off, n);
                h->body_len += (unsigned)n;
                h->body[h->body_len] = '\0';
            }
        } else if (type == 1) { /* HEADERS */
            if (h3_qpack_headers(h, h->buf + off, (size_t)len) != 0) {
                if (h->status || h->header_count)
                    h->qpack_partial = 1;
                else
                    h->failed = 1;
            }
        }
        off += (size_t)len;
    }
    if (off) {
        memmove(h->buf, h->buf + off, h->buf_len - off);
        h->buf_len -= off;
    }
}

static bool h3_init_fail(ProbeState *state) {
    struct Http3State *h = state->data;
    if (h) {
        FREE(h->path);
        FREE(h);
        state->data = NULL;
    }
    return false;
}

static bool h3_conn_init(ProbeState *state, ProbeTarget *target) {
    struct Http3State *h = CALLOC(1, sizeof(*h));
    if (!h)
        return h3_init_fail(state);
    state->data = h;
    h->path = STRDUP(h3_conf.path ? h3_conf.path : "/");
    if (!h->path)
        return h3_init_fail(state);
    h->max_body = h3_conf.max_body;
    h->record_body = h3_conf.record_body;

    uint64_t id;
    unsigned char tmp[1024];
    size_t off = 0;
    /* SETTINGS frame on the client control stream. */
    tmp[off++] = 0x04; /* frame type SETTINGS */
    tmp[off++] = 0x00; /* length 0 */
    if (!quic_state_open_uni(state, 0x00, &id) ||
        !quic_state_send_stream(state, id, tmp, off, false)) {
        return h3_init_fail(state);
    }
    if (!quic_state_open_uni(state, 0x02, &id)) { /* QPACK encoder */
        return h3_init_fail(state);
    }
    if (!quic_state_open_uni(state, 0x03, &id)) { /* QPACK decoder */
        return h3_init_fail(state);
    }
    if (!quic_state_open_bidi(state, &h->request_stream)) {
        return h3_init_fail(state);
    }

    char authority[300];
    if (h3_conf.authority && *h3_conf.authority) {
        snprintf(authority, sizeof(authority), "%s", h3_conf.authority);
    } else if (target->target.ip_them.version == 6) {
        snprintf(authority, sizeof(authority), "[%s]",
                 ipaddress_fmt(target->target.ip_them).string);
    } else {
        snprintf(authority, sizeof(authority), "%s",
                 ipaddress_fmt(target->target.ip_them).string);
    }

    unsigned char block[1024];
    size_t boff = 0;
    block[boff++] = 0x00; /* Required Insert Count = 0 */
    block[boff++] = 0x00; /* Delta Base = 0 */
    static const char *method = "GET";
    h3_put_literal_name(block, &boff, ":method", 7, method, strlen(method));
    h3_put_literal_name(block, &boff, ":scheme", 7, "https", 5);
    h3_put_literal_name(block, &boff, ":authority", 10, authority,
                        strlen(authority));
    h3_put_literal_name(block, &boff, ":path", 5, h->path, strlen(h->path));

    unsigned char frame[1100];
    size_t foff = 0;
    h3_put_varint(frame, &foff, 0x01); /* HEADERS */
    h3_put_varint(frame, &foff, boff);
    memcpy(frame + foff, block, boff);
    foff += boff;
    if (!quic_state_send_stream(state, h->request_stream, frame, foff, true)) {
        return h3_init_fail(state);
    }
    return true;
}

static void h3_make_hello(DataPass *pass, ProbeState *state,
                          ProbeTarget *target) {
    (void)pass;
    (void)state;
    (void)target;
}

static unsigned h3_parse_response(DataPass *pass, ProbeState *state,
                                  OutConf *out, ProbeTarget *target,
                                  const unsigned char *px,
                                  unsigned sizeof_px) {
    (void)pass;
    (void)state;
    (void)out;
    (void)target;
    (void)px;
    (void)sizeof_px;
    return 0;
}

static unsigned h3_stream_data(ProbeState *state, OutConf *out,
                               ProbeTarget *target, uint64_t stream_id,
                               const unsigned char *px, unsigned sizeof_px,
                               unsigned fin, OutItem *item) {
    (void)out;
    (void)target;
    struct Http3State *h = state->data;
    if (!h || stream_id != h->request_stream)
        return 0;
    size_t n = sizeof_px;
    if (n > sizeof(h->buf) - h->buf_len)
        n = sizeof(h->buf) - h->buf_len;
    if (n)
        memcpy(h->buf + h->buf_len, px, n);
    h->buf_len += n;
    h3_parse_frames(h, item);
    if (fin || h->buf_len == sizeof(h->buf)) {
        if (h->buf_len)
            h->failed = 1;
        h3_report(h, item);
    }
    return 0;
}

static void h3_conn_close(ProbeState *state, ProbeTarget *target) {
    (void)target;
    struct Http3State *h = state->data;
    if (h) {
        FREE(h->path);
        FREE(h->authority);
        FREE(h);
        state->data = NULL;
    }
}

Probe Http3StateProbe = {
    .name       = "http3-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .params     = h3_parameters,
    .short_desc = "Minimal HTTP/3 GET over a quic-state connection.",
    .desc =
        "Http3StateProbe sends one HTTP/3 GET on the QUIC stream opened by the "
        "quic-state transport. It implements the client control/QPACK streams, "
        "static QPACK field names and one request stream, then reports "
        "status/header count/body. Dynamic QPACK, push, server-initiated "
        "streams, HTTP/3 CONNECT and Huffman-encoded literals are intentionally "
        "unsupported in this first milestone. Use it only with `-scan "
        "quic-state`.",
    .init_cb           = &probe_init_nothing,
    .conn_init_cb      = &h3_conn_init,
    .make_hello_cb     = &h3_make_hello,
    .parse_response_cb = &h3_parse_response,
    .stream_data_cb    = &h3_stream_data,
    .conn_close_cb     = &h3_conn_close,
    .close_cb          = &probe_close_nothing,
};

#endif /* HAVE_NGTCP2 */
