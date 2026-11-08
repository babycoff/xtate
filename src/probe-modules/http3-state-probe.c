#ifdef HAVE_NGTCP2

/*
 * Minimal but strict HTTP/3 GET/POST probe on top of quic-state.
 *
 * Scope of this milestone: client control/QPACK streams, static/literal
 * QPACK field names (including Huffman string literals), full QPACK static
 * table, one request stream, response header extraction and a bounded body.
 * Dynamic QPACK, push, server-initiated streams, HTTP/3 CONNECT and WebTransport
 * remain unsupported and are reported explicitly.
 */

#include "probe-modules.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "../scan-modules/quic-state-api.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"
#include "../proto/proto-match.h"
#include "http3-qpack-tables.h"

extern Probe Http3StateProbe;

#define H3_MAX_FRAME 65536
#define H3_MAX_BODY 65536
#define H3_MAX_HEADERS 32
#define H3_MAX_HEADER_NAME 128
#define H3_MAX_HEADER_VALUE 1024
#define H3_MAX_REQUEST_HEADER 8192
#define H3_MAX_DATA 65536

struct H3Header {
    char name[H3_MAX_HEADER_NAME];
    char value[H3_MAX_HEADER_VALUE];
};

struct H3RequestHeader {
    struct H3RequestHeader *next;
    char name[H3_MAX_HEADER_NAME];
    char value[H3_MAX_HEADER_VALUE];
};

struct Http3State {
    char     *path;
    uint64_t  request_stream;
    unsigned  max_body;
    unsigned  max_headers;
    unsigned  record_body : 1;
    unsigned  record_headers : 1;
    unsigned  reported : 1;
    unsigned  failed : 1;
    unsigned  qpack_partial : 1;
    unsigned  body_truncated : 1;
    int       status;
    unsigned  header_count;
    unsigned  stored_headers;
    unsigned  body_len;
    unsigned  body_total;
    struct H3Header headers[H3_MAX_HEADERS];
    unsigned char  *buf;
    size_t          buf_len;
    char           *body;
};

static struct Http3Conf {
    char    *path;
    char    *authority;
    char    *method;
    char    *content_type;
    char    *data;
    size_t   data_len;
    char    *data_file;
    unsigned max_body;
    unsigned max_headers;
    unsigned record_body : 1;
    unsigned record_headers : 1;
    MatchSpec match;
    struct H3RequestHeader *headers;
} h3_conf = {.path = NULL, .authority = NULL, .method = NULL,
             .content_type = NULL, .data = NULL, .data_file = NULL,
             .max_body = 4096, .max_headers = 16, .record_body = 1,
             .record_headers = 1, .headers = NULL};

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
    static const char *allowed[] = {"GET", "HEAD", "POST", "PUT",
                                    "PATCH", "DELETE", "OPTIONS", NULL};
    bool ok = false;
    for (unsigned i = 0; allowed[i]; i++) {
        if (conf_equals(value, allowed[i])) {
            ok = true;
            break;
        }
    }
    if (!ok) {
        LOG(LEVEL_ERROR, "http3 method must be GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS\n");
        return Conf_ERR;
    }
    char upper[16];
    size_t n = strlen(value);
    if (n >= sizeof(upper))
        return Conf_ERR;
    for (size_t i = 0; i <= n; i++)
        upper[i] = (char)toupper((unsigned char)value[i]);
    FREE(h3_conf.method);
    h3_conf.method = STRDUP(upper);
    return Conf_OK;
}

static ConfRes SET_h3_content_type(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (strlen(value) > H3_MAX_HEADER_VALUE - 1) {
        LOG(LEVEL_ERROR, "http3 content-type is too long\n");
        return Conf_ERR;
    }
    FREE(h3_conf.content_type);
    h3_conf.content_type = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_h3_data(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (strlen(value) > H3_MAX_DATA) {
        LOG(LEVEL_ERROR, "http3 data is longer than %d bytes\n", H3_MAX_DATA);
        return Conf_ERR;
    }
    FREE(h3_conf.data);
    h3_conf.data = STRDUP(value);
    h3_conf.data_len = h3_conf.data ? strlen(h3_conf.data) : 0;
    return Conf_OK;
}

static ConfRes SET_h3_data_file(void *conf, const char *name,
                                const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || !*value || strlen(value) > 1024) {
        LOG(LEVEL_ERROR, "http3 data-file must be 1..1024 bytes\n");
        return Conf_ERR;
    }
    FREE(h3_conf.data_file);
    h3_conf.data_file = STRDUP(value);
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

static ConfRes SET_h3_max_headers(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    unsigned v = conf_parse_int(value);
    if (v < 1 || v > H3_MAX_HEADERS) {
        LOG(LEVEL_ERROR, "http3 max-headers must be 1..%d\n", H3_MAX_HEADERS);
        return Conf_ERR;
    }
    h3_conf.max_headers = v;
    return Conf_OK;
}

static ConfRes SET_h3_record_body(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    h3_conf.record_body = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_h3_record_headers(void *conf, const char *name,
                                     const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    h3_conf.record_headers = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_h3_header(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    const char *colon = strchr(value, ':');
    if (!colon || colon == value) {
        LOG(LEVEL_ERROR, "http3 header must be 'name: value'\n");
        return Conf_ERR;
    }
    size_t nlen = (size_t)(colon - value);
    const char *v = colon + 1;
    while (*v == ' ' || *v == '\t')
        v++;
    size_t vlen = strlen(v);
    if (nlen == 0 || nlen >= H3_MAX_HEADER_NAME ||
        vlen >= H3_MAX_HEADER_VALUE)
        return Conf_ERR;
    struct H3RequestHeader *h = CALLOC(1, sizeof(*h));
    if (!h)
        return Conf_ERR;
    memcpy(h->name, value, nlen);
    h->name[nlen] = '\0';
    memcpy(h->value, v, vlen);
    h->value[vlen] = '\0';
    h->next = h3_conf.headers;
    h3_conf.headers = h;
    return Conf_OK;
}

static ConfRes SET_keyword(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    return match_spec_set_keyword(&h3_conf.match, value) ? Conf_OK : Conf_ERR;
}

#ifndef NOT_FOUND_PCRE2
static ConfRes SET_regex(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    return match_spec_set_regex(&h3_conf.match, value) ? Conf_OK : Conf_ERR;
}
#endif

static ConfRes SET_scope(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    return match_spec_set_scope(&h3_conf.match, value) ? Conf_OK : Conf_ERR;
}

static ConfRes SET_insensitive(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    match_spec_set_case_insensitive(&h3_conf.match, conf_parse_bool(value));
    return Conf_OK;
}

static ConfRes SET_newlines(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    match_spec_set_include_newlines(&h3_conf.match, conf_parse_bool(value));
    return Conf_OK;
}

static ConfParam h3_parameters[] = {
    {"path", SET_h3_path, Type_ARG, {"url", 0},
     "HTTP/3 request :path. Default /."},
    {"authority", SET_h3_authority, Type_ARG, {"host", 0},
     "HTTP/3 request :authority. Default empty, which uses the target IP "
     "(IPv6 in brackets)."},
    {"method", SET_h3_method, Type_ARG, {"verb", 0},
     "HTTP/3 request method: GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS. "
     "Default GET."},
    {"header", SET_h3_header, Type_ARG, {"req-header", 0},
     "Additional HTTP/3 request header, repeatable, in 'name: value' form. "
     "Pseudo-headers are not added through this option."},
    {"content-type", SET_h3_content_type, Type_ARG, {"ctype", 0},
     "Value of the request content-type header."},
    {"data", SET_h3_data, Type_ARG, {"body", 0},
     "Inline request body, up to 65536 bytes. Only valid for methods that "
     "accept a body."},
    {"data-file", SET_h3_data_file, Type_ARG, {"body-file", 0},
     "Read request body from this file (up to 65536 bytes)."},
    {"max-body", SET_h3_max_body, Type_ARG, {"body-limit", 0},
     "Maximum HTTP/3 DATA bytes retained in the result; default 4096."},
    {"max-headers", SET_h3_max_headers, Type_ARG, {"header-limit", 0},
     "Maximum response headers retained in structured fields (1..32); "
     "default 16. The total header count is always reported."},
    {"record-body", SET_h3_record_body, Type_FLAG, {"body", 0},
     "Include retained response body bytes in output; default on."},
    {"record-headers", SET_h3_record_headers, Type_FLAG, {"headers", 0},
     "Emit structured response header fields; default on."},
    {"keyword", SET_keyword, Type_ARG, {0},
     "Literal keyword to search in the selected response scope. Mutually "
     "exclusive with --regex."},
#ifndef NOT_FOUND_PCRE2
    {"regex", SET_regex, Type_ARG, {0},
     "PCRE2 regex to search in the selected response scope. Mutually exclusive "
     "with --keyword."},
#endif
    {"match-scope", SET_scope, Type_ARG, {"scope", 0},
     "Where to match: all, headers or body. Default all."},
    {"case-insensitive", SET_insensitive, Type_FLAG, {"insensitive", 0},
     "Case-insensitive keyword/regex matching."},
    {"include-newlines", SET_newlines, Type_FLAG,
     {"include-newline", "newline", "newlines", 0},
     "Let PCRE2 dot match newlines (DOTALL)."},
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

static int h3_huffman_decode(const unsigned char *src, size_t srclen,
                             char *dst, size_t dstcap) {
    uint64_t acc = 0;
    unsigned bits = 0;
    size_t   si = 0, di = 0;

    for (;;) {
        while (bits < 32 && si < srclen) {
            acc = (acc << 8) | src[si++];
            bits += 8;
        }
        if (bits == 0)
            break;

        int      found = -1;
        unsigned flen = 0;
        for (unsigned sym = 0; sym < 257; sym++) {
            unsigned len = h3_huff_len[sym];
            if (len <= bits) {
                uint64_t mask = (1ULL << len) - 1;
                if (((acc >> (bits - len)) & mask) == h3_huff_code[sym]) {
                    found = (int)sym;
                    flen = len;
                    break;
                }
            }
        }
        if (found < 0) {
            if (si >= srclen && bits <= 7 &&
                (acc & ((1ULL << bits) - 1)) == ((1ULL << bits) - 1))
                break; /* valid all-ones padding */
            return -1;
        }
        if (found == 256) /* EOS is illegal in a string */
            return -1;
        if (di + 1 >= dstcap)
            return -1;
        dst[di++] = (char)found;
        bits -= flen;
        if (bits == 0 && si == srclen)
            break;
    }
    if (di >= dstcap)
        return -1;
    dst[di] = '\0';
    return (int)di;
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
                         char *out, size_t outcap) {
    if (*off >= len)
        return 0;
    unsigned huff = p[*off] & 0x80;
    uint64_t n;
    int rv = h3_get_prefixed(p, len, off, 7, &n);
    if (rv <= 0)
        return rv;
    if (n > len - *off)
        return 0;
    if (huff) {
        int d = h3_huffman_decode(p + *off, (size_t)n, out, outcap);
        if (d < 0)
            return -1;
    } else {
        if (n >= outcap)
            return -1;
        memcpy(out, p + *off, (size_t)n);
        out[n] = '\0';
    }
    *off += (size_t)n;
    return 1;
}

static void h3_add_header(struct Http3State *h, const char *name,
                          const char *value) {
    if (strcmp(name, ":status") == 0)
        h->status = atoi(value);
    h->header_count++;
    if (h->stored_headers >= h->max_headers)
        return;
    struct H3Header *dst = &h->headers[h->stored_headers++];
    snprintf(dst->name, sizeof(dst->name), "%s", name);
    snprintf(dst->value, sizeof(dst->value), "%s", value);
}

static int h3_qpack_headers(struct Http3State *h, const unsigned char *p,
                            size_t len) {
    size_t off = 0;
    uint64_t ric, base;
    if (h3_get_prefixed(p, len, &off, 8, &ric) <= 0 ||
        h3_get_prefixed(p, len, &off, 7, &base) <= 0)
        return -1;
    if (ric != 0)
        return -1; /* dynamic table is intentionally not enabled */
    (void)base;

    char name[H3_MAX_HEADER_NAME];
    char value[H3_MAX_HEADER_VALUE];

    while (off < len) {
        unsigned first = p[off];
        if (first & 0x80) { /* indexed field line */
            uint64_t idx;
            if (h3_get_prefixed(p, len, &off, 6, &idx) <= 0)
                return -1;
            if (!(first & 0x40) || idx >= 99)
                return -1;
            h3_add_header(h, h3_static_name[idx], h3_static_value[idx]);
            continue;
        }
        if ((first & 0xc0) == 0x40) { /* literal name reference */
            uint64_t idx;
            if (h3_get_prefixed(p, len, &off, 4, &idx) <= 0)
                return -1;
            if (!(first & 0x08) || idx >= 99)
                return -1;
            int rv = h3_get_string(p, len, &off, value, sizeof(value));
            if (rv <= 0)
                return rv < 0 ? -1 : 0;
            h3_add_header(h, h3_static_name[idx], value);
            continue;
        }
        if ((first & 0xe0) == 0x20) { /* literal name */
            uint64_t nlen;
            if (h3_get_prefixed(p, len, &off, 3, &nlen) <= 0)
                return -1;
            if (nlen >= sizeof(name) || nlen > len - off)
                return -1;
            if (first & 0x08) { /* QPACK literal-name H bit; N is 0x10 */
                int d = h3_huffman_decode(p + off, (size_t)nlen, name,
                                          sizeof(name));
                if (d < 0)
                    return -1;
            } else {
                memcpy(name, p + off, (size_t)nlen);
                name[nlen] = '\0';
            }
            off += (size_t)nlen;
            int rv = h3_get_string(p, len, &off, value, sizeof(value));
            if (rv <= 0)
                return rv < 0 ? -1 : 0;
            h3_add_header(h, name, value);
            continue;
        }
        return -1; /* post-base/dynamic forms */
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
    dach_set_int(&item->probe_report, "http3_body_total", h->body_total);
    if (h->body_truncated)
        dach_set_int(&item->probe_report, "http3_body_truncated", 1);
    if (h->qpack_partial)
        dach_set_int(&item->probe_report, "http3_qpack_partial", 1);
    if (h3_conf.match.configured) {
        size_t hlen = 0;
        for (unsigned i = 0; i < h->stored_headers; i++)
            hlen += strlen(h->headers[i].name) + strlen(h->headers[i].value) + 4;
        hlen += 2;
        size_t all_len = hlen + h->body_len;
        char  *headers = MALLOC(hlen + 1);
        char  *all = MALLOC(all_len + 1);
        if (headers && all) {
            size_t off = 0;
            for (unsigned i = 0; i < h->stored_headers; i++) {
                int n = snprintf(headers + off, hlen + 1 - off, "%s: %s\r\n",
                                 h->headers[i].name, h->headers[i].value);
                if (n > 0)
                    off += (size_t)n;
            }
            headers[off] = '\0';
            memcpy(all, headers, off);
            all[off] = '\r';
            all[off + 1] = '\n';
            memcpy(all + off + 2, h->body, h->body_len);
            size_t alen = off + 2 + h->body_len;
            MatchResult mr;
            match_spec_apply(&h3_conf.match, all, alen, headers, off, h->body,
                             h->body_len, &mr);
            dach_set_int(&item->probe_report, "http3_match", mr.matched ? 1 : 0);
            dach_append_str(&item->probe_report, "http3_match_kind", mr.kind,
                            strlen(mr.kind));
            dach_append_str(&item->probe_report, "http3_match_scope",
                            match_scope_name(mr.scope),
                            strlen(match_scope_name(mr.scope)));
            if (mr.text[0])
                dach_append_str(&item->probe_report, "http3_match_text", mr.text,
                                strlen(mr.text));
            if (!mr.matched) {
                item->level = OUT_FAILURE;
                safe_strcpy(item->classification, OUT_CLS_SIZE, "not matched");
                safe_strcpy(item->reason, OUT_RSN_SIZE, "no match");
            } else {
                item->level = OUT_SUCCESS;
                safe_strcpy(item->classification, OUT_CLS_SIZE, "matched");
            }
        }
        FREE(headers);
        FREE(all);
    }
    if (h3_conf.record_body && h->body_len)
        dach_append_str(&item->probe_report, "http3_body", h->body, h->body_len);

    if (h3_conf.record_headers) {
        for (unsigned i = 0; i < h->stored_headers; i++) {
            char key[40];
            snprintf(key, sizeof(key), "http3_header_%u_name", i + 1);
            dach_append_str(&item->probe_report, key, h->headers[i].name,
                            strlen(h->headers[i].name));
            snprintf(key, sizeof(key), "http3_header_%u_value", i + 1);
            dach_append_str(&item->probe_report, key, h->headers[i].value,
                            strlen(h->headers[i].value));
            if (strcmp(h->headers[i].name, "content-type") == 0)
                dach_append_str(&item->probe_report, "http3_content_type",
                                h->headers[i].value,
                                strlen(h->headers[i].value));
            if (strcmp(h->headers[i].name, "server") == 0)
                dach_append_str(&item->probe_report, "http3_server",
                                h->headers[i].value,
                                strlen(h->headers[i].value));
            if (strcmp(h->headers[i].name, "location") == 0)
                dach_append_str(&item->probe_report, "http3_location",
                                h->headers[i].value,
                                strlen(h->headers[i].value));
        }
    }
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
            h->body_total += (unsigned)n;
            if (n > h->max_body - h->body_len) {
                n = h->max_body - h->body_len;
                h->body_truncated = 1;
            }
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

static int h3_huffman_selftest(void) {
    static const unsigned char vec[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2,
                                        0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    char out[32];
    int  n = h3_huffman_decode(vec, sizeof(vec), out, sizeof(out));
    return n == 15 && strcmp(out, "www.example.com") == 0;
}

static int h3_frame_selftest(void) {
    /*
     * Decrypted HTTP/3 frame fixture:
     *   HEADERS type=1, length=3, QPACK RIC=0/base=0, indexed static :status 200
     *   DATA type=0, length=5, "hello"
     * This exercises frame parsing, QPACK static lookup and body accumulation
     * without a QUIC/TLS handshake.
     */
    static const unsigned char frames[] = {
        0x01, 0x03, 0x00, 0x00, 0xd9,
        0x00, 0x05, 'h', 'e', 'l', 'l', 'o',
    };
    unsigned char body[16] = {0};
    struct Http3State h = {0};
    OutItem item = {0};

    h.buf = (unsigned char *)frames;
    h.buf_len = sizeof(frames);
    h.body = (char *)body;
    h.max_body = sizeof(body) - 1;
    h.max_headers = 4;
    h.record_body = 1;
    h.record_headers = 1;
    h3_parse_frames(&h, &item);

    if (h.status != 200 || h.header_count != 1 || h.body_len != 5 ||
        memcmp(h.body, "hello", 5) != 0) {
        LOG(LEVEL_ERROR,
            "http3: decrypted frame fixture failed (status=%d headers=%u "
            "body=%u)\n",
            h.status, h.header_count, h.body_len);
        return 1;
    }

    /*
     * QPACK literal-name/literal-value Huffman fixture:
     *   HEADERS: QPACK block 0000 d9 2e f2 b1 7c a6 c1 ff 84 ee 3a 2d 2f
     *   d9 -> static :status 200
     *   2e -> literal name, Huffman name (x-extra), Huffman value "value"
     * This vector is produced by aioquic/pylsqpack and locks the H-bit (0x08)
     * and Huffman-literal decode path.
     */
    static const unsigned char huff_frames[] = {
        0x01, 0x0f, 0x00, 0x00, 0xd9, 0x2e, 0xf2, 0xb1, 0x7c,
        0xa6, 0xc1, 0xff, 0x84, 0xee, 0x3a, 0x2d, 0x2f,
    };
    unsigned char huff_body[8] = {0};
    struct Http3State hh = {0};
    OutItem huff_item = {0};
    hh.buf = (unsigned char *)huff_frames;
    hh.buf_len = sizeof(huff_frames);
    hh.body = (char *)huff_body;
    hh.max_body = sizeof(huff_body) - 1;
    hh.max_headers = 4;
    h3_parse_frames(&hh, &huff_item);
    bool found_extra = false;
    for (unsigned i = 0; i < hh.stored_headers; i++)
        if (strcmp(hh.headers[i].name, "x-extra") == 0 &&
            strcmp(hh.headers[i].value, "value") == 0)
            found_extra = true;
    if (hh.status != 200 || hh.header_count != 2 || !found_extra) {
        LOG(LEVEL_ERROR,
            "http3: QPACK Huffman frame fixture failed (status=%d headers=%u "
            "extra=%d)\n",
            hh.status, hh.header_count, (int)found_extra);
        return 1;
    }
    return 0;
}

static bool h3_init(const struct XtateConf *xconf) {
    UNUSEDPARM(xconf);
    if (!h3_huffman_selftest()) {
        LOG(LEVEL_ERROR, "http3: HPACK Huffman self-test failed\n");
        return false;
    }
    if (h3_frame_selftest() != 0)
        return false;
    if (!h3_conf.method)
        h3_conf.method = STRDUP("GET");
    if (!h3_conf.path)
        h3_conf.path = STRDUP("/");
    if (!h3_conf.method || !h3_conf.path)
        return false;
    if (h3_conf.data && h3_conf.data_file) {
        LOG(LEVEL_ERROR, "http3: --data and --data-file are mutually exclusive\n");
        return false;
    }
    if (!match_spec_finalize(&h3_conf.match))
        return false;
    if (h3_conf.data_file) {
        FILE *fp = fopen(h3_conf.data_file, "rb");
        if (!fp) {
            LOGPERROR("http3 data-file");
            return false;
        }
        FREE(h3_conf.data);
        h3_conf.data = MALLOC(H3_MAX_DATA + 2);
        if (!h3_conf.data) {
            fclose(fp);
            return false;
        }
        size_t n = fread(h3_conf.data, 1, H3_MAX_DATA + 1, fp);
        if (n > H3_MAX_DATA) {
            LOG(LEVEL_ERROR, "http3 data-file is larger than %d bytes\n",
                H3_MAX_DATA);
            fclose(fp);
            return false;
        }
        h3_conf.data[n] = '\0';
        h3_conf.data_len = n;
        fclose(fp);
    }
    bool has_body = h3_conf.data && h3_conf.data_len;
    if (has_body && (conf_equals(h3_conf.method, "GET") ||
                     conf_equals(h3_conf.method, "HEAD") ||
                     conf_equals(h3_conf.method, "DELETE") ||
                     conf_equals(h3_conf.method, "OPTIONS"))) {
        LOG(LEVEL_ERROR, "http3: request body requires POST/PUT/PATCH\n");
        return false;
    }
    return true;
}

static bool h3_init_fail(ProbeState *state) {
    struct Http3State *h = state->data;
    if (h) {
        FREE(h->path);
        FREE(h->buf);
        FREE(h->body);
        FREE(h);
        state->data = NULL;
    }
    return false;
}

static bool h3_conn_init(ProbeState *state, ProbeTarget *target) {
    struct Http3State *h = CALLOC(1, sizeof(*h));
    if (!h)
        return false;
    state->data = h;
    h->path = STRDUP(h3_conf.path ? h3_conf.path : "/");
    h->max_body = h3_conf.max_body;
    h->max_headers = h3_conf.max_headers;
    h->record_body = h3_conf.record_body;
    h->record_headers = h3_conf.record_headers;
    h->buf = MALLOC(H3_MAX_FRAME);
    h->body = MALLOC(h->max_body + 1);
    if (!h->path || !h->buf || !h->body)
        return h3_init_fail(state);

    uint64_t id;
    unsigned char tmp[16];
    size_t off = 0;
    tmp[off++] = 0x04; /* SETTINGS frame */
    tmp[off++] = 0x00; /* zero length */
    if (!quic_state_open_uni(state, 0x00, &id) ||
        !quic_state_send_stream(state, id, tmp, off, false))
        return h3_init_fail(state);
    if (!quic_state_open_uni(state, 0x02, &id))
        return h3_init_fail(state);
    if (!quic_state_open_uni(state, 0x03, &id))
        return h3_init_fail(state);
    if (!quic_state_open_bidi(state, &h->request_stream))
        return h3_init_fail(state);

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

    const char *method = h3_conf.method ? h3_conf.method : "GET";
    const char *body = h3_conf.data ? h3_conf.data : "";
    size_t body_len = h3_conf.data_len;
    char content_length[32];
    snprintf(content_length, sizeof(content_length), "%zu", body_len);

    unsigned char block[H3_MAX_REQUEST_HEADER];
    size_t boff = 0;
    block[boff++] = 0x00; /* Required Insert Count = 0 */
    block[boff++] = 0x00; /* Delta Base = 0 */
    h3_put_literal_name(block, &boff, ":method", 7, method, strlen(method));
    h3_put_literal_name(block, &boff, ":scheme", 7, "https", 5);
    h3_put_literal_name(block, &boff, ":authority", 10, authority,
                        strlen(authority));
    h3_put_literal_name(block, &boff, ":path", 5, h->path, strlen(h->path));
    if (body_len)
        h3_put_literal_name(block, &boff, "content-length", 14, content_length,
                            strlen(content_length));
    if (h3_conf.content_type && *h3_conf.content_type)
        h3_put_literal_name(block, &boff, "content-type", 12,
                            h3_conf.content_type,
                            strlen(h3_conf.content_type));
    for (struct H3RequestHeader *rh = h3_conf.headers; rh; rh = rh->next) {
        if (boff + strlen(rh->name) + strlen(rh->value) + 16 >
            sizeof(block))
            return h3_init_fail(state);
        h3_put_literal_name(block, &boff, rh->name, strlen(rh->name),
                            rh->value, strlen(rh->value));
    }

    unsigned char frame[H3_MAX_REQUEST_HEADER + 16];
    size_t foff = 0;
    h3_put_varint(frame, &foff, 0x01); /* HEADERS */
    h3_put_varint(frame, &foff, boff);
    memcpy(frame + foff, block, boff);
    foff += boff;
    if (!quic_state_send_stream(state, h->request_stream, frame, foff,
                                body_len == 0))
        return h3_init_fail(state);

    if (body_len) {
        unsigned char dframe[H3_MAX_DATA + 16];
        size_t doff = 0;
        h3_put_varint(dframe, &doff, 0x00); /* DATA */
        h3_put_varint(dframe, &doff, body_len);
        memcpy(dframe + doff, body, body_len);
        doff += body_len;
        if (!quic_state_send_stream(state, h->request_stream, dframe, doff,
                                    true))
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
    if (sizeof_px > H3_MAX_FRAME - h->buf_len) {
        h->failed = 1;
        h->buf_len = H3_MAX_FRAME;
    } else {
        memcpy(h->buf + h->buf_len, px, sizeof_px);
        h->buf_len += sizeof_px;
    }
    h3_parse_frames(h, item);
    if (fin) {
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
        FREE(h->buf);
        FREE(h->body);
        FREE(h);
        state->data = NULL;
    }
}

static void h3_close(void) {
    FREE(h3_conf.path);
    FREE(h3_conf.authority);
    FREE(h3_conf.method);
    FREE(h3_conf.content_type);
    FREE(h3_conf.data);
    FREE(h3_conf.data_file);
    while (h3_conf.headers) {
        struct H3RequestHeader *n = h3_conf.headers->next;
        FREE(h3_conf.headers);
        h3_conf.headers = n;
    }
    match_spec_free(&h3_conf.match);
}

#ifndef HTTP3_FUZZ
Probe Http3StateProbe = {
    .name       = "http3-state",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .params     = h3_parameters,
    .short_desc = "HTTP/3 request over quic-state with Huffman QPACK headers.",
    .desc =
        "Http3StateProbe sends one HTTP/3 request on the QUIC stream opened by "
        "quic-state. It implements client control/QPACK streams, static/literal "
        "QPACK field names including Huffman literals, the full QPACK static "
        "table, configurable methods/headers/body, bounded response "
        "HEADERS/DATA parsing with structured header output, and "
        "--keyword/--regex matching over all/headers/body. Dynamic QPACK, "
        "push, server-initiated streams, HTTP/3 CONNECT and WebTransport are "
        "not supported in this milestone. Use it only with `-scan quic-state`.",
    .init_cb           = &h3_init,
    .conn_init_cb      = &h3_conn_init,
    .make_hello_cb     = &h3_make_hello,
    .parse_response_cb = &h3_parse_response,
    .stream_data_cb    = &h3_stream_data,
    .conn_close_cb     = &h3_conn_close,
    .close_cb          = &h3_close,
};
#endif /* HTTP3_FUZZ */

#endif /* HAVE_NGTCP2 */
