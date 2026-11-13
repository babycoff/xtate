#include "probe-modules.h"

#include <stdio.h>
#include <string.h>

#include "../output-modules/output-modules.h"
#include "../target/target-ipaddress.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"
#include "../proto/proto-match.h"
#include "../proto/proto-dns.h"
#include "../proto/hpack-huffman.h"
#include "../version.h"

#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_PREFACE_LEN 24
#define H2_BUF_MAX (64 * 1024)
#define H2_SETTINGS_MAX 256

struct H2Conf {
    char     path[256];
    char     authority[256];
    char     user_agent[256];
    unsigned char settings[H2_SETTINGS_MAX];
    size_t        settings_len;
    unsigned      no_user_agent : 1;
    unsigned      record_raw    : 1;
    unsigned      decode_headers : 1;
    unsigned      max_frames;
    unsigned      max_data;
    unsigned      doh : 1;
    char          dns_name[256];
    dns_record_type dns_type;
    unsigned      dnssec : 1;
    MatchSpec     match;
};

static struct H2Conf h2_conf = {
    .path = "/",
    .authority = "",
    .user_agent = XTATE_WITH_VERSION,
    .settings_len = 0,
    .no_user_agent = 0,
    .record_raw = 0,
    .decode_headers = 1,
    .max_frames = 16,
    .max_data = 4096,
};

struct H2State {
    unsigned char *rx;
    size_t         rx_len;
    size_t         rx_cap;
    unsigned       frames;
    unsigned       settings_count;
    unsigned       header_count;
    unsigned       data_len;
    unsigned       headers_sent;
    unsigned       reported;
    char           headers[8192];
    size_t         headers_len;
    unsigned char  body[4096];
    size_t         body_len;
};

static ConfRes SET_path(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || strlen(value) >= sizeof(h2_conf.path))
        return Conf_ERR;
    snprintf(h2_conf.path, sizeof(h2_conf.path), "%s", value);
    return Conf_OK;
}

static ConfRes SET_authority(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || strlen(value) >= sizeof(h2_conf.authority))
        return Conf_ERR;
    snprintf(h2_conf.authority, sizeof(h2_conf.authority), "%s", value);
    return Conf_OK;
}

static ConfRes SET_user_agent(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    if (!value || strlen(value) >= sizeof(h2_conf.user_agent))
        return Conf_ERR;
    snprintf(h2_conf.user_agent, sizeof(h2_conf.user_agent), "%s", value);
    h2_conf.no_user_agent = 0;
    return Conf_OK;
}

static ConfRes SET_no_user_agent(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    h2_conf.no_user_agent = conf_parse_bool(value);
    return Conf_OK;
}

static bool h2_parse_hex(const char *value, unsigned char *out, size_t out_size,
                         size_t *out_len) {
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
    if (!h2_parse_hex(value, h2_conf.settings, sizeof(h2_conf.settings), &len))
        return Conf_ERR;
    h2_conf.settings_len = len;
    return Conf_OK;
}

static ConfRes SET_max_frames(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    h2_conf.max_frames = conf_parse_int(value);
    if (h2_conf.max_frames < 1)
        h2_conf.max_frames = 1;
    return Conf_OK;
}

static ConfRes SET_max_data(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    h2_conf.max_data = conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_record_raw(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    h2_conf.record_raw = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_no_decode_headers(void *conf, const char *name,
                                     const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    h2_conf.decode_headers = !conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_keyword(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    return match_spec_set_keyword(&h2_conf.match, value) ? Conf_OK : Conf_ERR;
}

#ifndef NOT_FOUND_PCRE2
static ConfRes SET_regex(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    return match_spec_set_regex(&h2_conf.match, value) ? Conf_OK : Conf_ERR;
}
#endif

static ConfRes SET_scope(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    return match_spec_set_scope(&h2_conf.match, value) ? Conf_OK : Conf_ERR;
}

static ConfRes SET_insensitive(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    match_spec_set_case_insensitive(&h2_conf.match, conf_parse_bool(value));
    return Conf_OK;
}

static ConfRes SET_newlines(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);
    match_spec_set_include_newlines(&h2_conf.match, conf_parse_bool(value));
    return Conf_OK;
}


static ConfRes SET_doh(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    h2_conf.doh = conf_parse_bool(value);
    return Conf_OK;
}
static ConfRes SET_dns_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    if (!value || strlen(value) >= sizeof(h2_conf.dns_name))
        return Conf_ERR;
    snprintf(h2_conf.dns_name, sizeof(h2_conf.dns_name), "%s", value);
    h2_conf.doh = 1;
    return Conf_OK;
}
static ConfRes SET_dns_type(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    h2_conf.dns_type = dns_str_to_record_type(value);
    return h2_conf.dns_type == DNS_REC_INVALID ? Conf_ERR : Conf_OK;
}
static ConfRes SET_dnssec(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    h2_conf.dnssec = conf_parse_bool(value);
    return Conf_OK;
}

static ConfParam h2_parameters[] = {
    {"path",
     SET_path,
     Type_ARG,
     {0},
     "Request :path (default `/`)."},
    {"authority",
     SET_authority,
     Type_ARG,
     {0},
     "Request :authority. Leave empty to use the target IP address."},
    {"user-agent",
     SET_user_agent,
     Type_ARG,
     {0},
     "HTTP/2 user-agent value. Default is the Xtate version, an overt "
     "fingerprint."},
    {"no-user-agent",
     SET_no_user_agent,
     Type_FLAG,
     {0},
     "Do not send the user-agent header."},
    {"settings-hex",
     SET_settings_hex,
     Type_ARG,
     {"settings", 0},
     "Hex payload for the client SETTINGS frame."},
    {"max-frames",
     SET_max_frames,
     Type_ARG,
     {0},
     "Maximum response frames to parse (default 16)."},
    {"max-data",
     SET_max_data,
     Type_ARG,
     {0},
     "Maximum DATA bytes to keep (default 4096)."},
    {"record-raw",
     SET_record_raw,
     Type_FLAG,
     {0},
     "Record the raw HTTP/2 response bytes."},
    {"no-decode-headers",
     SET_no_decode_headers,
     Type_FLAG,
     {0},
     "Do not HPACK-decode response HEADERS; report raw HEADERS only."},
    {"keyword",
     SET_keyword,
     Type_ARG,
     {0},
     "Literal keyword to search in the selected response scope. Mutually "
     "exclusive with --regex."},
#ifndef NOT_FOUND_PCRE2
    {"regex",
     SET_regex,
     Type_ARG,
     {0},
     "PCRE2 regex to search in the selected response scope. Mutually exclusive "
     "with --keyword."},
#endif
    {"match-scope",
     SET_scope,
     Type_ARG,
     {"scope", 0},
     "Where to match: all, headers or body. Default all."},
    {"case-insensitive",
     SET_insensitive,
     Type_FLAG,
     {"insensitive", 0},
     "Case-insensitive keyword/regex matching."},
    {"include-newlines",
     SET_newlines,
     Type_FLAG,
     {"include-newline", "newline", "newlines", 0},
     "Let PCRE2 dot match newlines (DOTALL)."},
    {"doh", SET_doh, Type_FLAG, {"doh-mode", 0},
     "Send an HTTP/2 POST with application/dns-message."},
    {"dns-name", SET_dns_name, Type_ARG, {"dns-query", 0},
     "DNS name for DoH mode."},
    {"dns-type", SET_dns_type, Type_ARG, {"dns-record-type", 0},
     "DNS type for DoH mode, default A."},
    {"dnssec", SET_dnssec, Type_FLAG, {"do", 0},
     "Set EDNS0 DO=1 in DoH mode."},
    {0}};

static size_t h2_put_indexed(unsigned char *buf, size_t cap, size_t off,
                             unsigned index) {
    if (off + 1 > cap)
        return 0;
    buf[off++] = (unsigned char)(0x80 | index);
    return off;
}

static size_t h2_put_literal_name_index(unsigned char *buf, size_t cap,
                                        size_t off, unsigned name_index,
                                        const char *value) {
    size_t len = strlen(value);
    if (off + 2 + len > cap)
        return 0;
    buf[off++] = (unsigned char)name_index;
    buf[off++] = (unsigned char)len;
    memcpy(buf + off, value, len);
    return off + len;
}

static size_t h2_put_literal_new_name(unsigned char *buf, size_t cap,
                                      size_t off, const char *name,
                                      const char *value) {
    size_t nlen = strlen(name);
    size_t vlen = strlen(value);
    if (off + 2 + nlen + 1 + vlen > cap)
        return 0;
    buf[off++] = 0;
    buf[off++] = (unsigned char)nlen;
    memcpy(buf + off, name, nlen);
    off += nlen;
    buf[off++] = (unsigned char)vlen;
    memcpy(buf + off, value, vlen);
    return off + vlen;
}

static size_t h2_encode_headers(unsigned char *buf, size_t cap,
                                ProbeTarget *target) {
    size_t off = 0;
    /* :method POST (static index 3) for DoH, GET (2) otherwise. */
    off = h2_put_indexed(buf, cap, off, h2_conf.doh ? 3 : 2);
    if (!off)
        return 0;
    off = h2_put_indexed(buf, cap, off, 7);
    if (!off)
        return 0;

    if (strcmp(h2_conf.path, "/") == 0) {
        off = h2_put_indexed(buf, cap, off, 4); /* :path / */
    } else {
        off = h2_put_literal_name_index(buf, cap, off, 4, h2_conf.path);
    }
    if (!off)
        return 0;

    char authority[300];
    if (h2_conf.authority[0]) {
        snprintf(authority, sizeof(authority), "%s", h2_conf.authority);
    } else {
        ipaddress_formatted_t fmt = ipaddress_fmt(target->target.ip_them);
        snprintf(authority, sizeof(authority), "%s", fmt.string);
    }
    off = h2_put_literal_name_index(buf, cap, off, 1, authority);
    if (!off)
        return 0;

    if (h2_conf.doh) {
        off = h2_put_literal_new_name(buf, cap, off, "content-type",
                                      "application/dns-message");
        return off;
    }
    if (!h2_conf.no_user_agent && h2_conf.user_agent[0]) {
        off = h2_put_literal_new_name(buf, cap, off, "user-agent",
                                      h2_conf.user_agent);
    }
    return off;
}

static size_t h2_frame_header(unsigned char *buf, unsigned length,
                              unsigned type, unsigned flags, unsigned stream) {
    buf[0] = (unsigned char)(length >> 16);
    buf[1] = (unsigned char)(length >> 8);
    buf[2] = (unsigned char)length;
    buf[3] = (unsigned char)type;
    buf[4] = (unsigned char)flags;
    buf[5] = (unsigned char)(stream >> 24);
    buf[6] = (unsigned char)(stream >> 16);
    buf[7] = (unsigned char)(stream >> 8);
    buf[8] = (unsigned char)stream;
    return 9;
}

static bool h2_init(const struct XtateConf *xconf) {
    UNUSEDPARM(xconf);
    if (h2_conf.doh && strcmp(h2_conf.path, "/") == 0)
        snprintf(h2_conf.path, sizeof(h2_conf.path), "%s", "/dns-query");
    return match_spec_finalize(&h2_conf.match);
}

static void h2_close(void) {
    match_spec_free(&h2_conf.match);
}

static bool h2_conn_init(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    struct H2State *hs = CALLOC(1, sizeof(struct H2State));
    if (!hs)
        return false;
    hs->rx_cap = 4096;
    hs->rx = MALLOC(hs->rx_cap);
    if (!hs->rx) {
        FREE(hs);
        return false;
    }
    state->data = hs;
    state->state = 0;
    return true;
}

static void h2_conn_close(ProbeState *state, ProbeTarget *target) {
    UNUSEDPARM(target);
    struct H2State *hs = state->data;
    if (!hs)
        return;
    FREE(hs->rx);
    FREE(hs);
    state->data = NULL;
}


static size_t h2_doh_query(ProbeTarget *target, unsigned char *out) {
    if (!h2_conf.dns_name[0])
        return 0;
    int n = dns_question_create(out, h2_conf.dns_name,
                                h2_conf.dns_type ? h2_conf.dns_type : DNS_REC_A,
                                target->cookie & 0xffff);
    if (n <= 0)
        return 0;
    if (h2_conf.dnssec) {
        unsigned char *p = out + n;
        p[0]=0; p[1]=0x00; p[2]=0x29; p[3]=0x04; p[4]=0xd0;
        p[5]=0; p[6]=0; p[7]=0x80; p[8]=0; p[9]=0; p[10]=0; p[11]=0;
        n += 11;
        out[10]=0; out[11]=1;
    }
    return n > 0 ? (size_t)n : 0;
}

static void h2_make_hello(DataPass *pass, ProbeState *state,
                          ProbeTarget *target) {
    UNUSEDPARM(state);
    size_t cap = 1024 + h2_conf.settings_len;
    unsigned char *buf = MALLOC(cap);
    if (!buf) {
        datapass_set_data(pass, NULL, 0, false);
        return;
    }

    size_t off = 0;
    memcpy(buf, H2_PREFACE, H2_PREFACE_LEN);
    off += H2_PREFACE_LEN;

    off += h2_frame_header(buf + off, (unsigned)h2_conf.settings_len, 4, 0, 0);
    if (h2_conf.settings_len)
        memcpy(buf + off, h2_conf.settings, h2_conf.settings_len);
    off += h2_conf.settings_len;

    unsigned char block[512];
    size_t block_len = h2_encode_headers(block, sizeof(block), target);
    if (!block_len) {
        FREE(buf);
        datapass_set_data(pass, NULL, 0, false);
        return;
    }
    off += h2_frame_header(buf + off, (unsigned)block_len, 1,
                           h2_conf.doh ? 0x4 : 0x5, 1);
    memcpy(buf + off, block, block_len);
    off += block_len;

    if (h2_conf.doh) {
        unsigned char dns[2048];
        size_t dns_len = h2_doh_query(target, dns);
        if (!dns_len || off + 9 + dns_len > cap) {
            FREE(buf);
            datapass_set_data(pass, NULL, 0, false);
            return;
        }
        off += h2_frame_header(buf + off, (unsigned)dns_len, 0, 0x1, 1);
        memcpy(buf + off, dns, dns_len);
        off += dns_len;
    }

    datapass_set_data(pass, buf, off, true);
}

/* ---------------- HPACK (static table, literals, Huffman) ---------- */

static const char *const h2_static_names[] = {
    "", ":authority", ":method", ":method", ":path", ":path", ":scheme",
    ":scheme", ":status", ":status", ":status", ":status", ":status",
    ":status", ":status", "accept-charset", "accept-encoding", "accept-language",
    "accept-ranges", "accept", "access-control-allow-origin", "age", "allow",
    "authorization", "cache-control", "content-disposition", "content-encoding",
    "content-language", "content-length", "content-location", "content-range",
    "content-type", "cookie", "date", "etag", "expect", "expires", "from",
    "host", "if-match", "if-modified-since", "if-none-match", "if-range",
    "if-unmodified-since", "last-modified", "link", "location", "max-forwards",
    "proxy-authenticate", "proxy-authorization", "range", "referer", "refresh",
    "retry-after", "server", "set-cookie", "strict-transport-security",
    "transfer-encoding", "user-agent", "vary", "via", "www-authenticate"};

static const char *h2_static_value(unsigned index) {
    switch (index) {
        case 2:
            return "GET";
        case 3:
            return "POST";
        case 4:
            return "/";
        case 5:
            return "/index.html";
        case 6:
            return "http";
        case 7:
            return "https";
        case 8:
            return "200";
        case 9:
            return "204";
        case 10:
            return "206";
        case 11:
            return "304";
        case 12:
            return "400";
        case 13:
            return "404";
        case 14:
            return "500";
        default:
            return "";
    }
}

static size_t h2_hpack_int(const unsigned char *data, size_t len, size_t *off,
                           unsigned prefix) {
    if (*off >= len)
        return (size_t)-1;
    unsigned mask = (1u << prefix) - 1;
    size_t   value = data[(*off)++] & mask;
    if (value < mask)
        return value;
    unsigned shift = 0;
    while (*off < len) {
        unsigned b = data[(*off)++];
        if (shift >= sizeof(value) * 8)
            return (size_t)-1;
        size_t add = (size_t)(b & 0x7f) << shift;
        if (value > ~(size_t)0 - add)
            return (size_t)-1;
        value += add;
        if (!(b & 0x80))
            return value;
        shift += 7;
    }
    return (size_t)-1;
}


static int h2_huffman_decode(const unsigned char *src, size_t srclen,
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
        int found = -1; unsigned flen = 0;
        for (unsigned sym = 0; sym < 257; sym++) {
            unsigned len = h3_huff_len[sym];
            if (len <= bits) {
                uint64_t mask = (1ULL << len) - 1;
                if (((acc >> (bits - len)) & mask) == h3_huff_code[sym]) {
                    found = (int)sym; flen = len; break;
                }
            }
        }
        if (found < 0) {
            if (si >= srclen && bits <= 7 &&
                (acc & ((1ULL << bits) - 1)) == ((1ULL << bits) - 1))
                break;
            return -1;
        }
        if (found == 256) return -1;
        if (di + 1 >= dstcap) return -1;
        dst[di++] = (char)found;
        bits -= flen;
        if (bits == 0 && si == srclen) break;
    }
    if (di >= dstcap) return -1;
    dst[di] = 0;
    return (int)di;
}

static bool h2_hpack_str(const unsigned char *data, size_t len, size_t *off,
                         char *out, size_t out_size) {
    if (*off >= len)
        return false;
    bool huffman = (data[*off] & 0x80) != 0;
    size_t slen = h2_hpack_int(data, len, off, 7);
    if (slen == (size_t)-1 || slen > len - *off)
        return false;
    if (huffman) {
        int d = h2_huffman_decode(data + *off, slen, out, out_size);
        if (d < 0)
            return false;
        *off += slen;
        return true;
    }
    if (slen >= out_size)
        return false;
    memcpy(out, data + *off, slen);
    out[slen] = '\0';
    *off += slen;
    return true;
}

#ifdef H2_FUZZ
static void h2_emit_header(OutItem *item, struct H2State *hs, const char *name,
                           const char *value) {
    (void)item;
    (void)name;
    (void)value;
    hs->header_count++;
}
#else
static void h2_emit_header(OutItem *item, struct H2State *hs, const char *name,
                           const char *value) {
    char field[32];
    char pair[512];
    snprintf(pair, sizeof(pair), "%s: %s", name, value);
    snprintf(field, sizeof(field), "h2_hdr_%u", hs->header_count);
    dach_append_str(&item->probe_report, field, pair, strlen(pair));
    if (hs->headers_len + strlen(name) + strlen(value) + 4 <
        sizeof(hs->headers)) {
        int n = snprintf(hs->headers + hs->headers_len,
                         sizeof(hs->headers) - hs->headers_len, "%s: %s\r\n",
                         name, value);
        if (n > 0)
            hs->headers_len += (size_t)n;
    }
    if (strcmp(name, ":status") == 0)
        dach_append_str(&item->probe_report, "h2_status", value, strlen(value));
    hs->header_count++;
}
#endif /* H2_FUZZ */

static bool h2_decode_headers(const unsigned char *data, size_t len,
                              OutItem *item, struct H2State *hs) {
    size_t off = 0;
    while (off < len) {
        unsigned b = data[off];
        if (b & 0x80) { /* indexed */
            size_t idx = h2_hpack_int(data, len, &off, 7);
            if (idx == (size_t)-1 || idx == 0 ||
                idx >= sizeof(h2_static_names) / sizeof(h2_static_names[0]))
                return false;
            const char *name = h2_static_names[idx];
            const char *value = h2_static_value((unsigned)idx);
            if (name[0])
                h2_emit_header(item, hs, name, value);
        } else if ((b & 0xc0) == 0x40 || (b & 0xf0) == 0x00 ||
                   (b & 0xf0) == 0x10) {
            unsigned prefix = ((b & 0xc0) == 0x40) ? 6 : 4;
            size_t name_idx = h2_hpack_int(data, len, &off, prefix);
            if (name_idx == (size_t)-1)
                return false;
            char name[128];
            if (name_idx == 0) {
                if (!h2_hpack_str(data, len, &off, name, sizeof(name)))
                    return false;
            } else {
                if (name_idx >= sizeof(h2_static_names) /
                                    sizeof(h2_static_names[0]))
                    return false;
                snprintf(name, sizeof(name), "%s", h2_static_names[name_idx]);
            }
            char value[512];
            if (!h2_hpack_str(data, len, &off, value, sizeof(value)))
                return false;
            h2_emit_header(item, hs, name, value);
        } else {
            return false;
        }
    }
    return true;
}

/* ---------------- response handling -------------------------------- */

static bool h2_rx_append(struct H2State *hs, const unsigned char *data,
                         size_t len) {
    if (hs->rx_len + len > H2_BUF_MAX)
        return false;
    if (hs->rx_len + len > hs->rx_cap) {
        size_t cap = hs->rx_cap;
        while (cap < hs->rx_len + len)
            cap *= 2;
        unsigned char *p = REALLOC(hs->rx, cap);
        if (!p)
            return false;
        hs->rx = p;
        hs->rx_cap = cap;
    }
    memcpy(hs->rx + hs->rx_len, data, len);
    hs->rx_len += len;
    return true;
}

static bool h2_handle_response(DataPass *pass, ProbeState *state, OutConf *out,
                               ProbeTarget *target, const unsigned char *px,
                               unsigned sizeof_px) {
    struct H2State *hs = state->data;
    if (!hs || !h2_rx_append(hs, px, sizeof_px))
        return false;

    OutItem item = {
        .level = OUT_SUCCESS,
        .target.ip_proto = target->target.ip_proto,
        .target.ip_them = target->target.ip_them,
        .target.ip_me = target->target.ip_me,
        .target.port_them = target->target.port_them,
        .target.port_me = target->target.port_me,
    };

    size_t   off = 0;
    unsigned settings_ack = 0;
    while (off + 9 <= hs->rx_len && hs->frames < h2_conf.max_frames) {
        unsigned length = ((unsigned)hs->rx[off] << 16) |
                          ((unsigned)hs->rx[off + 1] << 8) | hs->rx[off + 2];
        unsigned type = hs->rx[off + 3];
        unsigned flags = hs->rx[off + 4];
        unsigned stream = (((unsigned)hs->rx[off + 5] & 0x7f) << 24) |
                          ((unsigned)hs->rx[off + 6] << 16) |
                          ((unsigned)hs->rx[off + 7] << 8) | hs->rx[off + 8];
        if (off + 9 + length > hs->rx_len)
            break;

        hs->frames++;
        if (type == 4) { /* SETTINGS */
            hs->settings_count += length / 6;
            settings_ack = 1;
            for (unsigned i = 0; i + 5 < length; i += 6) {
                unsigned id = ((unsigned)hs->rx[off + 9 + i] << 8) |
                              hs->rx[off + 9 + i + 1];
                unsigned value = ((unsigned)hs->rx[off + 9 + i + 2] << 24) |
                                 ((unsigned)hs->rx[off + 9 + i + 3] << 16) |
                                 ((unsigned)hs->rx[off + 9 + i + 4] << 8) |
                                 hs->rx[off + 9 + i + 5];
                char field[32];
                snprintf(field, sizeof(field), "h2_set_%u", id);
                dach_set_int(&item.probe_report, field, value);
            }
        } else if (type == 1) { /* HEADERS */
            if (h2_conf.decode_headers &&
                !h2_decode_headers(hs->rx + off + 9, length, &item, hs)) {
                dach_set_bool(&item.probe_report, "h2_hpack_decode_failed", true);
            }
            if (stream == 1 && (flags & 0x1))
                hs->headers_sent = 1;
        } else if (type == 0) { /* DATA */
            unsigned take = length;
            if (hs->data_len + take > h2_conf.max_data)
                take = h2_conf.max_data - hs->data_len;
            if (take) {
                dach_append_bin(&item.probe_report, "h2_data",
                                hs->rx + off + 9, take);
                size_t bspace = sizeof(hs->body) - hs->body_len;
                size_t bcopy = take < bspace ? take : bspace;
                if (bcopy) {
                    memcpy(hs->body + hs->body_len, hs->rx + off + 9, bcopy);
                    hs->body_len += bcopy;
                }
                hs->data_len += take;
            }
            if (stream == 1 && (flags & 0x1)) {
                item.level = OUT_SUCCESS;
            }
        }
        off += 9 + length;
    }

    if (hs->rx_len > off) {
        memmove(hs->rx, hs->rx + off, hs->rx_len - off);
        hs->rx_len -= off;
    } else {
        hs->rx_len = 0;
    }

    dach_set_int(&item.probe_report, "h2_frame_count", hs->frames);
    dach_set_int(&item.probe_report, "h2_settings_count", hs->settings_count);
    dach_set_int(&item.probe_report, "h2_header_count", hs->header_count);
    dach_set_int(&item.probe_report, "h2_data_len", hs->data_len);
    if (h2_conf.record_raw)
        dach_append_bin(&item.probe_report, "h2_raw", px, sizeof_px);

    if (h2_conf.doh && hs->body_len >= 12) {
        dns_pkt_t pkt;
        if (dns_parse_reply(hs->body, hs->body_len, &pkt)) {
            dach_set_int(&item.probe_report, "doh_dns_len",
                         (unsigned)hs->body_len);
            dach_set_int(&item.probe_report, "doh_rcode",
                         pkt.head.header.rcode);
            dach_set_bool(&item.probe_report, "doh_ad", pkt.head.header.ad);
            if (pkt.head.header.ans_count > 0) {
                char answer[256];
                dns_raw_record_data2str(&pkt.body.ans[0], hs->body,
                                        hs->body + hs->body_len, false, answer,
                                        sizeof(answer));
                dach_append_str(&item.probe_report, "doh_answer", answer,
                                strlen(answer));
            }
            unsigned sig=0, key=0, ds=0, nsec=0;
            for (unsigned i=0; i<pkt.head.header.ans_count+
                                      pkt.head.header.auth_count+
                                      pkt.head.header.add_count; i++) {
                dns_record_t *r;
                if (i < pkt.head.header.ans_count) r=&pkt.body.ans[i];
                else if (i < pkt.head.header.ans_count+pkt.head.header.auth_count)
                    r=&pkt.body.auth[i-pkt.head.header.ans_count];
                else r=&pkt.body.add[i-pkt.head.header.ans_count-
                                            pkt.head.header.auth_count];
                if (r->type==46) sig++; else if (r->type==48) key++;
                else if (r->type==43) ds++; else if (r->type==47||r->type==50) nsec++;
            }
            dach_set_int(&item.probe_report, "doh_rrsig_count", sig);
            dach_set_int(&item.probe_report, "doh_dnskey_count", key);
            dach_set_int(&item.probe_report, "doh_ds_count", ds);
            dach_set_int(&item.probe_report, "doh_nsec_count", nsec);
            dach_set_bool(&item.probe_report, "doh_dnssec_present",
                          sig||key||ds||nsec);
            safe_strcpy(item.classification, OUT_CLS_SIZE, "doh");
            safe_strcpy(item.reason, OUT_RSN_SIZE,
                        dns_rcode2str(pkt.head.header.rcode));
        }
    }


    if (h2_conf.match.configured) {
        size_t all_len = hs->headers_len + hs->body_len + 3;
        char  *all = MALLOC(all_len);
        if (all) {
            memcpy(all, hs->headers, hs->headers_len);
            all[hs->headers_len] = '\r';
            all[hs->headers_len + 1] = '\n';
            memcpy(all + hs->headers_len + 2, hs->body, hs->body_len);
            all_len = hs->headers_len + 2 + hs->body_len;
            MatchResult mr;
            match_spec_apply(&h2_conf.match, all, all_len, hs->headers,
                             hs->headers_len, hs->body, hs->body_len, &mr);
            FREE(all);
            dach_set_int(&item.probe_report, "h2_match", mr.matched ? 1 : 0);
            dach_append_str(&item.probe_report, "h2_match_kind", mr.kind,
                            strlen(mr.kind));
            dach_append_str(&item.probe_report, "h2_match_scope",
                            match_scope_name(mr.scope),
                            strlen(match_scope_name(mr.scope)));
            if (mr.text[0])
                dach_append_str(&item.probe_report, "h2_match_text", mr.text,
                                strlen(mr.text));
            item.level = mr.matched ? OUT_SUCCESS : OUT_FAILURE;
            if (mr.matched)
                safe_strcpy(item.classification, OUT_CLS_SIZE, "matched");
            else {
                safe_strcpy(item.classification, OUT_CLS_SIZE, "not matched");
                safe_strcpy(item.reason, OUT_RSN_SIZE, "no match");
            }
        }
    }

    if (!hs->reported) {
        if (!h2_conf.match.configured) {
            safe_strcpy(item.classification, OUT_CLS_SIZE, "http/2");
            safe_strcpy(item.reason, OUT_RSN_SIZE, "response");
        }
        hs->reported = 1;
        output_result(out, &item);
    }

    if (settings_ack) {
        unsigned char *ack = MALLOC(9);
        if (ack) {
            h2_frame_header(ack, 0, 4, 1, 0);
            datapass_set_data(pass, ack, 9, true);
        }
    }

    /* The response is complete enough for this probe; let TLS close cleanly. */
    pass->is_close = 1;
    return true;
}

static unsigned h2_parse_response(DataPass *pass, ProbeState *state,
                                  OutConf *out, ProbeTarget *target,
                                  const unsigned char *px,
                                  unsigned sizeof_px) {
    h2_handle_response(pass, state, out, target, px, sizeof_px);
    return 0;
}

#ifndef H2_FUZZ

Probe DohH2Probe = {
    .name       = "doh-h2",
    .type       = ProbeType_STATE,
    .hello_wait = 0,
    .params     = h2_parameters,
    .short_desc = "DNS over HTTPS (DoH) over HTTP/2.",
    .desc = "Stateful DoH/HTTP2 client for `-scan tcp-state -probe tls-state "
            "-alpn h2 -subprobe doh-h2`. Sends an HTTP/2 POST with "
            "application/dns-message and parses the DNS response body. "
            "Requires --dns-name and --authority. State probe.",
    .init_cb           = &h2_init,
    .conn_init_cb      = &h2_conn_init,
    .make_hello_cb     = &h2_make_hello,
    .parse_response_cb = &h2_parse_response,
    .conn_close_cb     = &h2_conn_close,
    .close_cb          = &h2_close,
};

Probe H2Probe = {
    .name       = "h2",
    .type       = ProbeType_STATE,
    .slots      = {.count = 1, .trigger = ProbeSlot_None, .continue_cb = NULL},
    .params     = h2_parameters,
    .short_desc = "HTTP/2 over TLS via HLTCP (ALPN h2).",
    .desc = "Stateful HTTP/2 client for -scan tcp-state -probe tls-state "
            "-alpn h2 -subprobe h2. Sends the HTTP/2 preface, SETTINGS and a "
            "minimal HPACK request, then parses SETTINGS, HEADERS (static/"
            "HPACK including Huffman) and DATA. Response matching supports "
            "--keyword/--regex with all/headers/body scopes. It is not h2c; "
            "use the separate h2c probe for cleartext prior knowledge.\n"
            "Dependencies: OpenSSL (for tls-state).",
    .init_cb           = &h2_init,
    .conn_init_cb      = &h2_conn_init,
    .make_hello_cb     = &h2_make_hello,
    .parse_response_cb = &h2_parse_response,
    .conn_close_cb     = &h2_conn_close,
    .close_cb          = &h2_close,
};
#endif /* H2_FUZZ */
