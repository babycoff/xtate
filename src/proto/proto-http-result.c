#include "proto-http-result.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "../util-data/fine-malloc.h"
#include "proto-http-parser.h"

static int header_name_equals(const char *name, size_t name_len,
                              const char *expected) {
    size_t expected_len = strlen(expected);
    if (name_len != expected_len)
        return 0;
    for (size_t i = 0; i < name_len; i++) {
        if (tolower((unsigned char)name[i]) !=
            tolower((unsigned char)expected[i]))
            return 0;
    }
    return 1;
}

static void copy_field(char *dst, size_t dst_size, const char *src,
                       size_t src_len) {
    if (!dst_size)
        return;
    if (src_len >= dst_size)
        src_len = dst_size - 1;
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
}

int http_result_parse(const unsigned char *buf, size_t len, HttpResult *out) {
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));

    struct ph_header headers[HTTP_RESULT_MAX_HEADERS];
    size_t           num_headers = HTTP_RESULT_MAX_HEADERS;
    const char      *reason = NULL;
    size_t           reason_len = 0;

    int consumed = ph_parse_response((const char *)buf, len, &out->minor_version,
                                     &out->status, &reason, &reason_len,
                                     headers, &num_headers, 0);
    if (consumed < 0)
        return consumed == -2 ? -2 : -1;

    out->header_bytes = (size_t)consumed;
    out->body_offset = (size_t)consumed;
    copy_field(out->reason, sizeof(out->reason), reason, reason_len);

    for (size_t i = 0; i < num_headers && out->header_count < HTTP_RESULT_MAX_HEADERS;
         i++) {
        if (!headers[i].name)
            continue;
        HttpResultHeader *dst = &out->headers[out->header_count++];
        copy_field(dst->name, sizeof(dst->name), headers[i].name,
                   headers[i].name_len);
        copy_field(dst->value, sizeof(dst->value), headers[i].value,
                   headers[i].value_len);
    }

    const unsigned char *body = buf + consumed;
    size_t               body_avail = len - (size_t)consumed;

    size_t content_length = (size_t)-1;
    for (unsigned i = 0; i < out->header_count; i++) {
        if (header_name_equals(out->headers[i].name,
                               strlen(out->headers[i].name),
                               "content-length")) {
            content_length = (size_t)strtoull(out->headers[i].value, NULL, 10);
            out->content_length = content_length;
            out->has_content_length = 1;
        }
        if (header_name_equals(out->headers[i].name,
                               strlen(out->headers[i].name),
                               "transfer-encoding") &&
            strstr(out->headers[i].value, "chunked") != NULL) {
            out->chunked = 1;
        }
    }

    if (out->chunked) {
        size_t decode_len = body_avail;
        char  *decoded = MALLOC(decode_len + 1);
        if (!decoded)
            return -1;
        memcpy(decoded, body, decode_len);
        struct ph_chunked_decoder decoder;
        memset(&decoder, 0, sizeof(decoder));
        decoder.consume_trailer = 1;
        int r = ph_decode_chunked(&decoder, decoded, &decode_len);
        if (r == -2) {
            out->chunked_incomplete = 1;
            out->body_len = 0;
        } else if (r < 0) {
            FREE(decoded);
            return -1;
        } else {
            out->body_len = decode_len;
        }
        FREE(decoded);
    } else if (content_length != (size_t)-1) {
        out->body_len = body_avail < content_length ? body_avail : content_length;
    } else {
        out->body_len = body_avail;
    }

    return 0;
}

int proto_http_result_selftest(void) {
    const char *normal =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "hello";
    HttpResult r;
    if (http_result_parse((const unsigned char *)normal, strlen(normal), &r) != 0)
        return 1;
    if (r.status != 200 || r.header_count != 2 || r.body_len != 5 ||
        strcmp(r.reason, "OK") != 0)
        return 2;

    const char *chunked =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n";
    if (http_result_parse((const unsigned char *)chunked, strlen(chunked), &r) != 0)
        return 3;
    if (!r.chunked || r.body_len != 5)
        return 4;

    const char *partial = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n";
    if (http_result_parse((const unsigned char *)partial, strlen(partial), &r) != -2)
        return 5;

    return 0;
}
