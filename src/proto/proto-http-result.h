#ifndef PROTO_HTTP_RESULT_H
#define PROTO_HTTP_RESULT_H

#include <stddef.h>

#define HTTP_RESULT_MAX_HEADERS 64
#define HTTP_RESULT_NAME_SIZE 64
#define HTTP_RESULT_VALUE_SIZE 256
#define HTTP_RESULT_REASON_SIZE 128

typedef struct HttpResultHeader {
    char name[HTTP_RESULT_NAME_SIZE];
    char value[HTTP_RESULT_VALUE_SIZE];
} HttpResultHeader;

typedef struct HttpResult {
    int              minor_version;
    int              status;
    char             reason[HTTP_RESULT_REASON_SIZE];
    size_t           header_bytes;
    size_t           body_offset;
    unsigned         header_count;
    HttpResultHeader headers[HTTP_RESULT_MAX_HEADERS];
    size_t           body_len;
    size_t           content_length;
    unsigned         has_content_length : 1;
    unsigned         chunked : 1;
    unsigned         chunked_incomplete : 1;
} HttpResult;

/* Parse a complete response head and as much body as is present.  Returns 0
 * on success, -2 for a partial head, -1 for malformed input. */
int http_result_parse(const unsigned char *buf, size_t len, HttpResult *out);

/* Small deterministic parser regression used by --selftest. */
int proto_http_result_selftest(void);

#endif
