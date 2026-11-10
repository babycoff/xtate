#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util-data/json-escape.h"

struct buf {
    char  *p;
    size_t cap;
    size_t len;
};

static void sink(void *ctx, const char *data, size_t len) {
    struct buf *b = ctx;
    if (b->len + len > b->cap)
        abort();
    memcpy(b->p + b->len, data, len);
    b->len += len;
}

static int hex(int c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535)
        return 0;
    size_t      cap = size * 6 + 16;
    struct buf  b = {.p = malloc(cap), .cap = cap, .len = 0};
    if (!b.p)
        return 0;
    json_escape_to(sink, &b, data, size);

    for (size_t i = 0; i < b.len; i++) {
        unsigned char c = (unsigned char)b.p[i];
        if (c < 0x20 || c == '"')
            abort();
        if (c == '\\') {
            if (++i >= b.len)
                abort();
            unsigned char e = (unsigned char)b.p[i];
            if (e == 'u') {
                if (i + 4 >= b.len || !hex(b.p[i + 1]) || !hex(b.p[i + 2]) ||
                    !hex(b.p[i + 3]) || !hex(b.p[i + 4]))
                    abort();
                i += 4;
            } else if (!strchr("\"\\/bfnrt", e)) {
                abort();
            }
        }
    }
    free(b.p);
    return 0;
}

#ifdef JSON_ESCAPE_TEST_MAIN
int main(void) {
    uint8_t data[256];
    for (unsigned v = 0; v < 256; v++) {
        for (unsigned n = 0; n < sizeof(data); n++)
            data[n] = (uint8_t)(v + n);
        LLVMFuzzerTestOneInput(data, sizeof(data));
    }
    return 0;
}
#endif
