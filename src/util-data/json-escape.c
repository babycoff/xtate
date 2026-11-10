#include "json-escape.h"

void json_escape_to(JsonEscapeSink sink, void *ctx, const unsigned char *src,
                    size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char c = src[i];
        char          tmp[8];
        size_t        n = 0;
        switch (c) {
            case '"': sink(ctx, "\\\"", 2); break;
            case '\\': sink(ctx, "\\\\", 2); break;
            case '\b': sink(ctx, "\\b", 2); break;
            case '\f': sink(ctx, "\\f", 2); break;
            case '\n': sink(ctx, "\\n", 2); break;
            case '\r': sink(ctx, "\\r", 2); break;
            case '\t': sink(ctx, "\\t", 2); break;
            default:
                if (c < 0x20) {
                    static const char hex[] = "0123456789abcdef";
                    tmp[0]='\\'; tmp[1]='u'; tmp[2]='0'; tmp[3]='0';
                    tmp[4]=hex[(c >> 4) & 0xf]; tmp[5]=hex[c & 0xf];
                    n = 6;
                    sink(ctx, tmp, n);
                } else {
                    sink(ctx, (const char *)&c, 1);
                }
        }
    }
}
