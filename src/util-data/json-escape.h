#ifndef JSON_ESCAPE_H
#define JSON_ESCAPE_H
#include <stddef.h>

typedef void (*JsonEscapeSink)(void *ctx, const char *data, size_t len);

/* Escape JSON string content (without surrounding quotes). The sink may be
 * called multiple times; it must copy the bytes before returning. */
void json_escape_to(JsonEscapeSink sink, void *ctx, const unsigned char *src,
                    size_t len);
#endif
