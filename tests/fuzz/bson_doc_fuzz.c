#include <stdint.h>
#include <stdlib.h>
#include <bson/bson.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5 || size > 16 * 1024 * 1024)
        return 0;
    bson_t doc;
    if (bson_init_static(&doc, data, size)) {
        char *json = bson_as_relaxed_extended_json(&doc, NULL);
        bson_free(json);
        bson_destroy(&doc);
    }
    return 0;
}
