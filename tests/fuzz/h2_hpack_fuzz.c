/* libFuzzer harness for the in-tree HTTP/2 HPACK decoder. */
#define H2_FUZZ 1
#include "../../src/probe-modules/h2-probe.c"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    if (size > 65536)
        return 0;
    unsigned char buf[65536];
    memcpy(buf, data, size);
    struct H2State hs = {0};
    OutItem item = {0};
    h2_decode_headers(buf, size, &item, &hs);
    return 0;
}
