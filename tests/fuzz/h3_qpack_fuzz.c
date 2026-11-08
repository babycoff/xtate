/* libFuzzer harness for the in-tree HTTP/3 frame/QPACK decoder.
 * Includes the probe translation unit so the fuzzed code is the product code,
 * not a copy. Probe-specific unresolved callbacks are discarded by section GC
 * or ignored by the fuzz-only link.
 */
#define HAVE_NGTCP2 1
#include "../../src/probe-modules/http3-state-probe.c"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    if (size > 65536)
        return 0;
    unsigned char body[1024];
    unsigned char buf[65536];
    struct Http3State h = {0};
    OutItem item = {0};
    memcpy(buf, data, size);
    h.buf = buf;
    h.buf_len = size;
    h.body = (char *)body;
    h.max_body = sizeof(body) - 1;
    h.max_headers = H3_MAX_HEADERS;
    h.record_body = 1;
    h.record_headers = 1;
    h3_parse_frames(&h, &item);
    return 0;
}
