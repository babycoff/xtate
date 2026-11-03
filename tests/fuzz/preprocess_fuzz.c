/*
 * libFuzzer harness for the packet preprocessor.
 *
 * Build/run with tests/fuzz/run.sh. LOG is stubbed so the fuzzer only links the
 * parser, not the logger/OpenSSL/threads.
 */
#include <stdint.h>
#include <stddef.h>

#include "proto/proto-preprocess.h"
#include "stub/stub-pcap-dlt.h"

void LOG(int level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 65535)
        return 0;

    PreInfo info;
    (void)preprocess_frame(data, (unsigned)size, PCAP_DLT_ETHERNET, &info);
    return 0;
}
