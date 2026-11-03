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

    /* Exercise every link type the production parser accepts, not just
     * Ethernet. Each call gets a fresh PreInfo because callbacks may leave
     * parser-owned offsets/pointers behind. */
    static const unsigned link_types[] = {
        PCAP_DLT_ETHERNET,     PCAP_DLT_NULL,
        PCAP_DLT_RAW,          PCAP_DLT_IEEE802_11,
        PCAP_DLT_LINUX_SLL,    PCAP_DLT_PRISM_HEADER,
        PCAP_DLT_IEEE802_11_RADIO,
    };

    for (size_t i = 0; i < sizeof(link_types) / sizeof(link_types[0]); i++) {
        PreInfo info;
        (void)preprocess_frame(data, (unsigned)size, link_types[i], &info);
    }
    return 0;
}
