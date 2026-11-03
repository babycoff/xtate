#include "../../src/generate-modules/generate-modules.h"
#include "../../src/target/target-ipaddress.h"
#include "../../src/util-misc/misc.h"

#include <string.h>

static bool example_gen_init(const struct XtateConf *xconf,
                             uint64_t *count_targets,
                             uint64_t *count_endpoints, bool *init_ipv4,
                             bool *init_ipv6) {
    UNUSEDPARM(xconf);
    *count_targets = 4;
    *count_endpoints = 1;
    *init_ipv4 = true;
    *init_ipv6 = false;
    return true;
}

static bool example_gen_hasmore(unsigned tx_index, uint64_t index) {
    UNUSEDPARM(tx_index);
    return index < 4;
}

static Target example_gen_generate(unsigned tx_index, uint64_t index,
                                   uint64_t repeat, struct source_t *src) {
    UNUSEDPARM(tx_index);
    UNUSEDPARM(repeat);
    UNUSEDPARM(src);
    Target target = {0};
    target.ip_proto = IP_PROTO_TCP;
    target.ip_them.version = 4;
    target.ip_them.ipv4 = 0x0a000001u + (unsigned)index;
    target.port_them = 80;
    return target;
}

static void example_gen_close(void) {}

Generator ExampleGenerator = {
    .name = "example-generate",
    .desc = "Compile-tested generate-module template.",
    .init_cb = &example_gen_init,
    .hasmore_cb = &example_gen_hasmore,
    .generate_cb = &example_gen_generate,
    .close_cb = &example_gen_close,
};
