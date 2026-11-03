/*
 * libFuzzer harness for the IPv4/IPv6 target-range parser.
 *
 * target_parse_range is the parser used by --target-ip, --exclude and target
 * files. The harness provides the Range/Range6 outputs and a NUL-terminated
 * copy of the fuzzer input.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "target/target-parse.h"
#include "target/target-rangev4.h"
#include "target/target-rangev6.h"
#include "target/target-set.h"

/* target_parse.c also contains targetset_parse_file(), which references these
 * two symbols. The fuzzer only calls target_parse_range(); stubs keep the
 * linker happy without pulling in the whole TargetSet/AS subsystem. */
int targetset_add_ip_str(TargetSet *targetset, const char *string) {
    (void)targetset;
    (void)string;
    return 0;
}

void rangelist_sort(struct RangeList *targets) {
    (void)targets;
}

void LOG(int level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096)
        return 0;

    char *line = malloc(size + 1);
    if (line == NULL)
        return 0;
    memcpy(line, data, size);
    line[size] = '\0';

    struct Range  ipv4;
    struct Range6 ipv6;
    memset(&ipv4, 0, sizeof(ipv4));
    memset(&ipv6, 0, sizeof(ipv6));

    size_t offset = 0;
    (void)target_parse_range(line, &offset, size, &ipv4, &ipv6);

    free(line);
    return 0;
}
