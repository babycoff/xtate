/*
 * libFuzzer harness for target-set string and port-range parsing.
 *
 * targetset_add_ip_str() is the tokenizer behind --target-ip, --exclude and
 * target files; targetset_add_port_str() is the port/prefix parser behind -p.
 * ASN lookup is stubbed so the fuzzer does not need the AS database.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "target/target-set.h"
#include "target/target-parse.h"
#include "target/target-rangev4.h"
#include "target/target-rangev6.h"
#include "as/as-query.h"

void LOG(int level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}

bool as_query_add_as_to_range(const struct AS_Query *as_query,
                              struct RangeList *ipv4_list, unsigned asn) {
    (void)as_query;
    (void)ipv4_list;
    (void)asn;
    return false;
}

bool as_query_add_as_to_range6(const struct AS_Query *as_query,
                               struct Range6List *ipv6_list, unsigned asn) {
    (void)as_query;
    (void)ipv6_list;
    (void)asn;
    return false;
}

void xcmd_try_reboot(void) {
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 1024)
        return 0;

    char *line = malloc(size + 1);
    if (line == NULL)
        return 0;
    memcpy(line, data, size);
    line[size] = '\0';

    TargetSet targetset;
    memset(&targetset, 0, sizeof(targetset));

    (void)targetset_add_ip_str(&targetset, line);
    (void)targetset_add_port_str(&targetset, line, 0);
    targetset_rm_all(&targetset);

    free(line);
    return 0;
}
