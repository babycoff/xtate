/*
 * libFuzzer harness for target-file parsing.
 *
 * Writes one fuzzer input to a temporary file and calls
 * targetset_parse_file(), which is the line-oriented file/tokenizer path.
 */
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "target/target-set.h"
#include "target/target-parse.h"
#include "target/target-rangev4.h"
#include "target/target-rangev6.h"
#include "as/as-query.h"

void LOG(int level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}

void xcmd_try_reboot(void) {
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096)
        return 0;

    char path[] = "/tmp/xtate-target-fuzz-XXXXXX";
    int  fd     = mkstemp(path);
    if (fd < 0)
        return 0;

    if (size > 0) {
        const uint8_t *p = data;
        size_t         left = size;
        while (left > 0) {
            ssize_t n = write(fd, p, left);
            if (n <= 0)
                break;
            p += (size_t)n;
            left -= (size_t)n;
        }
    }
    close(fd);

    TargetSet targetset;
    memset(&targetset, 0, sizeof(targetset));
    (void)targetset_parse_file(&targetset, path);
    targetset_rm_all(&targetset);
    unlink(path);
    return 0;
}
