#ifndef XTATE_STREAM_READER_H
#define XTATE_STREAM_READER_H
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
static inline int stream_read_line(FILE *fp, char *buf, size_t cap,
                                   const char *filename, uint64_t *line,
                                   uint64_t *bad, bool *too_long) {
    *too_long = false;
    char *s = fgets(buf, (int)cap, fp);
    if (!s) return -1;
    (*line)++;
    size_t n = strlen(buf);
    if (n == cap - 1 && buf[n - 1] != '\n') {
        int c;
        while ((c = fgetc(fp)) != EOF && c != '\n') {}
        (*bad)++;
        *too_long = true;
        (void)filename;
        return 1;
    }
    return 0;
}
static inline int stream_bad_limit(uint64_t bad, uint64_t lines, bool strict,
                                   uint64_t max_errors, unsigned max_percent,
                                   const char *file, uint64_t line) {
    if (strict || (max_errors && bad >= max_errors) ||
        (max_percent && lines > 0 && bad * 100 > lines * max_percent)) {
        fprintf(stderr, "%s:%llu: too many invalid target lines (aborting)\n",
                file ? file : "<stdin>", (unsigned long long)line);
        return 1;
    }
    return 0;
}
#endif
