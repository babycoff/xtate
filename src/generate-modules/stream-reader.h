#ifndef XTATE_STREAM_READER_H
#define XTATE_STREAM_READER_H
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
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
#endif
