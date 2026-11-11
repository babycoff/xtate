#include "output-write.h"
#include <stdarg.h>
#include "output-modules.h"

static bool _failed = false;

bool output_failed(void) { return _failed; }

static void fail(void) {
    if (!_failed) {
        _failed = true;
        output_error("Output", "write failed");
    }
}

int out_fprintf(FILE *fp, const char *fmt, ...) {
    if (_failed) return -1;
    va_list ap; va_start(ap, fmt);
    int n = vfprintf(fp, fmt, ap);
    va_end(ap);
    if (n < 0) fail();
    return n;
}
int out_fputc(int c, FILE *fp) {
    if (_failed) return EOF;
    int n = fputc(c, fp);
    if (n == EOF) fail();
    return n;
}
size_t out_fwrite(const void *ptr, size_t size, size_t n, FILE *fp) {
    if (_failed) return 0;
    size_t w = fwrite(ptr, size, n, fp);
    if (w != n) fail();
    return w;
}
