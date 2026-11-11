#ifndef OUTPUT_WRITE_H
#define OUTPUT_WRITE_H
#include <stdio.h>
#include <stdbool.h>
int  out_fprintf(FILE *fp, const char *fmt, ...);
int  out_fputc(int c, FILE *fp);
size_t out_fwrite(const void *ptr, size_t size, size_t n, FILE *fp);
bool output_failed(void);
#endif
