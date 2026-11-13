#ifndef XTATE_FILE_OPEN_H
#define XTATE_FILE_OPEN_H
#include <stdio.h>

/*
 * Open a path stored as UTF-8.  On Windows the CRT narrow fopen() uses the
 * active ANSI code page, so user-controlled paths go through _wfopen().
 */
FILE *file_open_utf8_mode(const char *path, const char *mode);

/* Convenience: open a UTF-8 path for binary reading. */
FILE *file_open_utf8(const char *path);

#endif
