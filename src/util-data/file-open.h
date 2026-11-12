#ifndef XTATE_FILE_OPEN_H
#define XTATE_FILE_OPEN_H
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
static inline FILE *file_open_utf8(const char *path) {
    wchar_t wpath[2048];
    if (!path || MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
            (int)(sizeof(wpath)/sizeof(wpath[0]))) <= 0) return NULL;
    return _wfopen(wpath, L"rb");
}
#else
static inline FILE *file_open_utf8(const char *path) { return fopen(path, "rb"); }
#endif
#endif
