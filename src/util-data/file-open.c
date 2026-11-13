#include "file-open.h"

#ifdef _WIN32
#include <windows.h>

FILE *file_open_utf8_mode(const char *path, const char *mode) {
    wchar_t wpath[2048];
    wchar_t wmode[16];
    if (!path || !mode) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
            (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0)
        return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode,
            (int)(sizeof(wmode) / sizeof(wmode[0]))) <= 0)
        return NULL;
    return _wfopen(wpath, wmode);
}

FILE *file_open_utf8(const char *path) {
    return file_open_utf8_mode(path, "rb");
}
#else
FILE *file_open_utf8_mode(const char *path, const char *mode) {
    return fopen(path, mode);
}

FILE *file_open_utf8(const char *path) {
    return fopen(path, "rb");
}
#endif
