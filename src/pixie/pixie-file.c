#include "pixie-file.h"

#if defined(_WIN32)
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#define access _access
#else
#include <unistd.h>
#include <errno.h>
#endif

int pixie_fopen_shareable(FILE **in_fp, const char *filename, bool is_append) {
    FILE *fp;

    *in_fp = NULL;

#if defined(_WIN32)
    /* PORTABILITY: WINDOWS
     *  This bit of code deals with the fact that on Windows, fopen() opens
     *  a file so that it can't be moved. This code opens it a different
     *  way so that we can move it.
     *
     * NOTE: this is probably overkill, it appears that there is a better
     * API _fsopen() that does what I want without all this nonsense.
     */
    {
        HANDLE hFile;
        int    fd;
        DWORD  disposition = is_append ? OPEN_ALWAYS : CREATE_ALWAYS;
        wchar_t wpath[2048];

        /* The normal POSIX C functions lock the file */
        /* int fd = open(filename, O_RDWR | O_CREAT, _S_IREAD | _S_IWRITE); */ /* Fails
                                                                                */
        /* int fd = _sopen(filename, O_RDWR | O_CREAT, _SH_DENYNO, _S_IREAD |
         * _S_IWRITE); */ /* Also fails */

        /* We need to use WINAPI + _open_osfhandle to be able to use
           file descriptors (instead of WINAPI handles) */
        if (!filename ||
            MultiByteToWideChar(CP_UTF8, 0, filename, -1, wpath,
                (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0)
            return -1;
        hFile = CreateFileW(
            wpath, GENERIC_WRITE | (is_append ? FILE_APPEND_DATA : 0),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            disposition, FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return -1;
        }

        /* CREATE_ALWAYS truncates an existing file, which silently breaks
         * append mode. In append mode position the handle at the end. */
        if (is_append) {
            LARGE_INTEGER zero;
            zero.QuadPart = 0;
            if (!SetFilePointerEx(hFile, zero, NULL, FILE_END)) {
                CloseHandle(hFile);
                return -1;
            }
        }

        fd = _open_osfhandle((intptr_t)hFile,
                             _O_CREAT | _O_RDONLY | _O_TEMPORARY |
                                 (is_append ? _O_APPEND : 0));
        if (fd == -1) {
            CloseHandle(hFile);
            return -1;
        }

        fp = _fdopen(fd, is_append ? "a" : "w");
        if (fp == NULL) {
            _close(fd);
            return -1;
        }
    }

#else
    fp = fopen(filename, is_append ? "a" : "w");
    if (fp == NULL)
        return errno;
#endif

    *in_fp = fp;
    return 0;
}
