#include "heartbeat.h"
#include "../util-data/file-open.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

void heartbeat_write(const char *path, uint64_t sent, uint64_t targets,
                     uint64_t success, uint64_t failed, uint64_t info,
                     const char *phase) {
    if (!path || !path[0]) return;
    char tmp[1200];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *fp = file_open_utf8_mode(tmp, "w");
    if (!fp) return;
    fprintf(fp, "time=%lld\nsent=%llu\ntargets=%llu\nsuccess=%llu\n"
                "failed=%llu\ninfo=%llu\nphase=%s\n",
            (long long)time(NULL), (unsigned long long)sent,
            (unsigned long long)targets, (unsigned long long)success,
            (unsigned long long)failed, (unsigned long long)info,
            phase ? phase : "tx");
    fflush(fp);
    fclose(fp);
#ifdef _WIN32
    {
        wchar_t wtmp[1200], wpath[1200];
        if (MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wtmp,
                (int)(sizeof(wtmp) / sizeof(wtmp[0]))) > 0 &&
            MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
                (int)(sizeof(wpath) / sizeof(wpath[0]))) > 0)
            MoveFileExW(wtmp, wpath, MOVEFILE_REPLACE_EXISTING);
    }
#else
    rename(tmp, path);
#endif
}
