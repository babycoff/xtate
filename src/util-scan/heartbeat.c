#include "heartbeat.h"
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
    FILE *fp = fopen(tmp, "w");
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
    MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING);
#else
    rename(tmp, path);
#endif
}
