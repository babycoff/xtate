#include "control-client.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

int control_client_request(const char *endpoint, const char *request,
                           char *response, size_t cap) {
    if (!endpoint || !request || !response || cap == 0) return -1;
#ifdef _WIN32
    wchar_t wpath[1024];
    if (MultiByteToWideChar(CP_UTF8, 0, endpoint, -1, wpath, 1024) <= 0) return -1;
    HANDLE p = CreateFileW(wpath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (p == INVALID_HANDLE_VALUE) {
        return -1;
    }
    size_t reqlen = strlen(request);
    bool add_nl = reqlen == 0 || request[reqlen - 1] != '\n';
    size_t sent = 0;
    while (sent < reqlen) {
        DWORD wrote = 0;
        DWORD want = (DWORD)(reqlen - sent);
        if (!WriteFile(p, request + sent, want, &wrote, NULL) || wrote == 0) {
            CloseHandle(p); return -1;
        }
        sent += wrote;
    }
    if (add_nl) {
        DWORD wrote = 0;
        if (!WriteFile(p, "\n", 1, &wrote, NULL) || wrote != 1) {
            CloseHandle(p); return -1;
        }
    }
    size_t total = 0;
    while (total + 1 < cap) {
        DWORD got = 0;
        DWORD want = (DWORD)(cap - 1 - total);
        if (!ReadFile(p, response + total, want, &got, NULL) || got == 0) break;
        total += got;
        if (memchr(response, '\n', total)) break;
    }
    response[total] = 0;
    CloseHandle(p);
    return (int)total;
#else
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", endpoint);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd); return -1;
    }
    size_t len = strlen(request);
    bool add_nl = len == 0 || request[len - 1] != '\n';
    if (send(fd, request, len, 0) != (ssize_t)len) {
        close(fd); return -1;
    }
    if (add_nl && send(fd, "\n", 1, 0) != 1) {
        close(fd); return -1;
    }
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = recv(fd, response + n, cap - 1 - n, 0);
        if (r <= 0) break;
        n += (size_t)r;
        if (memchr(response, '\n', n)) break;
    }
    response[n] = 0;
    close(fd);
    return (int)n;
#endif
}
