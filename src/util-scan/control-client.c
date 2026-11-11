#include "control-client.h"
#include <stdio.h>
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
    HANDLE p = CreateFileA(endpoint, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (p == INVALID_HANDLE_VALUE) return -1;
    DWORD wrote = 0;
    if (!WriteFile(p, request, (DWORD)strlen(request), &wrote, NULL)) {
        CloseHandle(p); return -1;
    }
    DWORD got = 0;
    if (!ReadFile(p, response, (DWORD)cap - 1, &got, NULL)) {
        CloseHandle(p); return -1;
    }
    response[got] = 0;
    CloseHandle(p);
    return (int)got;
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
    if (send(fd, request, len, 0) != (ssize_t)len) {
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
