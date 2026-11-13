#include "ui-control.h"
#include "control-client.h"
#include "../crypto/crypto-json.h"
#include "../util-misc/secure-random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

#define UI_PING_ATTEMPTS 60
#define UI_PING_WAIT_MS 100

/*
 * A UI-started control plane is a private child of this process.  When the
 * caller did not configure a token, generate an ephemeral one so other local
 * accounts cannot drive the pipe/socket.  The parent and child share it
 * through the environment; explicit --control-plane servers are unchanged.
 */
static int g_generated_token;

static int ensure_private_token(void) {
    const char *existing = getenv("XTATE_CONTROL_TOKEN");
    unsigned char raw[16];
    char token[33];
    int i;

    if (existing && existing[0]) return 0;
    if (secure_random_bytes(raw, sizeof(raw)) != 1) return -1;
    for (i = 0; i < (int)sizeof(raw); i++)
        snprintf(token + i * 2, sizeof(token) - (size_t)i * 2, "%02x", raw[i]);
#ifdef _WIN32
    /* _putenv_s updates both the CRT environment used by getenv() and the
     * Win32 environment block inherited by CreateProcessW. */
    if (_putenv_s("XTATE_CONTROL_TOKEN", token) != 0) return -1;
#else
    if (setenv("XTATE_CONTROL_TOKEN", token, 1) != 0) return -1;
#endif
    g_generated_token = 1;
    return 0;
}

static void clear_private_token(void) {
    if (!g_generated_token) return;
#ifdef _WIN32
    _putenv_s("XTATE_CONTROL_TOKEN", "");
#else
    unsetenv("XTATE_CONTROL_TOKEN");
#endif
    g_generated_token = 0;
}

#ifdef _WIN32
static HANDLE g_process = NULL;
static HANDLE g_thread  = NULL;
static HANDLE g_job     = NULL;

static int utf8_to_wide(const char *src, wchar_t *dst, int dst_count) {
    if (!src || !dst || dst_count <= 0) return -1;
    return MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dst_count);
}

static char *ping_request(void) {
    JsonNode *root = json_mkobject();
    const char *token = getenv("XTATE_CONTROL_TOKEN");
    if (!root) return NULL;
    json_append_member(root, "id", json_mknumber(1));
    json_append_member(root, "method", json_mkstring("ping"));
    if (token && token[0]) json_append_member(root, "token", json_mkstring(token));
    char *text = json_stringify(root, NULL);
    json_delete(root);
    return text;
}
#else
static pid_t g_child = -1;
static char g_endpoint[256];

static char *ping_request(void) {
    JsonNode *root = json_mkobject();
    const char *token = getenv("XTATE_CONTROL_TOKEN");
    if (!root) return NULL;
    json_append_member(root, "id", json_mknumber(1));
    json_append_member(root, "method", json_mkstring("ping"));
    if (token && token[0]) json_append_member(root, "token", json_mkstring(token));
    char *text = json_stringify(root, NULL);
    json_delete(root);
    return text;
}
#endif

static int ping_ready(const char *endpoint, const char *request) {
    char response[4096];
    int n;
    if (!request) return -1;
    n = control_client_request(endpoint, request, response, sizeof(response));
    if (n <= 0) return -1;
    if (!strstr(response, "\"result\"")) return -1;
    return 0;
}

#ifdef _WIN32
int ui_control_start(const char *exe_path, char *endpoint, size_t endpoint_size) {
    wchar_t wexe[32768];
    wchar_t wendpoint[512];
    wchar_t wcmd[65536];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    char *request = NULL;
    DWORD pid;
    ULONGLONG tick;
    int i;

    (void)exe_path;
    if (!endpoint || endpoint_size < 64) return -1;
    if (g_process) return -1;
    if (ensure_private_token() != 0) return -1;

    if (GetModuleFileNameW(NULL, wexe, (DWORD)(sizeof(wexe) / sizeof(wexe[0]))) == 0) {
        clear_private_token();
        return -1;
    }

    pid = GetCurrentProcessId();
    tick = GetTickCount64();
    snprintf(endpoint, endpoint_size, "\\\\.\\pipe\\xtate-ui-%lu-%llu",
             (unsigned long)pid, (unsigned long long)tick);
    if (utf8_to_wide(endpoint, wendpoint,
                     (int)(sizeof(wendpoint) / sizeof(wendpoint[0]))) <= 0) {
        clear_private_token();
        return -1;
    }
    if (swprintf(wcmd, sizeof(wcmd) / sizeof(wcmd[0]),
                 L"\"%ls\" --control-plane=%ls", wexe, wendpoint) < 0) {
        clear_private_token();
        return -1;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(wexe, wcmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                        NULL, NULL, &si, &pi)) {
        clear_private_token();
        return -1;
    }

    g_process = pi.hProcess;
    g_thread  = pi.hThread;

    g_job = CreateJobObjectW(NULL, NULL);
    if (g_job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION li;
        ZeroMemory(&li, sizeof(li));
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(g_job, JobObjectExtendedLimitInformation,
                                &li, sizeof(li));
        AssignProcessToJobObject(g_job, g_process);
    }

    request = ping_request();
    for (i = 0; i < UI_PING_ATTEMPTS; i++) {
        if (WaitForSingleObject(g_process, 0) == WAIT_OBJECT_0) break;
        if (ping_ready(endpoint, request) == 0) {
            free(request);
            /* The server disconnects and recreates the pipe between clients. */
            Sleep(100);
            return 0;
        }
        Sleep(UI_PING_WAIT_MS);
    }
    free(request);
    ui_control_stop();
    return -1;
}

void ui_control_stop(void) {
    if (g_job) {
        TerminateJobObject(g_job, 1);
        CloseHandle(g_job);
        g_job = NULL;
    } else if (g_process) {
        TerminateProcess(g_process, 1);
    }
    if (g_process) {
        WaitForSingleObject(g_process, 3000);
        CloseHandle(g_process);
        g_process = NULL;
    }
    if (g_thread) {
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    clear_private_token();
}
#else
int ui_control_start(const char *exe_path, char *endpoint, size_t endpoint_size) {
    char *request = NULL;
    pid_t pid;
    pid_t parent_pid;
    int i;

    if (!exe_path || !exe_path[0] || !endpoint || endpoint_size < 64) return -1;
    if (g_child > 0) return -1;
    if (ensure_private_token() != 0) return -1;

    snprintf(endpoint, endpoint_size, "/tmp/xtate-ui-%lu-%lu.sock",
             (unsigned long)getuid(), (unsigned long)getpid());
    snprintf(g_endpoint, sizeof(g_endpoint), "%s", endpoint);
    unlink(endpoint);

    /* In a container the UI can legitimately be PID 1, so the child's parent
     * PID is 1 too. Compare against the actual parent instead of assuming 1
     * means the parent died. */
    parent_pid = getpid();
    pid = fork();
    if (pid < 0) {
        clear_private_token();
        return -1;
    }
    if (pid == 0) {
        int fd = open("/dev/null", O_RDWR);
        char arg[1100];
        char *args[3];
#ifdef __linux__
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != parent_pid) _exit(127);
#endif
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);
        }
        snprintf(arg, sizeof(arg), "--control-plane=%s", endpoint);
        args[0] = (char *)exe_path;
        args[1] = arg;
        args[2] = NULL;
        /* execvp also resolves a bare "xtate" through PATH. */
        execvp(exe_path, args);
        _exit(127);
    }

    g_child = pid;
    request = ping_request();
    for (i = 0; i < UI_PING_ATTEMPTS; i++) {
        int status = 0;
        if (waitpid(pid, &status, WNOHANG) == pid) break;
        if (ping_ready(endpoint, request) == 0) {
            free(request);
            /* The server unlinks/recreates its socket between clients. */
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 100000000L;
            nanosleep(&ts, NULL);
            return 0;
        }
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = UI_PING_WAIT_MS * 1000000L;
        nanosleep(&ts, NULL);
    }
    free(request);
    ui_control_stop();
    return -1;
}

void ui_control_stop(void) {
    int status;
    int i;
    if (g_child <= 0) {
        clear_private_token();
        return;
    }
    kill(g_child, SIGTERM);
    for (i = 0; i < 30; i++) {
        pid_t r = waitpid(g_child, &status, WNOHANG);
        if (r == g_child) {
            g_child = -1;
            unlink(g_endpoint);
            g_endpoint[0] = 0;
            clear_private_token();
            return;
        }
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 100000000L;
        nanosleep(&ts, NULL);
    }
    kill(g_child, SIGKILL);
    waitpid(g_child, &status, 0);
    unlink(g_endpoint);
    g_endpoint[0] = 0;
    g_child = -1;
    clear_private_token();
}
#endif
