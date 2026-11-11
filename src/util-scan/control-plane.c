#include "control-plane.h"
#include "job-manager.h"
#include "../crypto/crypto-json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

static int64_t field_int(const char *s, const char *key, int64_t def) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(s, pat);
    if (!p) return def;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') p++;
    return atoll(p);
}

static void send_json(FILE *out, const char *id, const char *result,
                      const char *code, const char *msg) {
    if (code) {
        char *esc = json_encode_string(msg ? msg : "");
        fprintf(out, "{\"id\":%s,\"error\":{\"code\":\"%s\",\"message\":%s,"
                     "\"retryable\":false}}\n", id, code, esc ? esc : "\"\"");
        free(esc);
    } else {
        fprintf(out, "{\"id\":%s,\"result\":%s}\n", id, result);
    }
    fflush(out);
}

static void handle(JobManager *m, const char *line, FILE *out) {
    char id[32] = "null";
    const char *p = strstr(line, "\"id\":");
    if (p) {
        p += 5; while (*p == ' ') p++;
        size_t n = 0;
        while (p[n] && p[n] != ',' && p[n] != '}' && n < sizeof(id)-1) {
            id[n] = p[n]; n++;
        }
        id[n] = 0;
    }
    if (strstr(line, "\"ping\"")) {
        send_json(out, id, "{\"pong\":true}", NULL, NULL);
        return;
    }
    if (strstr(line, "\"job.list\"")) {
        char buf[4096]; size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "{\"jobs\":[");
        job_manager_lock(m);
        int first = 1;
        for (Job *j = job_first(m); j; j = job_next(j)) {
            job_poll(j);
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "%s{\"job_id\":\"%s\",\"state\":\"%s\",\"result\":\"%s\"}",
                first ? "" : ",", job_id(j), job_state_string(job_state(j)),
                job_result_path(j) ? job_result_path(j) : "");
            first = 0;
            if (off > sizeof(buf) - 256) break;
        }
        job_manager_unlock(m);
        snprintf(buf + off, sizeof(buf) - off, "]}");
        send_json(out, id, buf, NULL, NULL);
        return;
    }
    const char *jid = strstr(line, "\"job_id\":");
    if (!jid) { send_json(out, id, NULL, "INVALID_ARGUMENT", "missing job_id"); return; }
    jid += 9; while (*jid == ' ') jid++;
    char jidbuf[64]; size_t jn = 0;
    while (jid[jn] && jid[jn] != '"' && jn < sizeof(jidbuf)-1) { jidbuf[jn] = jid[jn]; jn++; }
    jidbuf[jn] = 0;
    job_manager_lock(m);
    Job *j = job_find(m, jidbuf);
    if (!j) { job_manager_unlock(m); send_json(out, id, NULL, "JOB_NOT_FOUND", "unknown job"); return; }
    job_poll(j);
    if (strstr(line, "\"job.cancel\"")) {
        bool ok = job_cancel(j);
        job_manager_unlock(m);
        send_json(out, id, ok ? "{\"cancelled\":true}" : "{\"cancelled\":false}", NULL, NULL);
        return;
    }
    if (strstr(line, "\"job.results\"")) {
        int64_t off = field_int(line, "offset", 0);
        int64_t cap = field_int(line, "max_bytes", 65536);
        if (cap < 1 || cap > 1048576) cap = 65536;
        char *data = malloc((size_t)cap + 1);
        uint64_t next = 0; bool trunc = false;
        uint64_t n = data ? job_read_results(j, (uint64_t)off, data, (size_t)cap + 1,
                                             &next, &trunc) : 0;
        char *esc = json_encode_string(data ? data : "");
        char res[128];
        snprintf(res, sizeof(res), "{\"job_id\":\"%s\",\"next_offset\":%llu,"
                                   "\"truncated\":%s,\"data\":",
                 jidbuf, (unsigned long long)next, trunc ? "true" : "false");
        job_manager_unlock(m);
        fprintf(out, "{\"id\":%s,\"result\":%s%s}}\n", id, res, esc ? esc : "\"\"");
        fflush(out); free(esc); free(data);
        return;
    }
    char res[512];
    snprintf(res, sizeof(res),
             "{\"job_id\":\"%s\",\"state\":\"%s\",\"exit_code\":%u,"
             "\"result\":\"%s\",\"elapsed_ms\":%u}",
             job_id(j), job_state_string(job_state(j)), job_exit_code(j),
             job_result_path(j) ? job_result_path(j) : "", job_elapsed_ms(j));
    job_manager_unlock(m);
    send_json(out, id, res, NULL, NULL);
}

#ifndef _WIN32
int control_plane_serve(const char *endpoint) {
    JobManager *m = job_manager_create(16);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", endpoint);
    unlink(endpoint);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return 1; }
    listen(fd, 4);
    for (;;) {
        int c = accept(fd, NULL, NULL);
        if (c < 0) break;
        FILE *in = fdopen(c, "r");
        FILE *out = fdopen(dup(c), "w");
        if (!in || !out) { close(c); continue; }
        char line[8192];
        while (fgets(line, sizeof(line), in)) handle(m, line, out);
        fclose(in); fclose(out);
    }
    close(fd); unlink(endpoint); job_manager_destroy(m);
    return 0;
}
#else
int control_plane_serve(const char *endpoint) {
    JobManager *m = job_manager_create(16);
    for (;;) {
        HANDLE p = CreateNamedPipeA(endpoint, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 65536, 65536, 0, NULL);
        if (p == INVALID_HANDLE_VALUE) break;
        if (!ConnectNamedPipe(p, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(p); continue;
        }
        char buf[8192];
        DWORD got = 0;
        while (ReadFile(p, buf, sizeof(buf)-1, &got, NULL) && got) {
            buf[got] = 0;
            FILE *out = tmpfile();
            handle(m, buf, out);
            if (out) {
                fflush(out); rewind(out);
                char resp[8192]; size_t rn = fread(resp, 1, sizeof(resp), out);
                DWORD wrote = 0;
                WriteFile(p, resp, (DWORD)rn, &wrote, NULL);
                fclose(out);
            }
            got = 0;
        }
        DisconnectNamedPipe(p);
        CloseHandle(p);
    }
    job_manager_destroy(m);
    return 0;
}
#endif
