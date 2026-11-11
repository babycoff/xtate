#include "control-plane.h"
#include "job-manager.h"
#include "../crypto/crypto-json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

static const char *g_token = NULL;

static bool token_ok(const char *line) {
    if (!g_token || !g_token[0]) return true;
    const char *p = strstr(line, "\"token\"");
    if (!p) return false;
    p += 7;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return false;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return false;
    p++;
    size_t n = strlen(g_token);
    return strncmp(p, g_token, n) == 0 && p[n] == '"';
}

static const char *field_str(const char *s, const char *key, char *out,
                             size_t cap) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(s, pat);
    if (!p) return NULL;
    p += strlen(pat); while (*p == ' ') p++;
    if (*p != '"') return NULL;
    p++; size_t n = 0;
    while (p[n] && p[n] != '"' && n + 1 < cap) { out[n] = p[n]; n++; }
    out[n] = 0;
    return out;
}

static int64_t field_int(const char *s, const char *key, int64_t def) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(s, pat);
    if (!p) return def;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') p++;
    return atoll(p);
}

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
    bool   overflow;
} ControlResponse;

static void resp_printf(ControlResponse *r, const char *fmt, ...) {
    if (r->overflow || r->len + 1 >= r->cap) { r->overflow = true; return; }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(r->data + r->len, r->cap - r->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= r->cap - r->len) {
        r->overflow = true;
        return;
    }
    r->len += (size_t)n;
}

static void send_json(ControlResponse *out, const char *id, const char *result,
                      const char *code, const char *msg) {
    if (code) {
        char *esc = json_encode_string(msg ? msg : "");
        resp_printf(out, "{\"id\":%s,\"error\":{\"code\":\"%s\","
                         "\"message\":%s,\"retryable\":false}}\n",
                    id, code, esc ? esc : "\"\"");
        free(esc);
    } else {
        resp_printf(out, "{\"id\":%s,\"result\":%s}\n", id, result);
    }
}

static void handle(JobManager *m, const char *line, ControlResponse *out) {
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
    if (!token_ok(line)) {
        send_json(out, id, NULL, "UNAUTHORIZED", "invalid or missing token");
        return;
    }
    if (strstr(line, "\"ping\"")) {
        send_json(out, id, "{\"pong\":true}", NULL, NULL);
        return;
    }
    if (strstr(line, "\"job.start\"")) {
        char req[512], res[512];
        if (!field_str(line, "request_path", req, sizeof(req)) ||
            !field_str(line, "result_path", res, sizeof(res))) {
            send_json(out, id, NULL, "INVALID_ARGUMENT", "request_path and result_path required");
            return;
        }
#ifdef _WIN32
        char exe[MAX_PATH];
        GetModuleFileNameA(NULL, exe, sizeof(exe));
#else
        char exe[512];
        ssize_t el = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (el <= 0) { send_json(out, id, NULL, "INTERNAL_ERROR", "cannot find executable"); return; }
        exe[el] = 0;
#endif
        char hb[600]; snprintf(hb, sizeof(hb), "%s.heartbeat", res);
        char hbarg[600]; snprintf(hbarg, sizeof(hbarg), "--job-heartbeat=%s", hb);
        char *argv[] = {exe, "--scan-request", req, "--output-module", "ndjson",
                        "--output-file", res, "--show", "all", "--wait", "1",
                        "--no-status", hbarg, NULL};
        job_manager_lock(m);
        Job *j = job_start(m, argv, res, NULL, 0);
        if (j) job_set_heartbeat(j, hb, 30);
        job_manager_unlock(m);
        if (!j) { send_json(out, id, NULL, "JOB_LIMIT_REACHED", "too many jobs"); return; }
        char r[128]; snprintf(r, sizeof(r), "{\"job_id\":\"%s\"}", job_id(j));
        send_json(out, id, r, NULL, NULL);
        return;
    }
    if (strstr(line, "\"job.list\"")) {
        int64_t offset = field_int(line, "offset", 0);
        int64_t limit  = field_int(line, "limit", 100);
        if (offset < 0) offset = 0;
        if (limit < 1 || limit > 1000) limit = 100;
        size_t total = 0;
        job_manager_lock(m);
        for (Job *j = job_first(m); j; j = job_next(j)) total++;
        char buf[32768]; size_t off = 0;
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "{\"jobs\":[");
        size_t idx = 0, emitted = 0;
        int first = 1;
        for (Job *j = job_first(m); j; j = job_next(j), idx++) {
            if ((int64_t)idx < offset) continue;
            if ((int64_t)emitted >= limit) break;
            job_poll(j);
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "%s{\"job_id\":\"%s\",\"state\":\"%s\",\"result\":\"%s\"}",
                first ? "" : ",", job_id(j), job_state_string(job_state(j)),
                job_result_path(j) ? job_result_path(j) : "");
            first = 0; emitted++;
            if (off > sizeof(buf) - 512) break;
        }
        job_manager_unlock(m);
        snprintf(buf + off, sizeof(buf) - off,
                 "],\"offset\":%lld,\"limit\":%lld,\"next_offset\":%lld,"
                 "\"truncated\":%s,\"total\":%zu}",
                 (long long)offset, (long long)limit,
                 (long long)(offset + (int64_t)emitted),
                 (offset + (int64_t)emitted) < (int64_t)total ? "true" : "false",
                 total);
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
    if (strstr(line, "\"job.results\"") ||
        strstr(line, "\"job.result_manifest\"")) {
        char *path = json_encode_string(job_result_path(j) ? job_result_path(j) : "");
        char manifest_path[1200];
        snprintf(manifest_path, sizeof(manifest_path), "%s.manifest.json",
                 job_result_path(j) ? job_result_path(j) : "");
        char *mpath = json_encode_string(manifest_path);
        char res[1600];
        snprintf(res, sizeof(res),
                 "{\"job_id\":\"%s\",\"state\":\"%s\","
                 "\"result_path\":%s,\"manifest_path\":%s,"
                 "\"result_bytes\":%llu,\"complete\":%s}",
                 jidbuf, job_state_string(job_state(j)), path ? path : "\"\"",
                 mpath ? mpath : "\"\"",
                 (unsigned long long)job_result_bytes(j),
                 job_is_terminal(j) ? "true" : "false");
        free(path); free(mpath);
        job_manager_unlock(m);
        send_json(out, id, res, NULL, NULL);
        return;
    }

    char phase[32] = "unknown";
    uint64_t sent = 0, targets = 0, hb_age = 0;
    bool hb = job_heartbeat_info(j, phase, sizeof(phase), &sent, &targets, &hb_age);
    char res[768];
    snprintf(res, sizeof(res),
             "{\"job_id\":\"%s\",\"state\":\"%s\",\"phase\":\"%s\","
             "\"sent\":%llu,\"targets\":%llu,\"heartbeat_age_ms\":%llu,"
             "\"heartbeat\":%s,\"exit_code\":%u,"
             "\"result\":\"%s\",\"elapsed_ms\":%u}",
             job_id(j), job_state_string(job_state(j)), phase,
             (unsigned long long)sent, (unsigned long long)targets,
             (unsigned long long)hb_age, hb ? "true" : "false",
             job_exit_code(j), job_result_path(j) ? job_result_path(j) : "",
             job_elapsed_ms(j));
    job_manager_unlock(m);
    send_json(out, id, res, NULL, NULL);
}

#ifndef _WIN32
int control_plane_serve(const char *endpoint) {
    g_token = getenv("XTATE_CONTROL_TOKEN");
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
        if (!in) { close(c); continue; }
        char line[8192];
        while (fgets(line, sizeof(line), in)) {
            char data[65536];
            ControlResponse out = {data, 0, sizeof(data), false};
            handle(m, line, &out);
            if (out.overflow) {
                snprintf(data, sizeof(data),
                         "{\"id\":null,\"error\":{\"code\":\"RESPONSE_TOO_LARGE\","
                         "\"message\":\"use paging\",\"retryable\":false}}\n");
                out.len = strlen(data);
            }
            size_t sent = 0;
            while (sent < out.len) {
                ssize_t n = write(c, data + sent, out.len - sent);
                if (n <= 0) break;
                sent += (size_t)n;
            }
        }
        fclose(in);
    }
    close(fd); unlink(endpoint); job_manager_destroy(m);
    return 0;
}
#else
int control_plane_serve(const char *endpoint) {
    g_token = getenv("XTATE_CONTROL_TOKEN");
    g_token = getenv("XTATE_CONTROL_TOKEN");
    JobManager *m = job_manager_create(16);
    for (;;) {
        HANDLE p = CreateNamedPipeA(endpoint, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 65536, 65536, 0, NULL);
        if (p == INVALID_HANDLE_VALUE) break;
        if (!ConnectNamedPipe(p, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(p); continue;
        }
        char buf[8192];
        DWORD got = 0;
        while (ReadFile(p, buf, sizeof(buf)-1, &got, NULL) && got) {
            buf[got] = 0;
            char data[65536];
            ControlResponse out = {data, 0, sizeof(data), false};
            handle(m, buf, &out);
            if (out.overflow) {
                snprintf(data, sizeof(data),
                         "{\"id\":null,\"error\":{\"code\":\"RESPONSE_TOO_LARGE\","
                         "\"message\":\"use paging\",\"retryable\":false}}\n");
                out.len = strlen(data);
            }
            DWORD wrote = 0;
            WriteFile(p, data, (DWORD)out.len, &wrote, NULL);
            got = 0;
        }
        DisconnectNamedPipe(p);
        CloseHandle(p);
    }
    job_manager_destroy(m);
    return 0;
}
#endif
