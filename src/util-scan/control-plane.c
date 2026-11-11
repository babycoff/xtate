#include "control-plane.h"
#include "job-manager.h"
#include "result-store.h"
#include "../util-out/logger.h"
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
#include <pthread.h>
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

static const char *field_str2(const char *s, const char *key) {
    static char buf[64];
    return field_str(s, key, buf, sizeof(buf));
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

static void finalize_job(Job *j) {
    if (!j || !job_is_terminal(j) || job_result_finalized(j)) return;
    const char *result = job_result_path(j);
    uint64_t quota = job_result_quota(j);
    if (result && quota && job_result_bytes(j) > quota) {
        LOG(LEVEL_WARN, "job %s result %llu exceeds quota %llu; chunks will be incomplete\n",
            job_id(j), (unsigned long long)job_result_bytes(j),
            (unsigned long long)quota);
    }
    if (result && job_result_chunk_bytes(j)) {
        result_store_build(result, job_result_chunk_bytes(j),
                           job_result_index_enabled(j),
                           job_result_compression(j));
    }
    job_mark_result_finalized(j);
}

static void maintenance(JobManager *m) {
    job_manager_lock(m);
    for (Job *j = job_first(m); j; j = job_next(j)) {
        job_poll(j);
        finalize_job(j);
    }
    job_manager_prune(m);
    job_manager_unlock(m);
}

#ifndef _WIN32
static void *maintenance_thread(void *arg) {
    JobManager *m = (JobManager *)arg;
    for (;;) {
        maintenance(m);
        usleep(500000);
    }
    return NULL;
}
#else
static DWORD WINAPI maintenance_thread(LPVOID arg) {
    JobManager *m = (JobManager *)arg;
    for (;;) { maintenance(m); Sleep(500); }
    return 0;
}
#endif

static bool extract_object(const char *line, const char *key, char *out,
                           size_t cap) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(line, pat);
    if (!p) return false;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '{') return false;
    int depth = 0; bool in_str = false, esc = false; size_t n = 0;
    for (; *p; p++) {
        char c = *p;
        if (n + 1 < cap) out[n++] = c;
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
        } else {
            if (c == '"') in_str = true;
            else if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) break; }
        }
    }
    out[n] = 0;
    return depth == 0 && n > 1;
}

static void json_unescape_inplace(char *s) {
    char *w = s;
    for (const char *r = s; *r; r++) {
        if (*r == '\\' && r[1]) {
            r++;
            if (*r == 'n') *w++ = '\n';
            else if (*r == 'r') *w++ = '\r';
            else if (*r == 't') *w++ = '\t';
            else if (*r == 'u' && r[1] && r[2] && r[3] && r[4]) {
                unsigned cp = 0;
                for (int i = 0; i < 4; i++) {
                    char c = r[1 + i];
                    cp <<= 4;
                    if (c >= '0' && c <= '9') cp |= (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') cp |= (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') cp |= (unsigned)(c - 'A' + 10);
                    else { cp = 0; break; }
                }
                r += 4;
                if (cp < 0x80) *w++ = (char)cp;
                else if (cp < 0x800) {
                    *w++ = (char)(0xC0 | (cp >> 6));
                    *w++ = (char)(0x80 | (cp & 0x3F));
                } else {
                    *w++ = (char)(0xE0 | (cp >> 12));
                    *w++ = (char)(0x80 | ((cp >> 6) & 0x3F));
                    *w++ = (char)(0x80 | (cp & 0x3F));
                }
            }
            else *w++ = *r;
        } else *w++ = *r;
    }
    *w = 0;
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
        char req[600], res[600], params[16384];
        if (extract_object(line, "params", params, sizeof(params))) {
            const char *tmpdir = getenv("TMPDIR");
#ifdef _WIN32
            if (!tmpdir || !tmpdir[0]) tmpdir = getenv("TEMP");
#endif
            if (!tmpdir || !tmpdir[0]) tmpdir = "/tmp";
            snprintf(req, sizeof(req), "%s/xtate-job-%lld.request.json",
                     tmpdir, (long long)time(NULL));
            FILE *rf = fopen(req, "wb");
            if (!rf) {
                snprintf(req, sizeof(req), "xtate-job-%lld.request.json",
                         (long long)time(NULL));
                rf = fopen(req, "wb");
            }
            if (!rf) { send_json(out, id, NULL, "IO_ERROR", "cannot write request"); return; }
            fwrite(params, 1, strlen(params), rf);
            fclose(rf);
        } else if (!field_str(line, "request_path", req, sizeof(req))) {
            send_json(out, id, NULL, "INVALID_ARGUMENT", "params or request_path required");
            return;
        }
        if (!field_str(line, "result_path", res, sizeof(res))) {
            snprintf(res, sizeof(res), "xtate-job-%lld.ndjson", (long long)time(NULL));
        }
        json_unescape_inplace(res);
#ifdef _WIN32
        char exe[MAX_PATH * 4];
        wchar_t wexe[MAX_PATH];
        DWORD wn = GetModuleFileNameW(NULL, wexe, MAX_PATH);
        if (wn == 0) { send_json(out, id, NULL, "INTERNAL_ERROR", "cannot find executable"); return; }
        WideCharToMultiByte(CP_UTF8, 0, wexe, -1, exe, sizeof(exe), NULL, NULL);
#else
        char exe[512];
        ssize_t el = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (el <= 0) { send_json(out, id, NULL, "INTERNAL_ERROR", "cannot find executable"); return; }
        exe[el] = 0;
#endif
        char hb[600]; snprintf(hb, sizeof(hb), "%s.heartbeat", res);
        char hbarg[600]; snprintf(hbarg, sizeof(hbarg), "--job-heartbeat=%s", hb);
        uint64_t quota = (uint64_t)field_int(line, "quota_bytes", 0);
        char quotarg[64] = {0};
        if (quota) snprintf(quotarg, sizeof(quotarg), "--result-quota=%llu",
                            (unsigned long long)quota);
        char iface[256] = {0};
        bool has_iface = field_str(line, "interface", iface, sizeof(iface)) != NULL;
        if (has_iface) json_unescape_inplace(iface);

        char *argv[20];
        int ac = 0;
        argv[ac++] = exe; argv[ac++] = "--scan-request"; argv[ac++] = req;
        argv[ac++] = "--output-module"; argv[ac++] = "ndjson";
        argv[ac++] = "--output-file"; argv[ac++] = res;
        argv[ac++] = "--show"; argv[ac++] = "all";
        argv[ac++] = "--wait"; argv[ac++] = "1";
        argv[ac++] = "--no-status"; argv[ac++] = hbarg;
        if (quota) argv[ac++] = quotarg;
        if (has_iface) { argv[ac++] = "-if"; argv[ac++] = iface; }
        argv[ac] = NULL;
        job_manager_lock(m);
        char logpath[1100];
        snprintf(logpath, sizeof(logpath), "%s.log", res);
        Job *j = job_start(m, argv, res, logpath, 0);
        if (j) {
            job_set_heartbeat(j, hb, 30);
            job_set_result_config(j, (uint64_t)field_int(line, "chunk_size", 0),
                                  strstr(line, "\"index\":true") != NULL,
                                  field_str2(line, "compression"),
                                  (uint64_t)field_int(line, "quota_bytes", 0));
        }
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
            finalize_job(j);
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
    if (*jid == '"') jid++;
    char jidbuf[64]; size_t jn = 0;
    while (jid[jn] && jid[jn] != '"' && jn < sizeof(jidbuf)-1) { jidbuf[jn] = jid[jn]; jn++; }
    jidbuf[jn] = 0;
    job_manager_lock(m);
    Job *j = job_find(m, jidbuf);
    if (!j) { job_manager_unlock(m); send_json(out, id, NULL, "JOB_NOT_FOUND", "unknown job"); return; }
    job_poll(j);
    finalize_job(j);
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
#ifndef _WIN32
    pthread_t mt;
    pthread_create(&mt, NULL, maintenance_thread, m);
#endif
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
    CreateThread(NULL, 0, maintenance_thread, m, 0, NULL);
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
