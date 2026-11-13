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
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#endif

static const char *g_token = NULL;
static unsigned long g_name_seq = 0;
static volatile int g_stop;

static unsigned long next_name_seq(void) { return ++g_name_seq; }

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

static bool field_int_checked(const char *s, const char *key, int64_t *out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(s, pat);
    if (!p) return false;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '-' && (*p < '0' || *p > '9')) return false;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(p, &end, 10);
    if (errno || end == p) return false;
    while (*end == ' ' || *end == '\t') end++;
    if (*end != ',' && *end != '}') return false;
    *out = (int64_t)v;
    return true;
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
    while (!g_stop) {
        maintenance(m);
        usleep(500000);
    }
    return NULL;
}
#else
static DWORD WINAPI maintenance_thread(LPVOID arg) {
    JobManager *m = (JobManager *)arg;
    while (!g_stop) { maintenance(m); Sleep(500); }
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

#ifdef _WIN32
static FILE *open_write_utf8(const char *path) {
    wchar_t wpath[2048];
    if (!path || MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
            (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0)
        return NULL;
    return _wfopen(wpath, L"wb");
}
#endif

static int state_dir(char *out, size_t cap) {
#ifdef _WIN32
    wchar_t base[1024];
    wchar_t dir[2048];
    DWORD n;
    {
        wchar_t wdir[2048];
        DWORD wn = GetEnvironmentVariableW(L"XTATE_STATE_DIR", wdir,
                                           (DWORD)(sizeof(wdir) / sizeof(wdir[0])));
        if (wn > 0 && wn < sizeof(wdir) / sizeof(wdir[0])) {
            CreateDirectoryW(wdir, NULL);
            return WideCharToMultiByte(CP_UTF8, 0, wdir, -1, out, (int)cap,
                                       NULL, NULL) > 0;
        }
    }
    n = GetEnvironmentVariableW(L"LOCALAPPDATA", base,
                                (DWORD)(sizeof(base) / sizeof(base[0])));
    if (n == 0 || n >= sizeof(base) / sizeof(base[0])) return 0;
    if (swprintf(dir, sizeof(dir) / sizeof(dir[0]), L"%ls\\xtate", base) < 0)
        return 0;
    CreateDirectoryW(dir, NULL);
    {
        char utf8[2048];
        if (WideCharToMultiByte(CP_UTF8, 0, dir, -1, utf8, sizeof(utf8), NULL, NULL) <= 0)
            return 0;
        return snprintf(out, cap, "%s", utf8) < (int)cap;
    }
#else
    const char *base = getenv("XDG_STATE_HOME");
    char root[1500];
    {
        const char *override = getenv("XTATE_STATE_DIR");
        if (override && override[0]) {
            if (snprintf(out, cap, "%s", override) >= (int)cap) return 0;
            mkdir(out, 0700);
            return 1;
        }
    }
    if (base && base[0]) {
        if (snprintf(root, sizeof(root), "%s", base) >= (int)sizeof(root)) return 0;
    } else {
        const char *home = getenv("HOME");
        if (!home || !home[0]) return 0;
        if (snprintf(root, sizeof(root), "%s/.local/state", home) >= (int)sizeof(root))
            return 0;
        mkdir(root, 0700);
    }
    if (snprintf(out, cap, "%s/xtate", root) >= (int)cap) return 0;
    mkdir(out, 0700);
    return 1;
#endif
}

static int make_state_subdir(char *out, size_t cap, const char *name) {
    char dir[2048];
    if (!state_dir(dir, sizeof(dir))) return 0;
#ifdef _WIN32
    if (snprintf(out, cap, "%s\\%s", dir, name) >= (int)cap) return 0;
    {
        wchar_t wdir[2048];
        if (MultiByteToWideChar(CP_UTF8, 0, out, -1, wdir,
                                (int)(sizeof(wdir) / sizeof(wdir[0]))) <= 0)
            return 0;
        CreateDirectoryW(wdir, NULL);
    }
#else
    if (snprintf(out, cap, "%s/%s", dir, name) >= (int)cap) return 0;
    mkdir(out, 0700);
#endif
    return 1;
}

static int default_result_path(char *out, size_t cap) {
    char dir[2048];
    if (!make_state_subdir(dir, sizeof(dir), "results")) return 0;
#ifdef _WIN32
    return snprintf(out, cap, "%s\\xtate-job-%lld-%lu.ndjson", dir,
                    (long long)time(NULL), next_name_seq()) < (int)cap;
#else
    return snprintf(out, cap, "%s/xtate-job-%lld-%lu.ndjson", dir,
                    (long long)time(NULL), next_name_seq()) < (int)cap;
#endif
}

static void jesc(const char *s, char *out, size_t cap) {
    size_t n = 0;
    if (!out || !cap) return;
    for (; s && *s && n + 2 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { if (n + 3 < cap) { out[n++]='\\'; out[n++]=(char)c; } }
        else if (c == '\n') { out[n++]='\\'; out[n++]='n'; }
        else if (c == '\r') { out[n++]='\\'; out[n++]='r'; }
        else if (c < 0x20) out[n++]=' ';
        else out[n++]=(char)c;
    }
    out[n]=0;
}

static void read_log_tail(const char *path, char *out, size_t cap) {
    out[0] = 0;
    if (!path || !path[0] || cap < 8) return;
#ifdef _WIN32
    wchar_t wpath[2048];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
                            (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0) return;
    FILE *f = _wfopen(wpath, L"rb");
#else
    FILE *f = fopen(path, "rb");
#endif
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) { fclose(f); return; }
    long keep = n > 1024 ? 1024 : n;
    fseek(f, n - keep, SEEK_SET);
    size_t got = fread(out, 1, (size_t)keep, f);
    out[got] = 0;
    fclose(f);
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
        char req[2048], res[2048], params[16384];
        int64_t tmo = 0;
        if (field_int_checked(line, "timeout_sec", &tmo)) {
            if (tmo < 1 || tmo > 86400) {
                send_json(out, id, NULL, "INVALID_ARGUMENT", "timeout_sec must be 1..86400");
                return;
            }
        } else if (strstr(line, "\"timeout_sec\"")) {
            send_json(out, id, NULL, "INVALID_ARGUMENT", "timeout_sec must be an integer");
            return;
        }
        if (extract_object(line, "params", params, sizeof(params))) {
            char reqdir[2048];
            const char *tmpdir = make_state_subdir(reqdir, sizeof(reqdir), "requests")
                                     ? reqdir : getenv("TMPDIR");
#ifdef _WIN32
            if (!tmpdir || !tmpdir[0]) tmpdir = getenv("TEMP");
#endif
            if (!tmpdir || !tmpdir[0]) tmpdir = "/tmp";
#ifndef _WIN32
            int rn = snprintf(req, sizeof(req), "%s/xtate-job-XXXXXX", tmpdir);
            if (rn < 0 || (size_t)rn >= sizeof(req)) {
                send_json(out, id, NULL, "INVALID_ARGUMENT", "request path too long");
                return;
            }
            int rfd = mkstemp(req);
            FILE *rf = rfd >= 0 ? fdopen(rfd, "wb") : NULL;
            if (!rf && rfd >= 0) close(rfd);
#else
            int rn = snprintf(req, sizeof(req), "%s/xtate-job-%lld-%lu.request.json",
                              tmpdir, (long long)time(NULL), next_name_seq());
            if (rn < 0 || (size_t)rn >= sizeof(req)) {
                send_json(out, id, NULL, "INVALID_ARGUMENT", "request path too long");
                return;
            }
            FILE *rf = open_write_utf8(req);
#endif
            if (!rf) { send_json(out, id, NULL, "IO_ERROR", "cannot write request"); return; }
            fwrite(params, 1, strlen(params), rf);
            fclose(rf);
        } else if (!field_str(line, "request_path", req, sizeof(req))) {
            send_json(out, id, NULL, "INVALID_ARGUMENT", "params or request_path required");
            return;
        }
        if (!field_str(line, "result_path", res, sizeof(res))) {
            if (!default_result_path(res, sizeof(res))) {
                send_json(out, id, NULL, "IO_ERROR",
                          "cannot create a result path outside the working directory");
                return;
            }
        } else {
            json_unescape_inplace(res);
        }
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
        char hb[2100]; int hbn = snprintf(hb, sizeof(hb), "%s.heartbeat", res);
        char hbarg[2200];
        int hban = snprintf(hbarg, sizeof(hbarg), "--job-heartbeat=%s", hb);
        if (hbn < 0 || (size_t)hbn >= sizeof(hb) ||
            hban < 0 || (size_t)hban >= sizeof(hbarg)) {
            send_json(out, id, NULL, "INVALID_ARGUMENT", "heartbeat path too long");
            return;
        }
        int64_t quota_i = 0, chunk_i = 0;
        if (field_int_checked(line, "quota_bytes", &quota_i)) {
            if (quota_i < 0) {
                send_json(out, id, NULL, "INVALID_ARGUMENT", "quota_bytes must be >= 0");
                return;
            }
        } else if (strstr(line, "\"quota_bytes\"")) {
            send_json(out, id, NULL, "INVALID_ARGUMENT", "quota_bytes must be an integer");
            return;
        }
        if (field_int_checked(line, "chunk_size", &chunk_i)) {
            if (chunk_i < 1) {
                send_json(out, id, NULL, "INVALID_ARGUMENT", "chunk_size must be > 0");
                return;
            }
        } else if (strstr(line, "\"chunk_size\"")) {
            send_json(out, id, NULL, "INVALID_ARGUMENT", "chunk_size must be an integer");
            return;
        }
        uint64_t quota = (uint64_t)quota_i;
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
        char logpath[2200];
        snprintf(logpath, sizeof(logpath), "%s.log", res);
        unsigned job_timeout = (unsigned)tmo;
        Job *j = job_start(m, argv, res, logpath, job_timeout);
        if (j) {
            job_set_request_path(j, req);
            job_set_heartbeat(j, hb, 30);
            job_set_result_config(j, (uint64_t)chunk_i,
                                  strstr(line, "\"index\":true") != NULL,
                                  field_str2(line, "compression"),
                                  quota);
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
            char jp[2048]; jesc(job_result_path(j), jp, sizeof(jp));
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "%s{\"job_id\":\"%s\",\"state\":\"%s\",\"result\":\"%s\"}",
                first ? "" : ",", job_id(j), job_state_string(job_state(j)), jp);
            first = 0; emitted++;
            if (off > sizeof(buf) - 4096) break;
        }
        job_manager_unlock(m);
        if (off >= sizeof(buf)) off = sizeof(buf) - 1;
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
        char manifest_path[4200];
        snprintf(manifest_path, sizeof(manifest_path), "%s.manifest.json",
                 job_result_path(j) ? job_result_path(j) : "");
        char *mpath = json_encode_string(manifest_path);
        char res[12000];
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
    char res[12000], esres[4200], eslog[4200], eserr[512], tail[1100], estail[1400];
    jesc(job_result_path(j), esres, sizeof(esres));
    jesc(job_log_path(j), eslog, sizeof(eslog));
    jesc(job_error(j), eserr, sizeof(eserr));
    read_log_tail(job_log_path(j), tail, sizeof(tail));
    jesc(tail, estail, sizeof(estail));
    snprintf(res, sizeof(res),
             "{\"job_id\":\"%s\",\"state\":\"%s\",\"phase\":\"%s\","
             "\"sent\":%llu,\"targets\":%llu,\"heartbeat_age_ms\":%llu,"
             "\"heartbeat\":%s,\"exit_code\":%u,"
             "\"result\":\"%s\",\"log_path\":\"%s\",\"error\":\"%s\","
             "\"stderr_tail\":\"%s\",\"elapsed_ms\":%u}",
             job_id(j), job_state_string(job_state(j)), phase,
             (unsigned long long)sent, (unsigned long long)targets,
             (unsigned long long)hb_age, hb ? "true" : "false",
             job_exit_code(j), esres, eslog, eserr, estail,
             job_elapsed_ms(j));
    job_manager_unlock(m);
    send_json(out, id, res, NULL, NULL);
}

#ifndef _WIN32
int control_plane_serve(const char *endpoint) {
    g_token = getenv("XTATE_CONTROL_TOKEN");
    g_stop = 0;
    JobManager *m = job_manager_create(16);
#ifndef _WIN32
    pthread_t mt;
    pthread_create(&mt, NULL, maintenance_thread, m);
#endif
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        g_stop = 1;
#ifndef _WIN32
        pthread_join(mt, NULL);
#endif
        job_manager_destroy(m);
        return 1;
    }
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", endpoint);
    unlink(endpoint);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd); g_stop = 1;
#ifndef _WIN32
        pthread_join(mt, NULL);
#endif
        job_manager_destroy(m);
        return 1;
    }
    chmod(endpoint, 0600);
    signal(SIGPIPE, SIG_IGN);
    listen(fd, 4);
    for (;;) {
        int c = accept(fd, NULL, NULL);
        if (c < 0) break;
        FILE *in = fdopen(c, "r");
        if (!in) { close(c); continue; }
        char line[65536];
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
    close(fd); unlink(endpoint);
    g_stop = 1;
    pthread_join(mt, NULL);
    job_manager_destroy(m);
    return 0;
}
#else
int control_plane_serve(const char *endpoint) {
    g_token = getenv("XTATE_CONTROL_TOKEN");
    g_stop = 0;
    JobManager *m = job_manager_create(16);
    HANDLE mt = CreateThread(NULL, 0, maintenance_thread, m, 0, NULL);
    for (;;) {
        HANDLE p = CreateNamedPipeA(endpoint, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 65536, 65536, 0, NULL);
        if (p == INVALID_HANDLE_VALUE) break;
        if (!ConnectNamedPipe(p, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(p); continue;
        }
        char line[65536];
        size_t used = 0;
        bool dropping = false;
        char buf[8192];
        DWORD got = 0;
        while (ReadFile(p, buf, sizeof(buf), &got, NULL) && got) {
            for (DWORD i = 0; i < got; i++) {
                char ch = buf[i];
                if (ch == '\n') {
                    if (dropping) {
                        const char *msg =
                            "{\"id\":null,\"error\":{\"code\":\"INVALID_ARGUMENT\","
                            "\"message\":\"request line too long\",\"retryable\":false}}\n";
                        DWORD wrote = 0;
                        WriteFile(p, msg, (DWORD)strlen(msg), &wrote, NULL);
                        dropping = false;
                    } else if (used) {
                        line[used] = 0;
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
                            DWORD wrote = 0;
                            DWORD want = (DWORD)(out.len - sent);
                            if (!WriteFile(p, data + sent, want, &wrote, NULL) || wrote == 0)
                                break;
                            sent += wrote;
                        }
                    }
                    used = 0;
                } else if (!dropping) {
                    if (used + 1 < sizeof(line)) line[used++] = ch;
                    else { used = 0; dropping = true; }
                }
            }
        }
        DisconnectNamedPipe(p);
        CloseHandle(p);
    }
    g_stop = 1;
    if (mt) { WaitForSingleObject(mt, 2000); CloseHandle(mt); }
    job_manager_destroy(m);
    return 0;
}
#endif
