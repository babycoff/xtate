#include "mcp-server.h"
#include "control-client.h"
#include "../util-out/module-json.h"
#include "../crypto/crypto-json.h"
#include "../scan-modules/scan-modules.h"
#include "../probe-modules/probe-modules.h"
#include "../rawsock/rawsock.h"
#include "../target/target-parse.h"
#include "../target/target-rangev4.h"
#include "../target/target-rangev6.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#endif
#include "../util-data/file-open.h"
#include "../crypto/crypto-json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>
#ifdef _WIN32
#define strtok_r strtok_s
#endif

static const char *json_id(const char *line) {
    static char id[64];
    const char *p = strstr(line, "\"id\":");
    if (!p) return "null";
    p += 5; while (*p == ' ') p++;
    size_t n = 0;
    while (p[n] && p[n] != ',' && p[n] != '}' && n + 1 < sizeof(id)) {
        id[n] = p[n]; n++;
    }
    id[n] = 0;
    return id;
}

static bool json_str(const char *line, const char *key, char *out, size_t cap) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(line, pat);
    if (!p) return false;
    p += strlen(pat); while (*p == ' ') p++;
    if (*p != '"') return false;
    p++; size_t n = 0;
    while (p[n] && p[n] != '"' && n + 1 < cap) { out[n] = p[n]; n++; }
    out[n] = 0;
    return true;
}

static void emit(const char *json) {
    fputs(json, stdout); fputc('\n', stdout); fflush(stdout);
}

static void text_result(const char *id, const char *text, bool error) {
    char *esc = json_encode_string(text ? text : "");
    printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":%s}],\"isError\":%s}}\n",
           id, esc ? esc : "\"\"", error ? "true" : "false");
    fflush(stdout);
    free(esc);
}

static void rpc_error(const char *id, int code, const char *msg) {
    char *esc = json_encode_string(msg ? msg : "");
    printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":%d,\"message\":%s}}\n",
           id, code, esc ? esc : "\"\"");
    fflush(stdout); free(esc);
}

static const char *instructions =
"Xtate is a modular Internet-scale network scanner. It supports stateless TCP "
"banner scanning, hybrid-state TCP/TLS, HTTP/1.1, HTTP/2 (HPACK/Huffman), "
"HTTP/3 over QUIC, DNS over UDP, DNSSEC evidence, DoT and DoH over HTTP/1.1 "
"and HTTP/2. Scans run as jobs managed by the Xtate control plane.\n\n"
"Safety rules:\n"
"- Only scan targets the user has explicitly authorized.\n"
"- Use job_status/job_list to observe jobs; results are NOT in tool responses. "
"Read job_result_manifest and fetch result chunks from the returned path.\n"
"- On Linux, stateful scans (tcp-state, tls-state, state sub-probes) need the "
"firewall RST/ICMP rules; tcp-syn and UDP do not.\n"
"- Use timeouts or stall timeouts for long jobs; never start unbounded scans.\n"
"- start_scan is enabled only when the caller passes authorized=true for "
"targets it is permitted to scan; every other tool is read-only.\n";

static const char *tools_json =
"{\"tools\":["
"{\"name\":\"list_modules\",\"description\":\"List Xtate scan, probe, output and generate modules with their parameters. Use this before choosing a scanner/probe.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"job_list\",\"description\":\"List managed scan jobs with pagination. Returns job id, state and result path only; use job_result_manifest for result metadata.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"offset\":{\"type\":\"integer\",\"minimum\":0},\"limit\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1000}}},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"job_status\",\"description\":\"Return a job's state, phase, sent/targets progress, success/failed counts, heartbeat age and elapsed time. Does not return result records.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"job_id\":{\"type\":\"string\",\"description\":\"Job id returned by job.start\"}},\"required\":[\"job_id\"]},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"job_result_manifest\",\"description\":\"Return result_path, manifest_path, size and completion for a job. Does not carry result data; read chunks from the manifest path.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"job_id\":{\"type\":\"string\"}},\"required\":[\"job_id\"]},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"job_cancel\",\"description\":\"Request cancellation of a running job. The result file is preserved.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"job_id\":{\"type\":\"string\"}},\"required\":[\"job_id\"]},\"annotations\":{\"readOnlyHint\":false,\"destructiveHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"describe_probe\",\"description\":\"Return module metadata (parameters, probe type, description) for a scan or probe. Use before choosing options.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"description\":\"Module name, e.g. doh-h2\"}},\"required\":[\"name\"]},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"explain_target\",\"description\":\"Describe the interface, source address and route Xtate would use for a target. No packets are sent.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}},\"required\":[\"target\"]},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"check\",\"description\":\"Read-only preflight for a target set: interfaces, sources, gateways and Linux firewall prerequisites.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\",\"description\":\"IP, CIDR, range, or comma-separated set\"}}},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"validate_config\",\"description\":\"Validate a scan-request object (scan, targets, probe, ports, args) before starting a job.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"config\":{\"type\":\"object\",\"description\":\"Scan-request object\"}},\"required\":[\"config\"]},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"start_scan\",\"description\":\"Start a scan job from a closed scan-request object. Returns a job id; results are read via job_result_manifest. Only use with authorized targets.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"arguments\":{\"type\":\"object\",\"description\":\"Scan-request object with scan, targets, optional probe/ports/result_path, timeout_sec, rate and authorized=true\"}},\"required\":[\"arguments\"]},\"annotations\":{\"readOnlyHint\":false,\"destructiveHint\":false,\"openWorldHint\":true}}"
"]}";

static const char *resources_json =
"{\"resources\":["
"{\"uri\":\"xtate://docs/overview\",\"name\":\"Xtate overview\",\"mimeType\":\"text/markdown\"},"
"{\"uri\":\"xtate://docs/firewall\",\"name\":\"Linux firewall prerequisite\",\"mimeType\":\"text/markdown\"},"
"{\"uri\":\"xtate://schemas/scan-request\",\"name\":\"Scan request schema\",\"mimeType\":\"application/json\"}"
"]}";

static const char *prompts_json =
"{\"prompts\":[{\"name\":\"plan-safe-scan\",\"description\":\"Plan a scan with target authorization, protocol choice, timeout and firewall checks.\"}]}";

static bool extract_object(const char *line, const char *key, char *out,
                           size_t cap) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(line, pat);
    if (!p) return false;
    p += strlen(pat); while (*p == ' ' || *p == '\t') p++;
    if (*p != '{') return false;
    int depth = 0; bool in = false, esc = false; size_t n = 0;
    for (; *p; p++) {
        char c = *p;
        if (n + 1 < cap) out[n++] = c;
        if (in) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in = false;
        } else {
            if (c == '"') in = true;
            else if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) break; }
        }
    }
    out[n] = 0;
    return depth == 0 && n > 1;
}

static int control_call(const char *endpoint, const char *method,
                        const char *args, const char *iface,
                        char *resp, size_t cap) {
    char req[8192], token[256] = "";
    const char *tok = getenv("XTATE_CONTROL_TOKEN");
    if (tok && tok[0]) snprintf(token, sizeof(token), ",\"token\":\"%s\"", tok);
    char jid[128] = {0};
    json_str(args ? args : "", "job_id", jid, sizeof(jid));
    if (strcmp(method, "job.list") == 0) {
        int off = 0, lim = 100;
        const char *po = args ? strstr(args, "\"offset\":") : NULL;
        const char *pl = args ? strstr(args, "\"limit\":") : NULL;
        if (po) off = atoi(po + 9);
        if (pl) lim = atoi(pl + 8);
        snprintf(req, sizeof(req),
                 "{\"id\":1,\"method\":\"job.list\",\"offset\":%d,"
                 "\"limit\":%d%s}\n", off, lim, token);
    } else if (strcmp(method, "job.start") == 0) {
        char params[7168];
        if (!extract_object(args ? args : "", "arguments", params, sizeof(params)))
            return -1;
        if (iface && iface[0]) {
            size_t n = strlen(params);
            char *esc = json_encode_string(iface);
            if (n && params[n - 1] == '}') params[--n] = 0;
            snprintf(params + n, sizeof(params) - n,
                     ",\"interface\":%s}", esc ? esc : "\"\"");
            free(esc);
        }
        snprintf(req, sizeof(req),
                 "{\"id\":1,\"method\":\"job.start\",\"params\":%s%s}\n",
                 params, token);
    } else {
        snprintf(req, sizeof(req),
                 "{\"id\":1,\"method\":\"%s\",\"job_id\":\"%s\"%s}\n",
                 method, jid, token);
    }
    return control_client_request(endpoint, req, resp, cap);
}

static bool regular_file_utf8(const char *path) {
#ifdef _WIN32
    wchar_t wpath[2048];
    struct _stat64 st;
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
                            (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0)
        return false;
    return _wstat64(wpath, &st) == 0 && (st.st_mode & _S_IFREG) != 0;
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
#endif
}

static bool validate_cfg(const char *cfg, char *err, size_t errcap,
                         unsigned *ntargets, unsigned *rate) {
    JsonNode *root = json_decode(cfg);
    if (!root || root->tag != JSON_OBJECT) {
        snprintf(err, errcap, "config must be a JSON object"); if (root) json_delete(root); return false;
    }
    JsonNode *scan = json_find_member(root, "scan");
    if (!scan || scan->tag != JSON_STRING || !get_scan_module_by_name(scan->string_)) {
        snprintf(err, errcap, "unknown or missing scan"); json_delete(root); return false;
    }
    JsonNode *probe = json_find_member(root, "probe");
    if (probe && (probe->tag != JSON_STRING || !get_probe_module_by_name(probe->string_))) {
        snprintf(err, errcap, "unknown probe"); json_delete(root); return false;
    }
    JsonNode *targets = json_find_member(root, "targets");
    JsonNode *inc = json_find_member(root, "include_file");
    if (inc && (inc->tag != JSON_STRING || !inc->string_[0])) {
        snprintf(err, errcap, "include_file must be a non-empty string"); json_delete(root); return false;
    }
    bool has_file = inc != NULL;
    bool has_targets = targets && targets->tag == JSON_ARRAY && targets->children.head;
    if (has_targets && has_file) {
        snprintf(err, errcap, "targets and include_file are mutually exclusive"); json_delete(root); return false;
    }
    if (!has_targets && !has_file) {
        snprintf(err, errcap, "targets or include_file required"); json_delete(root); return false;
    }
    if (has_file) {
        if (strcmp(inc->string_, "-") == 0) {
            snprintf(err, errcap, "include_file '-' is not allowed over MCP"); json_delete(root); return false;
        }
        if (!regular_file_utf8(inc->string_)) {
            snprintf(err, errcap, "include_file must be a regular file");
            json_delete(root); return false;
        }
        FILE *f = file_open_utf8(inc->string_);
        if (!f) {
            snprintf(err, errcap, "include_file cannot be opened"); json_delete(root); return false;
        }
        fclose(f);
    }
    if (!targets || targets->tag != JSON_ARRAY) targets = NULL;
    unsigned count = 0;
    for (JsonNode *t = targets ? targets->children.head : NULL; t; t = t->next) {
        if (t->tag != JSON_STRING) { snprintf(err, errcap, "target must be a string"); json_delete(root); return false; }
        size_t off = 0, len = strlen(t->string_);
        struct Range r4; struct Range6 r6;
        while (off < len) {
            if (target_parse_range(t->string_, &off, len, &r4, &r6) == Bad_Address) {
                snprintf(err, errcap, "invalid target"); json_delete(root); return false;
            }
        }
        count++;
    }
    if (count > 20000) { snprintf(err, errcap, "too many targets"); json_delete(root); return false; }
    JsonNode *ports = json_find_member(root, "ports");
    if (ports) {
        if (ports->tag != JSON_ARRAY) { snprintf(err, errcap, "ports must be an array"); json_delete(root); return false; }
        for (JsonNode *p = ports->children.head; p; p = p->next)
            if (p->tag != JSON_NUMBER || p->number_ < 0 || p->number_ > 65535) {
                snprintf(err, errcap, "invalid port"); json_delete(root); return false;
            }
    }
    unsigned r = 0;
    JsonNode *rn = json_find_member(root, "rate");
    if (rn) {
        if (rn->tag != JSON_NUMBER || rn->number_ < 0 || rn->number_ > 10000 ||
            rn->number_ != (double)(long long)rn->number_) {
            snprintf(err, errcap, "rate must be an integer in 0..10000");
            json_delete(root); return false;
        }
        r = (unsigned)rn->number_;
    }
    JsonNode *n = json_find_member(root, "timeout_sec");
    if (n && (n->tag != JSON_NUMBER || n->number_ < 1 || n->number_ > 86400 ||
              n->number_ != (double)(long long)n->number_)) {
        snprintf(err, errcap, "timeout_sec must be an integer in 1..86400");
        json_delete(root); return false;
    }
    const char *obj_fields[] = {"probe_args", "scan_args"};
    for (size_t i = 0; i < sizeof(obj_fields) / sizeof(obj_fields[0]); i++) {
        n = json_find_member(root, obj_fields[i]);
        if (n && n->tag != JSON_OBJECT) {
            snprintf(err, errcap, "%s must be an object", obj_fields[i]);
            json_delete(root); return false;
        }
    }
    const char *str_fields[] = {"result_path", "interface"};
    for (size_t i = 0; i < sizeof(str_fields) / sizeof(str_fields[0]); i++) {
        n = json_find_member(root, str_fields[i]);
        if (n && (n->tag != JSON_STRING || !n->string_[0])) {
            snprintf(err, errcap, "%s must be a non-empty string", str_fields[i]);
            json_delete(root); return false;
        }
    }
    n = json_find_member(root, "chunk_size");
    if (n && (n->tag != JSON_NUMBER || n->number_ < 1 ||
              n->number_ != (double)(long long)n->number_)) {
        snprintf(err, errcap, "chunk_size must be a positive integer");
        json_delete(root); return false;
    }
    n = json_find_member(root, "quota_bytes");
    if (n && (n->tag != JSON_NUMBER || n->number_ < 0 ||
              n->number_ != (double)(long long)n->number_)) {
        snprintf(err, errcap, "quota_bytes must be a non-negative integer");
        json_delete(root); return false;
    }
    n = json_find_member(root, "compression");
    if (n && (n->tag != JSON_STRING ||
              (strcmp(n->string_, "none") != 0 && strcmp(n->string_, "zstd") != 0))) {
        snprintf(err, errcap, "compression must be \"none\" or \"zstd\"");
        json_delete(root); return false;
    }
    const char *bool_fields[] = {"index", "dry_run", "authorized"};
    for (size_t i = 0; i < sizeof(bool_fields) / sizeof(bool_fields[0]); i++) {
        n = json_find_member(root, bool_fields[i]);
        if (n && n->tag != JSON_BOOL) {
            snprintf(err, errcap, "%s must be a boolean", bool_fields[i]);
            json_delete(root); return false;
        }
    }
    if (ntargets) *ntargets = count;
    if (rate) *rate = r;
    json_delete(root);
    return true;
}

static bool safe_target(const char *t) {
    if (!t || !t[0] || strlen(t) > 128) return false;
    for (const char *p = t; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
              (*p >= 'A' && *p <= 'F') || *p == '.' || *p == ':' ||
              *p == '/' || *p == '-' || *p == ',')) return false;
    return true;
}

static bool self_path(char *out, size_t cap) {
#ifdef _WIN32
    wchar_t wexe[1024];
    DWORD n = GetModuleFileNameW(NULL, wexe,
                                 (DWORD)(sizeof(wexe) / sizeof(wexe[0])));
    if (n == 0) return false;
    return WideCharToMultiByte(CP_UTF8, 0, wexe, -1, out, (int)cap,
                               NULL, NULL) > 0;
#else
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0) return false;
    out[n] = 0;
    return true;
#endif
}

static char *read_file_alloc(const char *path) {
#ifdef _WIN32
    wchar_t wpath[1600];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
                            (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0)
        return NULL;
    FILE *f = _wfopen(wpath, L"rb");
#else
    FILE *f = fopen(path, "rb");
#endif
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *text = malloc((size_t)n + 1);
    if (!text) { fclose(f); return NULL; }
    if (fread(text, 1, (size_t)n, f) != (size_t)n) { free(text); fclose(f); return NULL; }
    text[n] = 0;
    fclose(f);
    return text;
}

/* Resources may be read from any working directory. Prefer the operator
 * override and locations next to the executable (plus up to four parents),
 * which covers an installed layout and the repository build directory. The
 * current directory is tried last because it can be attacker-controlled. */
/* Resource names are a fixed, compiled-in allowlist. Reject anything that is
 * absolute, drive-qualified or contains a parent traversal component, so the
 * lookup can never be turned into an arbitrary file read. */
static char *read_resource_file(const char *rel) {
    char cand[1600];
    if (!rel || !rel[0] || rel[0] == '/' || rel[0] == '\\' ||
        strchr(rel, ':') || strstr(rel, ".."))
        return NULL;
    const char *base = getenv("XTATE_MCP_DOCS_DIR");
    if (base && base[0]) {
        snprintf(cand, sizeof(cand), "%s/%s", base, rel);
        char *text = read_file_alloc(cand);
        if (text) return text;
    }
    char *text = NULL;
    char exe[1024];
    if (!self_path(exe, sizeof(exe))) return read_file_alloc(rel);
    char dir[1200];
    snprintf(dir, sizeof(dir), "%s", exe);
    char *slash = strrchr(dir, '/');
#ifdef _WIN32
    char *bslash = strrchr(dir, '\\');
    if (!slash || (bslash && bslash > slash)) slash = bslash;
#endif
    if (slash) *slash = 0; else dir[0] = 0;
    for (int i = 0; i < 5; i++) {
        snprintf(cand, sizeof(cand), "%s/%s", dir, rel);
        text = read_file_alloc(cand);
        if (text) return text;
        size_t len = strlen(dir);
        if (len + 3 >= sizeof(dir)) break;
        memcpy(dir + len, "/..", 4);
    }
    /* The current directory is the least trusted location: an MCP client may
     * start the server inside an untrusted project, so only use it when the
     * operator override and every install-relative location failed. */
    return read_file_alloc(rel);
}

static void normalize_text(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '\r' && r[1] == '\n') continue;
        *w++ = *r;
    }
    *w = 0;
}

/* Run this executable with a fixed argument vector and capture stdout.
 * Arguments are split on spaces; every caller builds them from validated
 * module names and target characters only, so no quoting or shell is needed.
 * This deliberately avoids popen()/system(): the client cannot inject a shell
 * command even if a validation rule is missed. */
static bool run_self(const char *args, char *out, size_t cap) {
    char exe[1024];
    if (!self_path(exe, sizeof(exe))) return false;

    char argbuf[8192];
    int argn = snprintf(argbuf, sizeof(argbuf), "%s", args ? args : "");
    if (argn < 0 || (size_t)argn >= sizeof(argbuf)) return false;
    char *argv[128];
    int argc = 0;
    argv[argc++] = exe;
    char *save = NULL;
    for (char *tok = strtok_r(argbuf, " ", &save);
         tok && argc + 1 < (int)(sizeof(argv) / sizeof(argv[0]));
         tok = strtok_r(NULL, " ", &save)) {
        argv[argc++] = tok;
    }
    argv[argc] = NULL;
    if (argc < 2) return false;

#ifdef _WIN32
    char cmd[10000];
    int cmdn = snprintf(cmd, sizeof(cmd), "\"%s\" %s", exe, args ? args : "");
    if (cmdn < 0 || (size_t)cmdn >= sizeof(cmd)) return false;

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                             OPEN_EXISTING, 0, NULL);

    wchar_t tmpdir[1024], tmpfile[MAX_PATH + 1];
    DWORD td = GetTempPathW((DWORD)(sizeof(tmpdir) / sizeof(tmpdir[0])), tmpdir);
    if (td == 0 || td >= sizeof(tmpdir) / sizeof(tmpdir[0]) ||
        !GetTempFileNameW(tmpdir, L"xtm", 0, tmpfile)) {
        td = GetCurrentDirectoryW((DWORD)(sizeof(tmpdir) / sizeof(tmpdir[0])), tmpdir);
        if (td == 0 || td >= sizeof(tmpdir) / sizeof(tmpdir[0]) ||
            !GetTempFileNameW(tmpdir, L"xtm", 0, tmpfile)) {
            if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
            return false;
        }
    }
    HANDLE fh = CreateFileW(tmpfile, GENERIC_READ | GENERIC_WRITE | DELETE, 0, &sa,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                            NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
        return false;
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = fh;
    si.hStdError = fh;
    si.hStdInput = (nul != INVALID_HANDLE_VALUE) ? nul
                                                 : GetStdHandle(STD_INPUT_HANDLE);

    wchar_t wexe[1024], wcmd[10000];
    bool ok = MultiByteToWideChar(CP_UTF8, 0, exe, -1, wexe,
                                  (int)(sizeof(wexe) / sizeof(wexe[0]))) > 0 &&
              MultiByteToWideChar(CP_UTF8, 0, cmd, -1, wcmd,
                                  (int)(sizeof(wcmd) / sizeof(wcmd[0]))) > 0 &&
              CreateProcessW(wexe, wcmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
    if (!ok) {
        CloseHandle(fh);
        if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
        return false;
    }
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    DWORD wait = WaitForSingleObject(pi.hProcess, 30000);
    bool timed_out = wait != WAIT_OBJECT_0;
    if (timed_out) TerminateProcess(pi.hProcess, 1);
    DWORD exit_code = 1;
    bool child_ok = !timed_out && GetExitCodeProcess(pi.hProcess, &exit_code) &&
                    exit_code == 0;
    size_t n = 0;
    SetFilePointer(fh, 0, NULL, FILE_BEGIN);
    DWORD got = 0;
    while (n + 1 < cap && ReadFile(fh, out + n, (DWORD)(cap - 1 - n), &got, NULL) &&
           got > 0)
        n += got;
    out[n] = 0;
    normalize_text(out);
    CloseHandle(fh);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return child_ok;
#else
    int fds[2];
    if (pipe(fds) != 0) return false;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (pid == 0) {
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) {
            dup2(nul, STDIN_FILENO);
            close(nul);
        }
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[0]);
        close(fds[1]);
        execv(exe, argv);
        _exit(127);
    }
    close(fds[1]);
    size_t n = 0;
    bool timed_out = false;
    for (;;) {
        struct pollfd pfd = {fds[0], POLLIN, 0};
        int pr = poll(&pfd, 1, 30000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) {
            kill(pid, SIGKILL);
            timed_out = true;
            break;
        }
        ssize_t got = read(fds[0], out + n, cap - 1 - n);
        if (got < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (got == 0) break;
        n += (size_t)got;
        if (n + 1 >= cap) break;
    }
    out[n] = 0;
    normalize_text(out);
    close(fds[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return !timed_out && WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

static void structured_explain(const char *id, const char *text);

static void net_info(const char *id, const char *target) {
    char out[16384], args[256];
    if (strcmp(target, "") == 0) {
        snprintf(args, sizeof(args), "--check --explain-target=8.8.8.8");
    } else {
        if (!safe_target(target)) { text_result(id, "invalid target", true); return; }
        snprintf(args, sizeof(args), "--explain-target=%s", target);
    }
    if (!run_self(args, out, sizeof(out))) { text_result(id, "preflight failed", true); return; }
    structured_explain(id, out);
}


static bool append_out(char *out, size_t cap, size_t *off,
                       const char *fmt, ...) {
    if (*off >= cap) return false;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *off, cap - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *off) return false;
    *off += (size_t)n;
    return true;
}

static bool emit_group(char *out, size_t cap, size_t *off, int *emitted,
                       const char *ifname, const char *src,
                       const char *gw, const char *samples) {
    char *ei = json_encode_string(ifname ? ifname : "");
    char *es = json_encode_string(src ? src : "");
    char *eg = json_encode_string(gw ? gw : "");
    char *ea = json_encode_string(samples ? samples : "");
    bool ok = append_out(out, cap, off,
        "%s{\"interface\":%s,\"source\":%s,\"gateway\":%s,\"samples\":%s}",
        *emitted ? "," : "", ei ? ei : "\"\"", es ? es : "\"\"",
        eg ? eg : "\"\"", ea ? ea : "\"\"");
    free(ei); free(es); free(eg); free(ea);
    if (ok) (*emitted)++;
    return ok;
}

static void structured_explain(const char *id, const char *text) {
    char copy[16384]; snprintf(copy, sizeof(copy), "%s", text);
    unsigned long long targets = 0; int groups = 0;
    const char *pt = strstr(copy, "Targets:");
    if (pt) targets = strtoull(pt + 8, NULL, 10);
    const char *pg = strstr(copy, "Route groups:");
    if (pg) groups = atoi(pg + 13);
    char out[16384]; size_t off = 0;
    if (!append_out(out, sizeof(out), &off,
            "{\"targets\":%llu,\"route_groups\":%d,\"groups\":[",
            targets, groups)) {
        text_result(id, "explain output too large", true);
        return;
    }
    int emitted = 0;
    char *save = NULL;
    char *line = strtok_r(copy, "\n", &save);
    char ifname[256] = {0}, src[64] = {0}, gw[64] = {0}, samples[1024] = {0};
    bool overflow = false;
    while (line) {
        while (*line == ' ') line++;
        if (strncmp(line, "Route group", 11) == 0) {
            if (ifname[0] &&
                !emit_group(out, sizeof(out), &off, &emitted,
                            ifname, src, gw, samples)) {
                overflow = true;
                break;
            }
            ifname[0] = src[0] = gw[0] = samples[0] = 0;
        } else if (strncmp(line, "Interface:", 10) == 0) {
            snprintf(ifname, sizeof(ifname), "%s", line + 10);
            char *p = ifname; while (*p == ' ') p++;
            memmove(ifname, p, strlen(p) + 1);
        } else if (strncmp(line, "Source IPv4:", 12) == 0) {
            snprintf(src, sizeof(src), "%s", line + 12);
            char *p = src; while (*p == ' ') p++; memmove(src, p, strlen(p) + 1);
        } else if (strncmp(line, "Source IPv6:", 12) == 0) {
            snprintf(src, sizeof(src), "%s", line + 12);
            char *p = src; while (*p == ' ') p++; memmove(src, p, strlen(p) + 1);
        } else if (strncmp(line, "Gateway:", 8) == 0) {
            snprintf(gw, sizeof(gw), "%s", line + 8);
            char *p = gw; while (*p == ' ') p++; memmove(gw, p, strlen(p) + 1);
        } else if (strncmp(line, "Samples:", 8) == 0) {
            snprintf(samples, sizeof(samples), "%s", line + 8);
            char *p = samples; while (*p == ' ') p++; memmove(samples, p, strlen(p) + 1);
        }
        line = strtok_r(NULL, "\n", &save);
    }
    if (!overflow && ifname[0] &&
        !emit_group(out, sizeof(out), &off, &emitted,
                    ifname, src, gw, samples))
        overflow = true;
    if (overflow || !append_out(out, sizeof(out), &off, "]}")) {
        text_result(id, "explain output too large", true);
        return;
    }
    text_result(id, out, false);
}

static int explain_group_count(const char *endpoint, const char *cfg) {
    (void)endpoint;
    char targets[4096] = {0}; size_t off = 0;
    JsonNode *root = json_decode(cfg);
    if (!root) return -1;
    JsonNode *ta = json_find_member(root, "targets");
    for (JsonNode *t = ta ? ta->children.head : NULL; t; t = t->next) {
        if (t->tag != JSON_STRING) continue;
        if (off + strlen(t->string_) + 2 >= sizeof(targets)) break;
        off += (size_t)snprintf(targets + off, sizeof(targets) - off, "%s%s",
                                off ? "," : "", t->string_);
    }
    json_delete(root);
    if (!targets[0]) return -1;
    char text[16384];
    char args[4300]; snprintf(args, sizeof(args), "--explain-target=%s", targets);
    if (!run_self(args, text, sizeof(text))) return -1;
    const char *pg = strstr(text, "Route groups:");
    return pg ? atoi(pg + 13) : -1;
}
static bool result_path_writable(const char *path) {
    if (!path || !path[0]) return false;
#ifdef _WIN32
    wchar_t wpath[2048];
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
                            (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0)
        return false;
    FILE *f = _wfopen(wpath, L"ab");
    if (!f) return false;
    fclose(f);
    return true;
#else
    FILE *f = fopen(path, "ab");
    if (!f) return false;
    fclose(f);
    return true;
#endif
}

static void tool_call(const char *id, const char *name, const char *args,
                      const char *endpoint) {
    if (strcmp(name, "list_modules") == 0) {
        char *m = module_json_string();
        if (!m) { text_result(id, "cannot read module metadata", true); return; }
        text_result(id, m, false);
        free(m);
        return;
    }
    if (strcmp(name, "describe_probe") == 0) {
        char mod[128] = {0};
        json_str(args ? args : "", "name", mod, sizeof(mod));
        char *m = module_json_describe(mod);
        if (!m) { text_result(id, "probe/scan not found", true); return; }
        text_result(id, m, false);
        free(m);
        return;
    }
    if (strcmp(name, "validate_config") == 0) {
        char cfg[8192], err[256] = {0};
        unsigned nt = 0, rate = 0;
        if (!extract_object(args ? args : "", "config", cfg, sizeof(cfg))) {
            text_result(id, "{\"valid\":false,\"reason\":\"config object required\"}", true); return;
        }
        if (!validate_cfg(cfg, err, sizeof(err), &nt, &rate)) {
            char out[512]; snprintf(out, sizeof(out), "{\"valid\":false,\"reason\":\"%s\"}", err);
            text_result(id, out, true);
        } else {
            char out[256]; snprintf(out, sizeof(out),
                "{\"valid\":true,\"targets\":%u,\"rate\":%u}", nt, rate);
            text_result(id, out, false);
        }
        return;
    }
    if (strcmp(name, "explain_target") == 0 || strcmp(name, "check") == 0) {
        char target[256] = {0};
        json_str(args ? args : "", "target", target, sizeof(target));
        net_info(id, target);
        return;
    }
    if (!endpoint || !endpoint[0]) {
        text_result(id, "control endpoint not configured", true);
        return;
    }
    if (strcmp(name, "job_list") != 0 && strcmp(name, "job_status") != 0 &&
        strcmp(name, "job_result_manifest") != 0 &&
        strcmp(name, "job_cancel") != 0 && strcmp(name, "start_scan") != 0) {
        text_result(id, "unknown or unsupported tool", true);
        return;
    }
    if (strcmp(name, "start_scan") == 0) {
        char cfg[8192];
        if (!extract_object(args ? args : "", "arguments", cfg, sizeof(cfg))) {
            text_result(id, "arguments object required", true); return;
        }
        JsonNode *aroot = json_decode(cfg);
        JsonNode *auth = aroot ? json_find_member(aroot, "authorized") : NULL;
        bool authorized = auth && auth->tag == JSON_BOOL && auth->bool_;
        if (aroot) json_delete(aroot);
        if (!authorized) {
            text_result(id, "target authorization required: set authorized=true", true); return;
        }
        char verr[256] = {0}; unsigned targets = 0, rate = 0;
        if (!validate_cfg(cfg, verr, sizeof(verr), &targets, &rate)) {
            text_result(id, verr, true); return;
        }
        JsonNode *ar2 = json_decode(cfg);
        JsonNode *rp = ar2 ? json_find_member(ar2, "result_path") : NULL;
        if (rp && rp->tag == JSON_STRING && !result_path_writable(rp->string_)) {
            text_result(id, "result_path is not writable", true);
            json_delete(ar2); return;
        }
        if (ar2) json_delete(ar2);
        int rg = explain_group_count(endpoint, cfg);
        if (rg < 0) {
            JsonNode *fr = json_decode(cfg);
            JsonNode *incn = fr ? json_find_member(fr, "include_file") : NULL;
            JsonNode *ifn = fr ? json_find_member(fr, "interface") : NULL;
            if (incn && incn->tag == JSON_STRING && ifn && ifn->tag == JSON_STRING) rg = 1;
            if (fr) json_delete(fr);
        }
        if (rg < 0) { text_result(id, "cannot determine route groups", true); return; }
        if (rg > 1) { text_result(id, "targets span multiple routes; split into separate jobs", true); return; }
        FILE *audit = fopen("xtate-mcp-audit.log", "a");
        if (audit) {
            fprintf(audit, "start_scan rate=%u cfg=%.*s\n", rate, 500, cfg);
            fclose(audit);
        }
    }
    char iface[256] = {0};
    if (strcmp(name, "start_scan") == 0) {
        char targets[4096] = {0}; size_t off = 0;
        char argsobj[7168];
        JsonNode *root = NULL;
        if (extract_object(args ? args : "", "arguments", argsobj, sizeof(argsobj)))
            root = json_decode(argsobj);
        JsonNode *ta = root ? json_find_member(root, "targets") : NULL;
        for (JsonNode *t = ta ? ta->children.head : NULL; t; t = t->next) {
            if (t->tag != JSON_STRING) continue;
            if (off + strlen(t->string_) + 2 >= sizeof(targets)) break;
            off += (size_t)snprintf(targets + off, sizeof(targets) - off, "%s%s",
                                    off ? "," : "", t->string_);
        }
        if (!targets[0]) {
            JsonNode *ir = root ? json_find_member(root, "interface") : NULL;
            if (ir && ir->tag == JSON_STRING) snprintf(iface, sizeof(iface), "%s", ir->string_);
        }
        if (root) json_delete(root);
        if (targets[0]) {
            char text[16384], ea[4300];
            snprintf(ea, sizeof(ea), "--explain-target=%s", targets);
            if (!run_self(ea, text, sizeof(text))) {
                text_result(id, "route preflight failed; targets were not accepted "
                                 "by explain_target", true);
                return;
            }
            const char *pif = strstr(text, "Interface:");
            if (pif) {
                pif += 10; while (*pif == ' ') pif++;
                size_t k = 0; while (pif[k] && pif[k] != '\n' && pif[k] != '\r' && k + 1 < sizeof(iface)) { iface[k]=pif[k]; k++; }
                iface[k] = 0;
            }
        }
    }
    char resp[65536];
    const char *method = name;
    if (strcmp(name, "job_result_manifest") == 0) method = "job.result_manifest";
    else if (strcmp(name, "job_status") == 0) method = "job.status";
    else if (strcmp(name, "job_cancel") == 0) method = "job.cancel";
    else if (strcmp(name, "job_list") == 0) method = "job.list";
    else if (strcmp(name, "start_scan") == 0) method = "job.start";
    int n = control_call(endpoint, method, args, iface, resp, sizeof(resp));
    if (n < 0) { text_result(id, "control request failed", true); return; }
    text_result(id, resp, strstr(resp, "\"error\":{\"") != NULL);
}

int mcp_server_run(const char *control_endpoint) {
    char line[65536];
    while (fgets(line, sizeof(line), stdin)) {
        const char *id = json_id(line);
        if (strstr(line, "\"notifications/initialized\"")) continue;
        char method[128] = {0};
        json_str(line, "method", method, sizeof(method));
        if (strcmp(method, "initialize") == 0) {
            char *ins = json_encode_string(instructions);
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{"
                   "\"protocolVersion\":\"2024-11-05\","
                   "\"capabilities\":{\"tools\":{},\"resources\":{},\"prompts\":{}},"
                   "\"serverInfo\":{\"name\":\"xtate\",\"title\":\"Xtate network scanner\",\"version\":\"2.42.0\"},"
                   "\"instructions\":%s}}\n", id, ins ? ins : "\"\"");
            free(ins); fflush(stdout);
        } else if (strcmp(method, "ping") == 0) {
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n", id);
            fflush(stdout);
        } else if (strcmp(method, "tools/list") == 0) {
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n", id, tools_json);
            fflush(stdout);
        } else if (strcmp(method, "tools/call") == 0) {
            char name[64] = {0};
            json_str(line, "name", name, sizeof(name));
            const char *args = strstr(line, "\"arguments\":");
            tool_call(id, name, args, control_endpoint);
        } else if (strcmp(method, "resources/list") == 0) {
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n", id, resources_json);
            fflush(stdout);
        } else if (strcmp(method, "resources/read") == 0) {
            char uri[256] = {0};
            json_str(line, "uri", uri, sizeof(uri));
            const char *path = NULL;
            if (strcmp(uri, "xtate://docs/overview") == 0) path = "docs/README.md";
            else if (strcmp(uri, "xtate://docs/firewall") == 0) path = "docs/firewall.md";
            else if (strcmp(uri, "xtate://schemas/scan-request") == 0) path = "schemas/scan-request.schema.json";
            char *text = path ? read_resource_file(path) : NULL;
            if (!text) { rpc_error(id, -32002, "resource not found"); continue; }
            char *esc = json_encode_string(text);
            const char *mime = strstr(path, ".json") ? "application/json" : "text/markdown";
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"contents\":[{\"uri\":\"%s\",\"mimeType\":\"%s\",\"text\":%s}]}}\n",
                   id, uri, mime, esc ? esc : "\"\"");
            free(esc); free(text); fflush(stdout);
        } else if (strcmp(method, "prompts/list") == 0) {
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n", id, prompts_json);
            fflush(stdout);
        } else if (strcmp(method, "prompts/get") == 0) {
            char name[64] = {0}; json_str(line, "name", name, sizeof(name));
            if (strcmp(name, "plan-safe-scan") != 0) { rpc_error(id, -32602, "unknown prompt"); continue; }
            char *esc = json_encode_string("First call list_modules. Then plan an authorized scan with explicit targets, timeout/stall policy, and Linux firewall check for stateful scans. Use job tools; read results via job_result_manifest.");
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"description\":\"Plan a safe scan\",\"messages\":[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":%s}}]}}\n", id, esc ? esc : "\"\"");
            free(esc); fflush(stdout);
        } else {
            rpc_error(id, -32601, "method not found");
        }
    }
    return 0;
}
