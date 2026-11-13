/*
    Xtate GUI: HTTP presentation for the control plane.

    The page is embedded at build time from web/gui.html by
    tools/build_gui_page.py.  The server is deliberately tiny: one HTML page,
    one JSON RPC endpoint and one info endpoint.  It binds loopback by default.
    A non-loopback bind is allowed only with XTATE_GUI_ALLOW_REMOTE=1 for
    container-to-host port mapping, and still validates the Host header.
*/

#include "gui.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "../crypto/crypto-json.h"
#include "../util-data/file-open.h"
#include "../util-misc/i18n.h"
#include "../util-out/module-json.h"
#include "../version.h"
#include "control-client.h"
#include "gui-data.h"
#include "result-read.h"
#include "gui-page.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <windows.h>
typedef SOCKET gui_sock;
#define GUI_INVALID INVALID_SOCKET
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
typedef int gui_sock;
#define GUI_INVALID (-1)
#endif

#define GUI_MAX_REQUEST (128 * 1024)
#define GUI_MAX_BODY (64 * 1024)
#define GUI_RESPONSE_SIZE (64 * 1024)
#define GUI_TOKEN_SIZE 33
#define GUI_COOKIE_NAME "xtate_gui_session"

static const char *GUI_PLACEHOLDER = "__XTATE_GUI_TOKEN__";

static int gui_send_all(gui_sock s, const char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
#if defined(_WIN32)
        int n = send(s, data + sent, (int)(len - sent), 0);
#else
        ssize_t n = send(s, data + sent, len - sent, 0);
#endif
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static const char *gui_reason(int code) {
    switch (code) {
    case 200: return "OK";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    default: return "Error";
    }
}

static int gui_respond(gui_sock s, int code, const char *type,
                       const char *body, size_t len) {
    char header[768];
    int n = snprintf(header, sizeof(header),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Cache-Control: no-store\r\n"
                     "X-Content-Type-Options: nosniff\r\n"
                     "X-Frame-Options: DENY\r\n"
                     "Referrer-Policy: no-referrer\r\n"
                     "Content-Security-Policy: default-src 'none'; "
                     "script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                     "connect-src 'self'; img-src 'self' data:; "
                     "base-uri 'none'; form-action 'none'\r\n"
                     "Connection: close\r\n\r\n",
                     code, gui_reason(code), type, len);
    if (n < 0 || (size_t)n >= sizeof(header)) return -1;
    if (gui_send_all(s, header, (size_t)n) < 0) return -1;
    if (len && gui_send_all(s, body, len) < 0) return -1;
    return 0;
}

static int gui_respond_bootstrap(gui_sock s, const char *token) {
    char header[1024];
    int n = snprintf(header, sizeof(header),
                     "HTTP/1.1 303 See Other\r\n"
                     "Location: /\r\n"
                     "Set-Cookie: " GUI_COOKIE_NAME
                     "=%s; HttpOnly; SameSite=Strict; Path=/\r\n"
                     "Content-Length: 0\r\n"
                     "Cache-Control: no-store\r\n"
                     "Connection: close\r\n\r\n",
                     token);
    if (n < 0 || (size_t)n >= sizeof(header)) return -1;
    return gui_send_all(s, header, (size_t)n);
}

static void gui_respond_error(gui_sock s, int status, const char *code,
                              const char *message) {
    JsonNode *root = json_mkobject();
    JsonNode *error = json_mkobject();
    char *text;
    if (!root || !error) {
        json_delete(root);
        json_delete(error);
        return;
    }
    json_append_member(error, "code", json_mkstring(code));
    json_append_member(error, "message", json_mkstring(message));
    json_append_member(root, "error", error);
    text = json_stringify(root, NULL);
    json_delete(root);
    if (text) {
        gui_respond(s, status, "application/json; charset=utf-8", text,
                    strlen(text));
        free(text);
    }
}

static int gui_ci_prefix(const char *line, const char *name, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (!line[i] || tolower((unsigned char)line[i]) !=
                            tolower((unsigned char)name[i]))
            return 0;
    }
    return 1;
}

static int gui_header_value(const char *request, size_t header_len,
                            const char *name, char *out, size_t cap) {
    const char *p = request;
    const char *end = request + header_len;
    size_t name_len = strlen(name);
    while (p < end) {
        const char *eol = strstr(p, "\r\n");
        if (!eol || eol >= end) break;
        if (gui_ci_prefix(p, name, name_len) && p[name_len] == ':') {
            const char *v = p + name_len + 1;
            const char *ve = eol;
            size_t used = 0;
            while (v < ve && (*v == ' ' || *v == '\t')) v++;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
            while (v < ve && used + 1 < cap) out[used++] = *v++;
            out[used] = 0;
            return 1;
        }
        p = eol + 2;
    }
    return 0;
}

static long gui_content_length(const char *request, size_t header_len) {
    char value[32];
    char *end = NULL;
    long n;
    if (!gui_header_value(request, header_len, "Content-Length", value,
                          sizeof(value)))
        return 0;
    errno = 0;
    n = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != 0 || n < 0 || n > GUI_MAX_BODY) return -1;
    return n;
}

/*
    Return the full request length (headers + body) or a negative HTTP status
    hint: -413 body too large, -431 header too large, -400 malformed.
*/
static int gui_read_request(gui_sock s, char *buf, size_t cap,
                            size_t *header_len) {
    size_t used = 0;
    size_t hlen = 0;
    long body_len;

    *header_len = 0;
    while (used + 1 < cap) {
#if defined(_WIN32)
        int n = recv(s, buf + used, (int)(cap - 1 - used), 0);
#else
        ssize_t n = recv(s, buf + used, cap - 1 - used, 0);
#endif
        if (n <= 0) return -400;
        used += (size_t)n;
        buf[used] = 0;
        {
            char *p = strstr(buf, "\r\n\r\n");
            if (p) {
                hlen = (size_t)(p - buf) + 4;
                break;
            }
        }
    }
    if (!hlen) return -431;
    *header_len = hlen;
    body_len = gui_content_length(buf, hlen);
    if (body_len < 0) return -413;
    if ((size_t)body_len + hlen + 1 > cap) return -413;
    while (used < hlen + (size_t)body_len) {
#if defined(_WIN32)
        int n = recv(s, buf + used, (int)(hlen + (size_t)body_len - used), 0);
#else
        ssize_t n = recv(s, buf + used, hlen + (size_t)body_len - used, 0);
#endif
        if (n <= 0) return -400;
        used += (size_t)n;
    }
    buf[used] = 0;
    return (int)used;
}

static int gui_token_equal(const char *a, const char *b) {
    size_t la, lb, i;
    unsigned diff = 0;
    if (!a || !b) return 0;
    la = strlen(a);
    lb = strlen(b);
    if (la != lb) return 0;
    for (i = 0; i < la; i++) diff |= (unsigned)(a[i] ^ b[i]);
    return diff == 0;
}

static int gui_query_token(const char *query, char *out, size_t cap) {
    const char *p = query;
    if (!query || !cap) return 0;
    while (*p) {
        if (strncmp(p, "token=", 6) == 0) {
            const char *v = p + 6;
            size_t n = 0;
            while (v[n] && v[n] != '&' && n + 1 < cap) {
                out[n] = v[n];
                n++;
            }
            out[n] = 0;
            return n > 0;
        }
        p = strchr(p, '&');
        if (!p) break;
        p++;
    }
    out[0] = 0;
    return 0;
}

static int gui_cookie_token(const char *request, size_t header_len, char *out,
                            size_t cap) {
    char cookie[2048];
    const char *p;
    if (!gui_header_value(request, header_len, "Cookie", cookie, sizeof(cookie)))
        return 0;
    p = cookie;
    while (*p) {
        size_t name_len = strlen(GUI_COOKIE_NAME);
        if (strncmp(p, GUI_COOKIE_NAME, name_len) == 0 &&
            p[name_len] == '=') {
            const char *v = p + name_len + 1;
            size_t n = 0;
            while (v[n] && v[n] != ';' && v[n] != ' ' && n + 1 < cap) {
                out[n] = v[n];
                n++;
            }
            out[n] = 0;
            return n > 0;
        }
        p = strchr(p, ';');
        if (!p) break;
        p++;
        while (*p == ' ') p++;
    }
    out[0] = 0;
    return 0;
}

static int gui_make_token(char out[GUI_TOKEN_SIZE]) {
    unsigned char raw[16];
    static const char hex[] = "0123456789abcdef";
    size_t i;
    if (RAND_bytes(raw, sizeof(raw)) != 1) return -1;
    for (i = 0; i < sizeof(raw); i++) {
        out[i * 2] = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0x0f];
    }
    out[32] = 0;
    return 0;
}

static bool gui_remote_allowed(void) {
    const char *v = getenv("XTATE_GUI_ALLOW_REMOTE");
    return v && (!strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "yes"));
}

static int gui_parse_listen(const char *listen, int *port, bool *any) {
    const char *host = "127.0.0.1";
    const char *colon;
    const char *p;
    int value = 8787;

    *any = false;
    if (listen && listen[0]) {
        colon = strrchr(listen, ':');
        if (!colon) return -1;
        if (colon != listen) {
            host = listen;
        }
        if (strncmp(host, "0.0.0.0", 7) == 0 && host[7] == ':') {
            if (!gui_remote_allowed()) return -2;
            *any = true;
        } else if (!(strncmp(host, "127.0.0.1", 9) == 0 && host[9] == ':') &&
                   !(strncmp(host, "localhost", 9) == 0 && host[9] == ':')) {
            return -1;
        }
        if (!colon[1]) return -1;
        if (strlen(colon + 1) > 5) return -1;
        for (p = colon + 1; *p; p++) {
            if (!isdigit((unsigned char)*p)) return -1;
        }
        value = atoi(colon + 1);
        if (value < 0 || value > 65535) return -1;
    }
    *port = value;
    return 0;
}

static void gui_set_timeouts(gui_sock s) {
#if defined(_WIN32)
    DWORD tv = 8000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = 8;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

static void gui_serve_page(gui_sock s, const char *token) {
    const char *place;
    char *page;
    size_t prefix, suffix, token_len = strlen(token);
    size_t total;

    place = strstr((const char *)GUI_PAGE, GUI_PLACEHOLDER);
    if (!place) {
        gui_respond(s, 200, "text/html; charset=utf-8", (const char *)GUI_PAGE,
                    GUI_PAGE_LEN);
        return;
    }
    prefix = (size_t)(place - (const char *)GUI_PAGE);
    suffix = GUI_PAGE_LEN - prefix - strlen(GUI_PLACEHOLDER);
    total = GUI_PAGE_LEN - strlen(GUI_PLACEHOLDER) + token_len;
    page = (char *)malloc(total + 1);
    if (!page) {
        gui_respond_error(s, 500, "OUT_OF_MEMORY", "cannot render GUI page");
        return;
    }
    memcpy(page, GUI_PAGE, prefix);
    memcpy(page + prefix, token, token_len);
    memcpy(page + prefix + token_len, (const char *)GUI_PAGE + prefix +
               strlen(GUI_PLACEHOLDER), suffix);
    page[total] = 0;
    gui_respond(s, 200, "text/html; charset=utf-8", page, total);
    free(page);
}

static int gui_method_allowed(const char *method) {
    static const char *allowed[] = {
        "job.list", "job.status", "job.cancel", "job.result_manifest",
        "job.start",
    };
    size_t i;
    for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        if (strcmp(method, allowed[i]) == 0) return 1;
    }
    return 0;
}

static int gui_start_authorized(JsonNode *root) {
    JsonNode *params = json_find_member(root, "params");
    JsonNode *authorized;
    if (!params || params->tag != JSON_OBJECT) return 0;
    authorized = json_find_member(params, "authorized");
    return authorized && authorized->tag == JSON_BOOL && authorized->bool_;
}

static void gui_handle_rpc(gui_sock s, const char *endpoint,
                           const char *body) {
    JsonNode *root;
    JsonNode *method;
    JsonNode *existing_token;
    char response[GUI_RESPONSE_SIZE];
    char *request = NULL;
    int rc;

    root = json_decode(body);
    if (!root || root->tag != JSON_OBJECT) {
        json_delete(root);
        gui_respond_error(s, 400, "INVALID_JSON", "request must be a JSON object");
        return;
    }
    method = json_find_member(root, "method");
    if (!method || method->tag != JSON_STRING || !method->string_ ||
        !gui_method_allowed(method->string_)) {
        json_delete(root);
        gui_respond_error(s, 403, "METHOD_NOT_ALLOWED",
                          "only job methods are available through the GUI");
        return;
    }
    existing_token = json_find_member(root, "token");
    if (existing_token) {
        json_delete(root);
        gui_respond_error(s, 400, "TOKEN_NOT_ALLOWED",
                          "the GUI server supplies the control token");
        return;
    }
    if (strcmp(method->string_, "job.start") == 0) {
        JsonNode *rp;
        if (!gui_start_authorized(root)) {
            json_delete(root);
            gui_respond_error(s, 403, "AUTHORIZATION_REQUIRED",
                              "job.start requires params.authorized=true");
            return;
        }
        /* The console always uses the server-managed per-run path; never let
         * a browser-supplied path truncate an arbitrary file. */
        rp = json_find_member(root, "result_path");
        if (rp) {
            json_remove_from_parent(rp);
            json_delete(rp);
        }
    }
    if (!json_find_member(root, "id"))
        json_append_member(root, "id", json_mknumber(1));
    if (getenv("XTATE_CONTROL_TOKEN") && getenv("XTATE_CONTROL_TOKEN")[0])
        json_append_member(root, "token",
                           json_mkstring(getenv("XTATE_CONTROL_TOKEN")));
    request = json_stringify(root, NULL);
    json_delete(root);
    if (!request) {
        gui_respond_error(s, 500, "ENCODE_FAILED", "cannot encode request");
        return;
    }
    rc = control_client_request(endpoint, request, response, sizeof(response));
    free(request);
    if (rc < 0) {
        gui_respond_error(s, 502, "CONTROL_UNAVAILABLE",
                          "cannot reach the control plane");
        return;
    }
    gui_respond(s, 200, "application/json; charset=utf-8", response,
                strlen(response));
}

static void gui_handle_info(gui_sock s, const char *endpoint) {
    JsonNode *root = json_mkobject();
    char *text;
    if (!root) {
        gui_respond_error(s, 500, "OUT_OF_MEMORY", "cannot build info");
        return;
    }
    json_append_member(root, "endpoint", json_mkstring(endpoint));
    json_append_member(root, "version", json_mkstring(XTATE_VERSION));
    text = json_stringify(root, NULL);
    json_delete(root);
    if (!text) {
        gui_respond_error(s, 500, "ENCODE_FAILED", "cannot encode info");
        return;
    }
    gui_respond(s, 200, "application/json; charset=utf-8", text, strlen(text));
    free(text);
}

static char *gui_value_after(const char *query, const char *key);

static void gui_handle_system(gui_sock s, const char *endpoint) {
    char *text = gui_system_json(endpoint);
    if (!text) {
        gui_respond_error(s, 500, "SYSTEM_INFO_FAILED",
                          "cannot collect system information");
        return;
    }
    gui_respond(s, 200, "application/json; charset=utf-8", text, strlen(text));
    free(text);
}

static void gui_handle_interfaces(gui_sock s) {
    char *text = gui_interfaces_json();
    if (!text) {
        gui_respond_error(s, 500, "INTERFACE_INFO_FAILED",
                          "cannot enumerate capture interfaces");
        return;
    }
    gui_respond(s, 200, "application/json; charset=utf-8", text, strlen(text));
    free(text);
}

static void gui_handle_options(gui_sock s, const char *query) {
    I18nLanguage saved = i18n_get_language();
    char *lang = gui_value_after(query, "lang");
    char *text;

    if (lang && (strcmp(lang, "zh") == 0 || strcmp(lang, "zh-CN") == 0 ||
                 strcmp(lang, "cn") == 0))
        i18n_set_language("zh-CN");
    else
        i18n_set_language("en");

    text = gui_options_json();
    free(lang);
    i18n_set_language(saved == I18N_ZH_CN ? "zh-CN" : "en");

    if (!text) {
        gui_respond_error(s, 500, "OPTION_INFO_FAILED",
                          "cannot enumerate global options");
        return;
    }
    gui_respond(s, 200, "application/json", text, strlen(text));
    free(text);
}

static void gui_handle_modules(gui_sock s, const char *query) {
    I18nLanguage saved = i18n_get_language();
    char *lang = gui_value_after(query, "lang");
    char *text;

    if (lang && (strcmp(lang, "zh") == 0 || strcmp(lang, "zh-CN") == 0 ||
                 strcmp(lang, "cn") == 0))
        i18n_set_language("zh-CN");
    else
        i18n_set_language("en");

    text = module_json_string();
    free(lang);
    i18n_set_language(saved == I18N_ZH_CN ? "zh-CN" : "en");

    if (!text) {
        gui_respond_error(s, 500, "MODULE_INFO_FAILED",
                          "cannot enumerate modules");
        return;
    }
    gui_respond(s, 200, "application/json; charset=utf-8", text, strlen(text));
    free(text);
}

static void gui_handle_preflight(gui_sock s, const char *body) {
    char *text = gui_preflight_json(body);
    if (!text) {
        gui_respond_error(s, 400, "PREFLIGHT_FAILED",
                          "cannot validate the scan request");
        return;
    }
    gui_respond(s, 200, "application/json; charset=utf-8", text, strlen(text));
    free(text);
}

static char *gui_value_after(const char *query, const char *key) {
    const char *p = query;
    size_t klen = strlen(key);
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            const char *end = strchr(v, '&');
            size_t len = end ? (size_t)(end - v) : strlen(v);
            char *out = (char *)malloc(len + 1);
            if (out) { memcpy(out, v, len); out[len] = 0; }
            return out;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return NULL;
}

static int gui_job_id_ok(const char *job_id) {
    size_t i;
    if (!job_id || strncmp(job_id, "job-", 4) != 0 || !job_id[4]) return 0;
    for (i = 4; job_id[i]; i++) {
        if (job_id[i] < '0' || job_id[i] > '9') return 0;
    }
    return 1;
}

/* Resolve a job artifact path from the control plane.  The client never
   supplies a path: only the job id and a kind are accepted. */
static int gui_job_path(const char *endpoint, const char *job_id, const char *kind,
                        char *out, size_t cap) {
    char response[GUI_RESPONSE_SIZE];
    JsonNode *root, *result, *node, *rq;
    const char *member = "result";
    const char *control_token = getenv("XTATE_CONTROL_TOKEN");
    char *request;
    int rc;

    if (!gui_job_id_ok(job_id) || !out || cap == 0) return 0;
    if (strcmp(kind, "manifest") == 0) member = "manifest_path";
    else if (strcmp(kind, "log") != 0 && strcmp(kind, "result") != 0) return 0;
    rq = json_mkobject();
    if (!rq) return 0;
    json_append_member(rq, "id", json_mknumber(1));
    json_append_member(rq, "method", json_mkstring(
        strcmp(kind, "manifest") == 0 ? "job.result_manifest" : "job.status"));
    json_append_member(rq, "job_id", json_mkstring(job_id));
    if (control_token && control_token[0])
        json_append_member(rq, "token", json_mkstring(control_token));
    request = json_stringify(rq, NULL);
    json_delete(rq);
    if (!request) return 0;
    rc = control_client_request(endpoint, request, response, sizeof(response));
    free(request);
    if (rc < 0) return 0;
    root = json_decode(response);
    if (!root) return 0;
    result = json_find_member(root, "result");
    if (!result || result->tag != JSON_OBJECT) {
        json_delete(root);
        return 0;
    }
    node = json_find_member(result, member);
    if (!node || node->tag != JSON_STRING || !node->string_ || !node->string_[0]) {
        json_delete(root);
        return 0;
    }
    snprintf(out, cap, "%s", node->string_);
    json_delete(root);
    return 1;
}

static int gui_open_path(const char *path) {
#if defined(_WIN32)
    wchar_t wpath[2048];
    wchar_t sysdir[MAX_PATH];
    wchar_t app[MAX_PATH + 32];
    wchar_t cmd[4096];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    UINT n;

    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath,
                            (int)(sizeof(wpath) / sizeof(wpath[0]))) <= 0)
        return 0;
    n = GetSystemDirectoryW(sysdir, (UINT)(sizeof(sysdir) / sizeof(sysdir[0])));
    if (n == 0 || n >= sizeof(sysdir) / sizeof(sysdir[0]))
        return 0;
    if (swprintf(app, sizeof(app) / sizeof(app[0]), L"%ls\\notepad.exe",
                 sysdir) < 0)
        return 0;
    if (swprintf(cmd, sizeof(cmd) / sizeof(cmd[0]), L"\"%ls\" \"%ls\"",
                 app, wpath) < 0)
        return 0;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    /* Launch the text editor directly. ShellExecuteW may wait several seconds
     * for a DDE/AppX association before the file appears, which made the GUI
     * feel broken. */
    if (!CreateProcessW(app, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return 0;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
#else
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) {
        pid_t grandchild = fork();
        if (grandchild == 0) {
            execlp("xdg-open", "xdg-open", path, (char *)NULL);
            _exit(127);
        }
        _exit(grandchild < 0 ? 1 : 0);
    }
    return 1;
#endif
}

static int gui_kind_ok(const char *kind) {
    return kind && (strcmp(kind, "log") == 0 || strcmp(kind, "result") == 0 ||
                    strcmp(kind, "manifest") == 0);
}

static void gui_handle_open(gui_sock s, const char *endpoint, const char *body) {
    JsonNode *root = json_decode(body);
    JsonNode *job_id, *kind;
    char path[2048];
    char out[256];

    if (!root || root->tag != JSON_OBJECT) {
        json_delete(root);
        gui_respond_error(s, 400, "INVALID_JSON", "request must be a JSON object");
        return;
    }
    job_id = json_find_member(root, "job_id");
    kind = json_find_member(root, "kind");
    if (!job_id || job_id->tag != JSON_STRING || !gui_job_id_ok(job_id->string_) ||
        !kind || kind->tag != JSON_STRING || !gui_kind_ok(kind->string_)) {
        json_delete(root);
        gui_respond_error(s, 400, "INVALID_ARGUMENT",
                          "job_id must be job-<number> and kind must be log, result or manifest");
        return;
    }
    if (!gui_job_path(endpoint, job_id->string_, kind->string_, path, sizeof(path))) {
        json_delete(root);
        gui_respond_error(s, 404, "JOB_FILE_NOT_FOUND",
                          "the job has no such file yet");
        return;
    }
    if (!gui_open_path(path)) {
        json_delete(root);
        gui_respond_error(s, 500, "OPEN_FAILED",
                          "the operating system could not open the file");
        return;
    }
    snprintf(out, sizeof(out),
             "{\"opened\":true,\"kind\":\"%s\"}", kind->string_);
    json_delete(root);
    gui_respond(s, 200, "application/json; charset=utf-8", out, strlen(out));
}

static void gui_handle_results(gui_sock s, const char *endpoint,
                               const char *query) {
    char *job_id = gui_value_after(query, "job_id");
    char *offset_s = gui_value_after(query, "offset");
    char *limit_s = gui_value_after(query, "limit");
    int offset = offset_s ? atoi(offset_s) : 0;
    int limit = limit_s ? atoi(limit_s) : 50;
    int status = 0;
    char *text;

    free(offset_s);
    free(limit_s);
    text = result_records_json(endpoint, job_id ? job_id : "", offset, limit,
                               &status);
    free(job_id);
    if (!text) {
        if (status == 400)
            gui_respond_error(s, 400, "INVALID_JOB_ID",
                              "job_id must be job-<number>");
        else if (status == 404)
            gui_respond_error(s, 404, "RESULT_NOT_FOUND",
                              "job result is not available");
        else
            gui_respond_error(s, 500, "RESULT_READ_FAILED",
                              "cannot read result records");
        return;
    }
    gui_respond(s, 200, "application/json; charset=utf-8", text, strlen(text));
    free(text);
}

static int gui_host_allowed(const char *request, size_t header_len, int port) {
    char host[128];
    const char *p;
    (void)port;
    if (!gui_header_value(request, header_len, "Host", host, sizeof(host)))
        return 0;
    /* Docker and other reverse proxies publish the GUI on a different host
     * port, so accept any explicit port as long as the host is loopback. */
    if (strncmp(host, "127.0.0.1", 9) == 0) p = host + 9;
    else if (strncmp(host, "localhost", 9) == 0) p = host + 9;
    else return 0;
    if (*p == 0) return 1;
    if (*p != ':') return 0;
    p++;
    if (!*p) return 0;
    while (*p) {
        if (*p < '0' || *p > '9') return 0;
        p++;
    }
    return 1;
}

static void gui_handle(gui_sock s, const char *endpoint, const char *token,
                       int port) {
    char request[GUI_MAX_REQUEST];
    char method[8];
    char path[1024];
    char supplied[GUI_TOKEN_SIZE + 8];
    char token_from_query[GUI_TOKEN_SIZE];
    char token_from_cookie[GUI_TOKEN_SIZE];
    size_t header_len = 0;
    int total;
    int route;
    char *query;

    gui_set_timeouts(s);
    total = gui_read_request(s, request, sizeof(request), &header_len);
    if (total < 0) {
        if (total == -431)
            gui_respond_error(s, 431, "REQUEST_TOO_LARGE",
                              "request header is too large");
        else if (total == -413)
            gui_respond_error(s, 413, "BODY_TOO_LARGE", "request body is too large");
        else
            gui_respond_error(s, 400, "BAD_REQUEST", "malformed HTTP request");
        return;
    }
    if (sscanf(request, "%7s %1023s", method, path) != 2) {
        gui_respond_error(s, 400, "BAD_REQUEST", "malformed request line");
        return;
    }
    query = strchr(path, '?');
    if (query) *query++ = 0;
    if (!gui_host_allowed(request, header_len, port)) {
        gui_respond_error(s, 403, "INVALID_HOST",
                          "GUI requests must use the loopback host");
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/favicon.ico") == 0) {
        gui_respond(s, 204, "text/plain", "", 0);
        return;
    }
    if (strcmp(method, "GET") == 0 &&
        (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0)) {
        int have_header =
            gui_header_value(request, header_len, "X-Xtate-GUI-Token", supplied,
                             sizeof(supplied)) &&
            gui_token_equal(supplied, token);
        int have_cookie = gui_cookie_token(request, header_len, token_from_cookie,
                                           sizeof(token_from_cookie)) &&
                          gui_token_equal(token_from_cookie, token);
        int have_query = gui_query_token(query, token_from_query,
                                         sizeof(token_from_query)) &&
                         gui_token_equal(token_from_query, token);
        if (have_query && !have_cookie && !have_header) {
            if (gui_respond_bootstrap(s, token) < 0)
                gui_respond_error(s, 500, "GUI_PAGE_FAILED",
                                  "cannot start GUI session");
            return;
        }
        if (!have_header && !have_cookie) {
            gui_respond_error(s, 403, "GUI_TOKEN_REQUIRED",
                              "open the URL printed by the GUI");
            return;
        }
        gui_serve_page(s, token);
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/info") == 0)
        route = 1;
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/rpc") == 0)
        route = 2;
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/system") == 0)
        route = 3;
    else if (strcmp(method, "GET") == 0 &&
             strcmp(path, "/api/interfaces") == 0)
        route = 4;
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/modules") == 0)
        route = 5;
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/options") == 0)
        route = 9;
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/preflight") == 0)
        route = 6;
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/api/results") == 0)
        route = 7;
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/api/open") == 0)
        route = 8;
    else
        route = 0;

    if (!route) {
        gui_respond_error(s, 404, "NOT_FOUND", "no such endpoint");
        return;
    }
    if (!(gui_header_value(request, header_len, "X-Xtate-GUI-Token", supplied,
                           sizeof(supplied)) &&
          gui_token_equal(supplied, token)) &&
        !(gui_cookie_token(request, header_len, token_from_cookie,
                           sizeof(token_from_cookie)) &&
          gui_token_equal(token_from_cookie, token))) {
        gui_respond_error(s, 403, "GUI_TOKEN_REQUIRED",
                          "missing or invalid GUI session token");
        return;
    }
    switch (route) {
    case 1: gui_handle_info(s, endpoint); break;
    case 2: gui_handle_rpc(s, endpoint, request + header_len); break;
    case 3: gui_handle_system(s, endpoint); break;
    case 4: gui_handle_interfaces(s); break;
    case 5: gui_handle_modules(s, query ? query : ""); break;
    case 6: gui_handle_preflight(s, request + header_len); break;
    case 7: gui_handle_results(s, endpoint, query ? query : ""); break;
    case 8: gui_handle_open(s, endpoint, request + header_len); break;
    case 9: gui_handle_options(s, query ? query : ""); break;
    default: break;
    }
}

int gui_run(const char *endpoint, const char *listen_addr) {
    gui_sock server;
    struct sockaddr_in addr;
    socklen_t addr_len;
    char token[GUI_TOKEN_SIZE];
    char url[128];
    char open_url[1600];
    const char *public_url;
    int port = 0;
    int actual_port = 0;
    bool bind_any = false;

    if (!endpoint || !endpoint[0]) {
        fprintf(stderr, "xtate: --gui requires --control-connect\n");
        return 1;
    }
    int parsed = gui_parse_listen(listen_addr, &port, &bind_any);
    if (parsed != 0) {
        if (parsed == -2)
            fprintf(stderr,
                    "xtate: refusing a remote GUI bind without "
                    "XTATE_GUI_ALLOW_REMOTE=1; use 127.0.0.1:PORT\n");
        else
            fprintf(stderr,
                    "xtate: invalid --gui-listen value; use 127.0.0.1:PORT\n");
        return 1;
    }
    if (gui_make_token(token) != 0) {
        fprintf(stderr, "xtate: cannot obtain secure random GUI token\n");
        return 1;
    }

#if defined(_WIN32)
    {
        WSADATA wsa;
        WSAStartup(0x101, &wsa);
    }
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == GUI_INVALID) {
        fprintf(stderr, "xtate: cannot create GUI socket\n");
        return 1;
    }
    {
        int reuse = 1;
        setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
                   sizeof(reuse));
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(bind_any ? INADDR_ANY : INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "xtate: cannot bind GUI listener to %s:%d\n",
                bind_any ? "0.0.0.0" : "127.0.0.1", port);
#if defined(_WIN32)
        closesocket(server);
#else
        close(server);
#endif
        return 1;
    }
    if (listen(server, 16) != 0) {
        fprintf(stderr, "xtate: cannot listen on GUI socket\n");
#if defined(_WIN32)
        closesocket(server);
#else
        close(server);
#endif
        return 1;
    }
    addr_len = sizeof(addr);
    if (getsockname(server, (struct sockaddr *)&addr, &addr_len) == 0)
        actual_port = ntohs(addr.sin_port);
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/", actual_port);

    public_url = getenv("XTATE_GUI_PUBLIC_URL");
    printf("Xtate GUI listening on %s\n", url);
    if (bind_any)
        printf("WARNING: GUI is bound to all interfaces. Publish it only on "
               "host loopback (for example -p 127.0.0.1:8787:8787) or behind "
               "a firewall.\n");
    printf("Control endpoint: %s\n", endpoint);
    printf("GUI session token: %s\n", token);
    if (public_url && public_url[0])
        snprintf(open_url, sizeof(open_url), "%s%stoken=%s", public_url,
                 strchr(public_url, '?') ? "&" : "?", token);
    else if (bind_any)
        snprintf(open_url, sizeof(open_url),
                 "http://127.0.0.1:%d/?token=%s", actual_port, token);
    else
        snprintf(open_url, sizeof(open_url), "%s?token=%s", url, token);
    if (bind_any && !(public_url && public_url[0]))
        printf("Open %s on the host after publishing this port (or set "
               "XTATE_GUI_PUBLIC_URL).\n", open_url);
    else if (bind_any)
        printf("Open %s in your browser. Remote GUI access is enabled by "
               "XTATE_GUI_ALLOW_REMOTE; keep it behind host loopback or a "
               "firewall.\n", open_url);
    else
        printf("Open %s in your browser. The server is loopback-only.\n",
               open_url);
    printf("Press Ctrl-C to stop.\n");
    fflush(stdout);

    for (;;) {
        gui_sock client = accept(server, NULL, NULL);
        if (client == GUI_INVALID) {
#if !defined(_WIN32)
            if (errno == EINTR) continue;
#endif
            break;
        }
        gui_handle(client, endpoint, token, actual_port);
#if defined(_WIN32)
        closesocket(client);
#else
        close(client);
#endif
    }
#if defined(_WIN32)
    closesocket(server);
    WSACleanup();
#else
    close(server);
#endif
    return 0;
}
