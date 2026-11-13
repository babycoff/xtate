/*
    Xtate TUI: a small control-plane dashboard.

    This is deliberately a client, not a scanner. The control plane owns job
    lifetime, result storage and safety limits; the TUI only renders state and
    sends the same JSON methods that MCP uses.
*/

#include "tui.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../crypto/crypto-json.h"
#include "../util-data/safe-string.h"
#include "control-client.h"

#if defined(_WIN32)
#include <conio.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

#define TUI_MAX_JOBS 200
#define TUI_ID_SIZE 64
#define TUI_STATE_SIZE 32
#define TUI_RESULT_SIZE 2048
#define TUI_MSG_SIZE 512

typedef struct TuiJob {
    char id[TUI_ID_SIZE];
    char state[TUI_STATE_SIZE];
    char result[TUI_RESULT_SIZE];
} TuiJob;

static TuiJob g_jobs[TUI_MAX_JOBS];
static int g_job_count;
static int g_selected;
static size_t g_total;
static char g_endpoint[1024];
static char g_message[TUI_MSG_SIZE];
static int g_req_id = 1;
static int g_width = 100;
static int g_height = 30;

#if defined(_WIN32)
static HANDLE g_old_in = INVALID_HANDLE_VALUE;
static HANDLE g_old_out = INVALID_HANDLE_VALUE;
static DWORD g_old_in_mode;
static DWORD g_old_out_mode;
static UINT g_old_cp;
static int g_old_stdout_mode;
#else
static struct termios g_old_term;
#endif
static int g_raw_active;

static void tui_out(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static void clip_utf8(const char *src, int max_chars, char *dst, size_t cap) {
    size_t used = 0;
    int chars = 0;
    if (!dst || cap == 0) return;
    if (!src) src = "";
    while (*src && chars < max_chars) {
        unsigned char c = (unsigned char)*src;
        size_t len = 1;
        if ((c & 0x80) == 0)
            len = 1;
        else if ((c & 0xE0) == 0xC0)
            len = 2;
        else if ((c & 0xF0) == 0xE0)
            len = 3;
        else if ((c & 0xF8) == 0xF0)
            len = 4;
        if (used + len + 1 > cap) break;
        memcpy(dst + used, src, len);
        used += len;
        src += len;
        chars++;
    }
    dst[used] = 0;
}

static const char *json_str(JsonNode *object, const char *key) {
    JsonNode *node = json_find_member(object, key);
    if (node && node->tag == JSON_STRING && node->string_)
        return node->string_;
    return "";
}

static double json_num(JsonNode *object, const char *key) {
    JsonNode *node = json_find_member(object, key);
    return (node && node->tag == JSON_NUMBER) ? node->number_ : 0;
}

static JsonNode *tui_request(const char *method) {
    JsonNode *root = json_mkobject();
    const char *token = getenv("XTATE_CONTROL_TOKEN");
    json_append_member(root, "id", json_mknumber((double)g_req_id++));
    json_append_member(root, "method", json_mkstring(method));
    if (token && token[0]) json_append_member(root, "token", json_mkstring(token));
    return root;
}

static JsonNode *tui_rpc(JsonNode *root, char *err, size_t errcap) {
    char response[65536];
    char *request;
    JsonNode *parsed;
    JsonNode *error;

    if (err && errcap) err[0] = 0;
    request = json_stringify(root, NULL);
    json_delete(root);
    if (!request) {
        snprintf(err, errcap, "cannot encode control request");
        return NULL;
    }
    if (control_client_request(g_endpoint, request, response, sizeof(response)) <
        0) {
        free(request);
        snprintf(err, errcap, "control request failed (%s)", g_endpoint);
        return NULL;
    }
    free(request);

    parsed = json_decode(response);
    if (!parsed) {
        snprintf(err, errcap, "invalid control response");
        return NULL;
    }
    error = json_find_member(parsed, "error");
    if (error) {
        const char *code = json_str(error, "code");
        const char *message = json_str(error, "message");
        snprintf(err, errcap, "%s%s%s", code && code[0] ? code : "ERROR",
                 (message && message[0]) ? ": " : "",
                 (message && message[0]) ? message : "");
        json_delete(parsed);
        return NULL;
    }
    if (!json_find_member(parsed, "result")) {
        snprintf(err, errcap, "control response has no result");
        json_delete(parsed);
        return NULL;
    }
    return parsed;
}

static bool tui_fetch_jobs(char *err, size_t errcap) {
    JsonNode *root;
    JsonNode *response;
    JsonNode *result;
    JsonNode *jobs;
    JsonNode *job;

    root = tui_request("job.list");
    json_append_member(root, "limit", json_mknumber(TUI_MAX_JOBS));
    response = tui_rpc(root, err, errcap);
    if (!response) return false;

    result = json_find_member(response, "result");
    g_total = (size_t)json_num(result, "total");
    g_job_count = 0;
    jobs = json_find_member(result, "jobs");
    if (jobs && jobs->tag == JSON_ARRAY) {
        json_foreach(job, jobs) {
            if (g_job_count >= TUI_MAX_JOBS) break;
            if (job->tag != JSON_OBJECT) continue;
            snprintf(g_jobs[g_job_count].id, sizeof(g_jobs[g_job_count].id),
                     "%s", json_str(job, "job_id"));
            snprintf(g_jobs[g_job_count].state, sizeof(g_jobs[g_job_count].state),
                     "%s", json_str(job, "state"));
            snprintf(g_jobs[g_job_count].result,
                     sizeof(g_jobs[g_job_count].result), "%s",
                     json_str(job, "result"));
            g_job_count++;
        }
    }
    json_delete(response);
    if (g_selected >= g_job_count) g_selected = g_job_count > 0 ? g_job_count - 1 : 0;
    if (g_selected < 0) g_selected = 0;
    return true;
}

static void one_line(const char *src, char *dst, size_t cap) {
    size_t used = 0;
    if (!cap) return;
    if (!src) src = "";
    while (*src && used + 1 < cap) {
        unsigned char c = (unsigned char)*src++;
        dst[used++] = (c == '\r' || c == '\n' || c == '\t') ? ' ' : (char)c;
    }
    dst[used] = 0;
}

static bool tui_fetch_status(const char *id, char *out, size_t cap) {
    JsonNode *root = tui_request("job.status");
    JsonNode *response;
    JsonNode *result;
    char raw[2048];
    char err[256];

    if (!id || !id[0]) {
        snprintf(out, cap, "no job selected");
        return false;
    }
    json_append_member(root, "job_id", json_mkstring(id));
    response = tui_rpc(root, err, sizeof(err));
    if (!response) {
        snprintf(out, cap, "%s", err);
        return false;
    }
    result = json_find_member(response, "result");
    snprintf(raw, sizeof(raw),
             "phase=%s  sent=%.0f/%.0f  heartbeat=%.0fms  elapsed=%.0fms%s%s%s%s",
             json_str(result, "phase"), json_num(result, "sent"),
             json_num(result, "targets"), json_num(result, "heartbeat_age_ms"),
             json_num(result, "elapsed_ms"),
             json_str(result, "error")[0] ? "  error=" : "",
             json_str(result, "error"),
             json_str(result, "stderr_tail")[0] ? "  stderr=" : "",
             json_str(result, "stderr_tail"));
    one_line(raw, out, cap);
    json_delete(response);
    return true;
}

static void tui_term_size(void) {
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
        g_width = info.srWindow.Right - info.srWindow.Left + 1;
        g_height = info.srWindow.Bottom - info.srWindow.Top + 1;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        g_width = ws.ws_col;
        g_height = ws.ws_row;
    }
#endif
    if (g_width < 50) g_width = 50;
    if (g_height < 12) g_height = 12;
}

static int tui_isatty(void) {
#if defined(_WIN32)
    return _isatty(_fileno(stdin)) && _isatty(_fileno(stdout));
#else
    return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
#endif
}

static int tui_term_raw(void) {
#if defined(_WIN32)
    g_old_in = GetStdHandle(STD_INPUT_HANDLE);
    g_old_out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleMode(g_old_in, &g_old_in_mode)) return -1;
    if (!GetConsoleMode(g_old_out, &g_old_out_mode)) return -1;
    g_old_cp = GetConsoleOutputCP();
    g_old_stdout_mode = _setmode(_fileno(stdout), _O_BINARY);
    if (!SetConsoleMode(g_old_in,
                        g_old_in_mode &
                            ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
                              ENABLE_PROCESSED_INPUT)))
        return -1;
    if (!SetConsoleMode(g_old_out, g_old_out_mode |
                                       ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        return -1;
    SetConsoleOutputCP(CP_UTF8);
    tui_out("\x1b[?1049h\x1b[?25l");
#else
    if (tcgetattr(STDIN_FILENO, &g_old_term) != 0) return -1;
    {
        struct termios raw = g_old_term;
        raw.c_lflag &= (tcflag_t) ~(ICANON | ECHO | ISIG);
        raw.c_iflag &= (tcflag_t) ~(IXON | ICRNL);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return -1;
    }
    tui_out("\x1b[?1049h\x1b[?25l");
#endif
    g_raw_active = 1;
    return 0;
}

static void tui_term_restore(void) {
    if (!g_raw_active) return;
    tui_out("\x1b[?25h\x1b[?1049l");
    fflush(stdout);
#if defined(_WIN32)
    SetConsoleMode(g_old_in, g_old_in_mode);
    SetConsoleMode(g_old_out, g_old_out_mode);
    if (g_old_cp) SetConsoleOutputCP(g_old_cp);
    if (g_old_stdout_mode != -1) _setmode(_fileno(stdout), g_old_stdout_mode);
#else
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_old_term);
#endif
    g_raw_active = 0;
}

static int tui_getkey(int timeout_ms) {
#if defined(_WIN32)
    int waited = 0;
    while (waited <= timeout_ms) {
        if (_kbhit()) {
            int c = _getch();
            if (c == 0 || c == 224) {
                int c2 = _getch();
                if (c2 == 72) return 1001; /* up */
                if (c2 == 80) return 1002; /* down */
                return -1;
            }
            if (c == '\r') return '\n';
            return c;
        }
        Sleep(30);
        waited += 30;
    }
    return -1;
#else
    struct pollfd pfd;
    unsigned char c;
    int pr;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;
    pfd.revents = 0;
    pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) return -1;
    if (read(STDIN_FILENO, &c, 1) != 1) return -1;
    if (c == 0x1b) {
        unsigned char seq[2];
        struct pollfd p2;
        p2.fd = STDIN_FILENO;
        p2.events = POLLIN;
        p2.revents = 0;
        if (poll(&p2, 1, 10) <= 0) return 27;
        if (read(STDIN_FILENO, &seq[0], 1) != 1) return 27;
        if (seq[0] != '[') return 27;
        if (poll(&p2, 1, 10) <= 0) return 27;
        if (read(STDIN_FILENO, &seq[1], 1) != 1) return 27;
        if (seq[1] == 'A') return 1001;
        if (seq[1] == 'B') return 1002;
        return 27;
    }
    if (c == '\r' || c == '\n') return '\n';
    if (c == 127 || c == 8) return 8;
    return (int)c;
#endif
}

static int tui_read_line(const char *prompt, char *out, size_t cap) {
    char line[1024];
    size_t len;
    if (!out || cap == 0) return -1;
    out[0] = 0;
    tui_out("%s", prompt);
    fflush(stdout);
#if defined(_WIN32)
    {
        wchar_t wide[1024];
        DWORD got = 0;
        if (!ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), wide,
                          (DWORD)(sizeof(wide) / sizeof(wide[0]) - 1), &got,
                          NULL))
            return -1;
        wide[got] = 0;
        if (!WideCharToMultiByte(CP_UTF8, 0, wide, -1, line, (int)sizeof(line),
                                 NULL, NULL))
            return -1;
    }
#else
    if (!fgets(line, sizeof(line), stdin)) return -1;
#endif
    line[sizeof(line) - 1] = 0;
    len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = 0;
    safe_strcpy(out, cap, line);
    return 0;
}

static int tui_read_default(const char *prompt, char *value, size_t cap) {
    char input[1024];
    if (tui_read_line(prompt, input, sizeof(input)) < 0) return -1;
    if (input[0]) safe_strcpy(value, cap, input);
    return 0;
}

static void tui_draw(void) {
    char id[32], state[16], result[128], detail[512];
    int i;
    int rows;

    tui_term_size();
    tui_out("\x1b[H\x1b[2J");
    {
        char ep[80];
        clip_utf8(g_endpoint, g_width - 24, ep, sizeof(ep));
        tui_out("Xtate TUI  control: %s\n", ep);
    }
    tui_out("Jobs: %d shown, %zu total   [r]efresh [s]tart [c]ancel "
            "[Enter]details [q]uit\n",
            g_job_count, g_total);
    tui_out("--------------------------------------------------------------"
            "----------------------\n");
    tui_out("   %-20s %-12s %s\n", "JOB ID", "STATE", "RESULT");
    rows = g_height - 9;
    if (rows < 1) rows = 1;
    if (g_job_count == 0) {
        tui_out("   (no jobs)\n");
    } else {
        int first = 0;
        if (g_selected >= rows) first = g_selected - rows + 1;
        for (i = first; i < g_job_count && i < first + rows; i++) {
            clip_utf8(g_jobs[i].id, 20, id, sizeof(id));
            clip_utf8(g_jobs[i].state, 12, state, sizeof(state));
            clip_utf8(g_jobs[i].result, g_width - 40, result, sizeof(result));
            if (i == g_selected)
                tui_out("\x1b[7m > %-20s %-12s %s\x1b[0m\n", id, state,
                        result);
            else
                tui_out("   %-20s %-12s %s\n", id, state, result);
        }
    }
    tui_out("--------------------------------------------------------------"
            "----------------------\n");
    if (g_job_count > 0) {
        if (!tui_fetch_status(g_jobs[g_selected].id, detail, sizeof(detail)))
            snprintf(detail, sizeof(detail), "%s", g_message[0] ? g_message : "");
        {
            char clipped[512];
            clip_utf8(detail, g_width - 4, clipped, sizeof(clipped));
            tui_out("selected: %s\n", clipped);
        }
    } else {
        tui_out("selected: -\n");
    }
    {
        char msg[512];
        clip_utf8(g_message, g_width - 4, msg, sizeof(msg));
        tui_out("%s\n", msg);
    }
    fflush(stdout);
}

static void tui_show_details(void) {
    char status[2048];
    char manifest[1024];
    JsonNode *root;
    JsonNode *response;
    JsonNode *result;
    char err[256];
    int key;

    if (g_job_count == 0) return;
    if (!tui_fetch_status(g_jobs[g_selected].id, status, sizeof(status)))
        snprintf(status, sizeof(status), "status unavailable");

    root = tui_request("job.result_manifest");
    json_append_member(root, "job_id", json_mkstring(g_jobs[g_selected].id));
    response = tui_rpc(root, err, sizeof(err));
    if (response) {
        result = json_find_member(response, "result");
        snprintf(manifest, sizeof(manifest),
                 "state=%s result_bytes=%.0f complete=%s\nresult=%s\nmanifest=%s",
                 json_str(result, "state"), json_num(result, "result_bytes"),
                 (json_find_member(result, "complete") &&
                  json_find_member(result, "complete")->tag == JSON_BOOL &&
                  json_find_member(result, "complete")->bool_)
                     ? "yes"
                     : "no",
                 json_str(result, "result_path"),
                 json_str(result, "manifest_path"));
        json_delete(response);
    } else {
        snprintf(manifest, sizeof(manifest), "%s", err);
    }

    tui_out("\x1b[H\x1b[2J");
    tui_out("Job %s\n", g_jobs[g_selected].id);
    tui_out("----------------------------------------\n");
    tui_out("%s\n\n", status);
    tui_out("%s\n", manifest);
    tui_out("\nPress any key to return.");
    fflush(stdout);
    key = tui_getkey(60000);
    (void)key;
}

static void tui_cancel(void) {
    char prompt[256];
    int key;
    if (g_job_count == 0) return;
    snprintf(prompt, sizeof(prompt), "Cancel %s? y/n", g_jobs[g_selected].id);
    tui_out("\n%s", prompt);
    fflush(stdout);
    for (;;) {
        key = tui_getkey(60000);
        if (key == 'y' || key == 'Y') {
            JsonNode *root = tui_request("job.cancel");
            JsonNode *response;
            char err[256];
            json_append_member(root, "job_id",
                               json_mkstring(g_jobs[g_selected].id));
            response = tui_rpc(root, err, sizeof(err));
            if (response) {
                snprintf(g_message, sizeof(g_message), "cancel requested");
                json_delete(response);
            } else {
                snprintf(g_message, sizeof(g_message), "cancel failed: %s", err);
            }
            return;
        }
        if (key == 'n' || key == 'N' || key == 27) {
            snprintf(g_message, sizeof(g_message), "cancel aborted");
            return;
        }
    }
}

static int tui_parse_ports(const char *text, int *ports, int max_ports) {
    const char *p = text;
    int count = 0;
    while (*p) {
        char *end = NULL;
        long value;
        while (*p && (*p == ',' || isspace((unsigned char)*p))) p++;
        if (!*p) break;
        value = strtol(p, &end, 10);
        if (end == p || value < 0 || value > 65535) return -1;
        if (count >= max_ports) return -1;
        ports[count++] = (int)value;
        p = end;
        if (*p && *p != ',' && !isspace((unsigned char)*p)) return -1;
    }
    return count;
}

static void tui_start_wizard(void) {
    char scan[64], scan_input[64], targets[512], ports_text[256], rate_text[32];
    char timeout_text[32], path[512], confirm[32], iface[256];
    char err[256];
    int ports[128];
    int port_count;
    long rate, timeout;
    JsonNode *root;
    JsonNode *params;
    JsonNode *array;
    int tokens = 0;

    tui_term_restore();
    tui_out("\x1b[2J\x1b[H");
    tui_out("Start scan (all packets require explicit authorization)\n");
    tui_out("Hint: if auto interface selection fails, run "
            "`xtate --explain-target=<target>` and paste -if here.\n");
    tui_out("-----------------------------------------------------\n");
    snprintf(scan, sizeof(scan), "tcp-syn");
    snprintf(rate_text, sizeof(rate_text), "1000");
    snprintf(timeout_text, sizeof(timeout_text), "300");
    snprintf(path, sizeof(path), "xtate-tui-%lld.ndjson", (long long)time(NULL));

    if (tui_read_line("scan module [tcp-syn]: ", scan_input, sizeof(scan_input)) < 0)
        goto done;
    if (scan_input[0]) safe_strcpy(scan, sizeof(scan), scan_input);
    if (tui_read_line("targets (comma-separated, required): ", targets,
                      sizeof(targets)) < 0)
        goto done;
    if (!targets[0]) {
        snprintf(g_message, sizeof(g_message), "start cancelled: targets required");
        goto done;
    }
    if (tui_read_line("ports (comma-separated, empty for module default): ",
                      ports_text, sizeof(ports_text)) < 0)
        goto done;
    iface[0] = 0;
    if (tui_read_line("interface (optional; blank = auto): ", iface,
                      sizeof(iface)) < 0)
        goto done;
    if (tui_read_default("rate [1000]: ", rate_text, sizeof(rate_text)) < 0)
        goto done;
    if (tui_read_default("timeout seconds [300]: ", timeout_text,
                         sizeof(timeout_text)) < 0)
        goto done;
    if (tui_read_default("result path: ", path, sizeof(path)) < 0) goto done;
    if (!path[0]) {
        snprintf(g_message, sizeof(g_message), "start cancelled: result path required");
        goto done;
    }
    tui_out("\nTargets: %s\nPorts: %s\nInterface: %s\nResult: %s\n", targets,
            ports_text[0] ? ports_text : "(module default)",
            iface[0] ? iface : "(auto)", path);
    if (tui_read_line("Type YES to confirm you are authorized: ", confirm,
                      sizeof(confirm)) < 0)
        goto done;
    if (strcmp(confirm, "YES") != 0) {
        snprintf(g_message, sizeof(g_message), "start cancelled: authorization not confirmed");
        goto done;
    }

    rate = strtol(rate_text, NULL, 10);
    timeout = strtol(timeout_text, NULL, 10);
    if (rate < 0 || rate > 10000 || timeout < 1 || timeout > 86400) {
        snprintf(g_message, sizeof(g_message), "invalid rate or timeout");
        goto done;
    }
    port_count = ports_text[0] ? tui_parse_ports(ports_text, ports, 128) : 0;
    if (port_count < 0) {
        snprintf(g_message, sizeof(g_message), "invalid port list (integers 0-65535)");
        goto done;
    }

    params = json_mkobject();
    json_append_member(params, "scan", json_mkstring(scan));
    array = json_mkarray();
    {
        char buf[512];
        size_t i = 0;
        safe_strcpy(buf, sizeof(buf), targets);
        while (i < strlen(buf) && tokens < 64) {
            char *start = buf + i;
            char *end;
            while (*start == ',' || isspace((unsigned char)*start)) start++;
            if (!*start) break;
            end = start;
            while (*end && *end != ',') end++;
            if (*end == ',') *end++ = 0;
            {
                char *tail = end - 1;
                while (tail >= start && isspace((unsigned char)*tail)) *tail-- = 0;
            }
            if (start[0]) {
                json_append_element(array, json_mkstring(start));
                tokens++;
            }
            i = (size_t)(end - buf);
            if (*end == 0) break;
        }
    }
    if (tokens == 0) {
        json_delete(array);
        json_delete(params);
        snprintf(g_message, sizeof(g_message), "no targets parsed");
        goto done;
    }
    json_append_member(params, "targets", array);
    if (port_count > 0) {
        array = json_mkarray();
        for (int i = 0; i < port_count; i++)
            json_append_element(array, json_mknumber(ports[i]));
        json_append_member(params, "ports", array);
    }
    json_append_member(params, "rate", json_mknumber((double)rate));
    json_append_member(params, "authorized", json_mkbool(true));

    root = tui_request("job.start");
    json_append_member(root, "params", params);
    json_append_member(root, "result_path", json_mkstring(path));
    json_append_member(root, "timeout_sec", json_mknumber((double)timeout));
    json_append_member(root, "compression", json_mkstring("none"));
    json_append_member(root, "index", json_mkbool(false));
    if (iface[0]) json_append_member(root, "interface", json_mkstring(iface));
    {
        JsonNode *response = tui_rpc(root, err, sizeof(err));
        if (response) {
            JsonNode *result = json_find_member(response, "result");
            snprintf(g_message, sizeof(g_message), "started job %s",
                     json_str(result, "job_id"));
            json_delete(response);
        } else {
            snprintf(g_message, sizeof(g_message), "start failed: %s", err);
        }
    }

done:
    if (tui_term_raw() != 0) {
        tui_out("cannot restore TUI terminal\n");
        exit(1);
    }
}

static int tui_snapshot(void) {
    char err[256];
    int i;
    tui_term_size();
    if (!tui_fetch_jobs(err, sizeof(err))) {
        fprintf(stderr, "TUI: %s\n", err);
        return 1;
    }
    printf("Xtate TUI control endpoint: %s\n", g_endpoint);
    printf("%d job(s) shown, %zu total\n", g_job_count, g_total);
    printf("%-24s %-14s %s\n", "JOB ID", "STATE", "RESULT");
    for (i = 0; i < g_job_count; i++)
        printf("%-24s %-14s %s\n", g_jobs[i].id, g_jobs[i].state,
               g_jobs[i].result);
    return 0;
}

int tui_run(const char *endpoint) {
    if (!endpoint || !endpoint[0]) {
        fprintf(stderr, "TUI requires --control-connect=<endpoint>\n");
        return 1;
    }
    snprintf(g_endpoint, sizeof(g_endpoint), "%s", endpoint);
    if (!tui_isatty()) return tui_snapshot();
    if (tui_term_raw() != 0) {
        fprintf(stderr, "TUI: cannot initialize terminal\n");
        return 1;
    }
    atexit(tui_term_restore);
    for (;;) {
        char err[256];
        int key;
        if (!tui_fetch_jobs(err, sizeof(err)))
            snprintf(g_message, sizeof(g_message), "%s", err);
        tui_draw();
        key = tui_getkey(2000);
        if (key < 0) continue;
        if (key == 'q' || key == 'Q' || key == 3) break;
        if (key == 1001 && g_selected > 0) g_selected--;
        else if (key == 1002 && g_selected + 1 < g_job_count) g_selected++;
        else if (key == 'k' && g_selected > 0) g_selected--;
        else if (key == 'j' && g_selected + 1 < g_job_count) g_selected++;
        else if (key == 'r' || key == 'R') {
            g_message[0] = 0;
        } else if (key == 's' || key == 'S') {
            tui_start_wizard();
        } else if (key == 'c' || key == 'C') {
            tui_cancel();
        } else if (key == '\n') {
            tui_show_details();
        }
    }
    tui_term_restore();
    return 0;
}
