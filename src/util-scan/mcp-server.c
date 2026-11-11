#include "mcp-server.h"
#include "control-client.h"
#include "../crypto/crypto-json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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

static const char *tools_json =
"{\"tools\":["
"{\"name\":\"job_list\",\"description\":\"List jobs, paginated\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"offset\":{\"type\":\"integer\"},\"limit\":{\"type\":\"integer\"}}}},"
"{\"name\":\"job_status\",\"description\":\"Get job status and heartbeat\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"job_id\":{\"type\":\"string\"}},\"required\":[\"job_id\"]}},"
"{\"name\":\"job_result_manifest\",\"description\":\"Get result manifest metadata\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"job_id\":{\"type\":\"string\"}},\"required\":[\"job_id\"]}},"
"{\"name\":\"job_cancel\",\"description\":\"Cancel a running job\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"job_id\":{\"type\":\"string\"}},\"required\":[\"job_id\"]}}"
"]}";

static int control_call(const char *endpoint, const char *method,
                        const char *args, char *resp, size_t cap) {
    char req[4096];
    const char *tok = getenv("XTATE_CONTROL_TOKEN");
    char jid[128] = {0};
    json_str(args ? args : "", "job_id", jid, sizeof(jid));
    int off = 0, lim = 100;
    const char *po = args ? strstr(args, "\"offset\":") : NULL;
    const char *pl = args ? strstr(args, "\"limit\":") : NULL;
    if (po) off = atoi(po + 9);
    if (pl) lim = atoi(pl + 8);
    if (strcmp(method, "job.list") == 0) {
        snprintf(req, sizeof(req),
                 "{\"id\":1,\"method\":\"job.list\",\"offset\":%d,"
                 "\"limit\":%d%s%s}\n", off, lim,
                 tok ? ",\"token\":\"" : "", tok ? tok : "");
        if (tok) {
            size_t l = strlen(req);
            req[l - 2] = '"'; req[l - 1] = '}'; req[l] = '\n'; req[l + 1] = 0;
        }
    } else {
        snprintf(req, sizeof(req),
                 "{\"id\":1,\"method\":\"%s\",\"job_id\":\"%s\""
                 "%s%s}\n", method, jid,
                 tok ? ",\"token\":\"" : "", tok ? tok : "");
        if (tok) {
            size_t l = strlen(req);
            req[l - 2] = '"'; req[l - 1] = '}'; req[l] = '\n'; req[l + 1] = 0;
        }
    }
    return control_client_request(endpoint, req, resp, cap);
}

static void tool_call(const char *id, const char *name, const char *args,
                      const char *endpoint) {
    if (!endpoint || !endpoint[0]) {
        text_result(id, "control endpoint not configured", true);
        return;
    }
    if (strcmp(name, "job_list") != 0 && strcmp(name, "job_status") != 0 &&
        strcmp(name, "job_result_manifest") != 0 &&
        strcmp(name, "job_cancel") != 0) {
        text_result(id, "unknown or unsupported tool", true);
        return;
    }
    char resp[65536];
    const char *method = name;
    if (strcmp(name, "job_result_manifest") == 0) method = "job.result_manifest";
    else if (strcmp(name, "job_status") == 0) method = "job.status";
    else if (strcmp(name, "job_cancel") == 0) method = "job.cancel";
    else if (strcmp(name, "job_list") == 0) method = "job.list";
    int n = control_call(endpoint, method, args, resp, sizeof(resp));
    if (n < 0) { text_result(id, "control request failed", true); return; }
    text_result(id, resp, false);
}

int mcp_server_run(const char *control_endpoint) {
    char line[65536];
    while (fgets(line, sizeof(line), stdin)) {
        const char *id = json_id(line);
        if (strstr(line, "\"notifications/initialized\"")) continue;
        char method[128] = {0};
        json_str(line, "method", method, sizeof(method));
        if (strcmp(method, "initialize") == 0) {
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"xtate\",\"version\":\"0.1\"}}}\n", id);
            fflush(stdout);
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
        } else {
            rpc_error(id, -32601, "method not found");
        }
    }
    return 0;
}
