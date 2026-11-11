#include "mcp-server.h"
#include "control-client.h"
#include "../util-out/module-json.h"
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
"- This server exposes read-only and job-lifecycle tools; start_scan is not "
"enabled yet.\n";

static const char *tools_json =
"{\"tools\":["
"{\"name\":\"list_modules\",\"description\":\"List Xtate scan, probe, output and generate modules with their parameters. Use this before choosing a scanner/probe.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"job_list\",\"description\":\"List managed scan jobs with pagination. Returns job id, state and result path only; use job_result_manifest for result metadata.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"offset\":{\"type\":\"integer\",\"minimum\":0},\"limit\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":1000}}},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"job_status\",\"description\":\"Return a job's state, phase, sent/targets progress, success/failed counts, heartbeat age and elapsed time. Does not return result records.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"job_id\":{\"type\":\"string\",\"description\":\"Job id returned by job.start\"}},\"required\":[\"job_id\"]},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"job_result_manifest\",\"description\":\"Return result_path, manifest_path, size and completion for a job. Does not carry result data; read chunks from the manifest path.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"job_id\":{\"type\":\"string\"}},\"required\":[\"job_id\"]},\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":false}},"
"{\"name\":\"job_cancel\",\"description\":\"Request cancellation of a running job. The result file is preserved.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"job_id\":{\"type\":\"string\"}},\"required\":[\"job_id\"]},\"annotations\":{\"readOnlyHint\":false,\"destructiveHint\":true,\"openWorldHint\":false}}"
"]}";

static const char *resources_json =
"{\"resources\":["
"{\"uri\":\"xtate://docs/overview\",\"name\":\"Xtate overview\",\"mimeType\":\"text/markdown\"},"
"{\"uri\":\"xtate://docs/firewall\",\"name\":\"Linux firewall prerequisite\",\"mimeType\":\"text/markdown\"},"
"{\"uri\":\"xtate://schemas/scan-request\",\"name\":\"Scan request schema\",\"mimeType\":\"application/json\"}"
"]}";

static const char *prompts_json =
"{\"prompts\":[{\"name\":\"plan-safe-scan\",\"description\":\"Plan a scan with target authorization, protocol choice, timeout and firewall checks.\"}]}";

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
    if (strcmp(name, "list_modules") == 0) {
        char *m = module_json_string();
        if (!m) { text_result(id, "cannot read module metadata", true); return; }
        text_result(id, m, false);
        free(m);
        return;
    }
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
            if (strstr(uri, "docs/overview")) path = "docs/README.md";
            else if (strstr(uri, "docs/firewall")) path = "docs/firewall.md";
            else if (strstr(uri, "schemas/scan-request")) path = "schemas/scan-request.json";
            char *text = NULL;
            if (path) {
                FILE *f = fopen(path, "rb");
                if (f) {
                    fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
                    text = malloc((size_t)n + 1);
                    if (text && fread(text, 1, (size_t)n, f) == (size_t)n) text[n] = 0;
                    else { free(text); text = NULL; }
                    fclose(f);
                }
            }
            if (!text) { rpc_error(id, -32002, "resource not found"); continue; }
            char *esc = json_encode_string(text);
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"contents\":[{\"uri\":\"%s\",\"mimeType\":\"text/plain\",\"text\":%s}]}}\n",
                   id, uri, esc ? esc : "\"\"");
            free(esc); free(text); fflush(stdout);
        } else if (strcmp(method, "prompts/list") == 0) {
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n", id, prompts_json);
            fflush(stdout);
        } else if (strcmp(method, "prompts/get") == 0) {
            char name[64] = {0}; json_str(line, "name", name, sizeof(name));
            char *esc = json_encode_string("First call list_modules. Then plan an authorized scan with explicit targets, timeout/stall policy, and Linux firewall check for stateful scans. Use job tools; read results via job_result_manifest.");
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"description\":\"Plan a safe scan\",\"messages\":[{\"role\":\"user\",\"content\":{\"type\":\"text\",\"text\":%s}}]}}\n", id, esc ? esc : "\"\"");
            free(esc); fflush(stdout);
        } else {
            rpc_error(id, -32601, "method not found");
        }
    }
    return 0;
}
