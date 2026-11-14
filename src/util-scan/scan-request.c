#include "scan-request.h"
#include "../util-data/file-open.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "../crypto/crypto-json.h"
#include "../util-data/fine-malloc.h"
#include "../util-out/logger.h"
#include "../util-out/error-code.h"
#include "../scan-modules/scan-modules.h"
#include "../probe-modules/probe-modules.h"
#include "../target/target-parse.h"
#include "../target/target-rangev4.h"
#include "../target/target-rangev6.h"

static void req_error(ErrorCode code, const char *msg) {
    char *esc = json_encode_string(msg ? msg : "");
    fprintf(stderr, "{\"error\":{\"code\":\"%s\",\"message\":%s,"
                    "\"retryable\":%s}}\n", error_code_name(code),
            esc ? esc : "\"\"", error_code_retryable(code) ? "true" : "false");
    if (esc) free(esc);
}

static bool allowed(const char *name) {
    static const char *ok[] = {"scan","probe","targets","ports","probe_args",
                               "scan_args","global_args","rate","timeout_sec","dry_run","result_path",
                               "chunk_size","compression","index","quota_bytes","authorized","interface","timeout_sec","include_file",0};
    for (int i=0; ok[i]; i++) if (strcmp(name, ok[i]) == 0) return true;
    return false;
}

extern ConfParam config_parameters[];

static ConfParam *find_global_param(const char *name) {
    if (!name || !name[0]) return NULL;
    for (ConfParam *p = config_parameters; p && p->name; p++) {
        if (!p->help_text) continue;
        if (strcmp(p->name, name) == 0) return p;
        for (int i = 0; i < 8 && p->alt_names[i]; i++)
            if (strcmp(p->alt_names[i], name) == 0) return p;
    }
    return NULL;
}

int scan_request_global_arg_allowed(const char *name) {
    /* Deliberately an allowlist, not a deny list.  These options only affect
       scan semantics, packet fields, buffers or dedup.  Everything that can
       change process mode, spawn programs, read/write caller paths, override
       job/output/control fields or make a job non-terminating is excluded. */
    static const char *ok[] = {
        "seed", "no-cpu-bind", "packet-ttl", "tcp-init-window", "tcp-window",
        "tcp-wscale", "tcp-mss", "tcp-sackok", "tcp-tsecho", "max-packet-len",
        "adapter-snaplen", "stack-buf-count", "dispatch-buf-count", "no-dedup",
        "dedup-win",
        "shard", "static-seed", "tx-thread-count", "rx-handler-count",
        "source-port", "adapter-vlan", "init-ipv4-adapter",
        "init-ipv6-adapter", NULL};
    if (!name || !find_global_param(name)) return 0;
    for (int i = 0; ok[i]; i++)
        if (strcmp(name, ok[i]) == 0) return 1;
    return 0;
}

int scan_request_global_arg_is_flag(const char *name) {
    ConfParam *p = find_global_param(name);
    return p && p->type == Type_FLAG;
}

static int parse_u64(const char *s, uint64_t lo, uint64_t hi, uint64_t *out) {
    char *end = NULL;
    unsigned long long v;
    if (!s || !s[0] || s[0] == '+' || s[0] == '-') return 0;
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno || !end || *end || v < lo || v > hi) return 0;
    *out = (uint64_t)v;
    return 1;
}

static int power_of_two(uint64_t v) { return v && !(v & (v - 1)); }

int scan_request_global_arg_value_valid(const char *name, const char *val) {
    uint64_t v;
    if (strcmp(name, "seed") == 0)
        return strcmp(val, "time") == 0 || (val[0] != '-' &&
               parse_u64(val, 0, UINT64_MAX, &v));
    if (strcmp(name, "packet-ttl") == 0) return parse_u64(val, 0, 255, &v);
    if (strcmp(name, "tcp-init-window") == 0 ||
        strcmp(name, "tcp-window") == 0) return parse_u64(val, 0, 65535, &v);
    if (strcmp(name, "tcp-wscale") == 0)
        return strcmp(val, "true") == 0 || strcmp(val, "false") == 0 ||
               parse_u64(val, 0, 14, &v);
    if (strcmp(name, "tcp-mss") == 0)
        return strcmp(val, "true") == 0 || strcmp(val, "false") == 0 ||
               parse_u64(val, 0, 65535, &v);
    if (strcmp(name, "tcp-tsecho") == 0)
        return strcmp(val, "true") == 0 || strcmp(val, "false") == 0 ||
               parse_u64(val, 0, UINT32_MAX, &v);
    if (strcmp(name, "max-packet-len") == 0 ||
        strcmp(name, "adapter-snaplen") == 0) return parse_u64(val, 64, 65535, &v);
    if (strcmp(name, "stack-buf-count") == 0 ||
        strcmp(name, "dispatch-buf-count") == 0) {
        if (!parse_u64(val, 1024, 1048576, &v)) return 0;
        return power_of_two(v);
    }
    if (strcmp(name, "dedup-win") == 0) return parse_u64(val, 1, 10000000, &v);
    if (strcmp(name, "tx-thread-count") == 0) return parse_u64(val, 1, 64, &v);
    if (strcmp(name, "rx-handler-count") == 0) {
        if (!parse_u64(val, 1, 64, &v)) return 0;
        return power_of_two(v);
    }
    if (strcmp(name, "source-port") == 0) return parse_u64(val, 0, 65535, &v);
    if (strcmp(name, "adapter-vlan") == 0) return parse_u64(val, 0, 4095, &v);
    if (strcmp(name, "shard") == 0) {
        const char *slash = strchr(val, '/');
        char a[16], b[16];
        size_t alen;
        uint64_t x, y;
        if (!slash || slash == val) return 0;
        alen = (size_t)(slash - val);
        if (alen >= sizeof(a) || strlen(slash + 1) >= sizeof(b)) return 0;
        memcpy(a, val, alen); a[alen] = 0;
        snprintf(b, sizeof(b), "%s", slash + 1);
        if (!parse_u64(a, 1, 1024, &x) || !parse_u64(b, 1, 1024, &y)) return 0;
        return x <= y;
    }
    return 1;
}

static char *join_array(JsonNode *a, bool ports) {
    size_t cap = 64, len = 0;
    char *out = MALLOC(cap);
    if (!out) return NULL;
    for (JsonNode *n = a ? a->children.head : NULL; n; n = n->next) {
        char tmp[64];
        if (ports) {
            if (n->tag != JSON_NUMBER) { FREE(out); return NULL; }
            snprintf(tmp, sizeof(tmp), "%d", (int)n->number_);
        } else {
            if (n->tag != JSON_STRING) { FREE(out); return NULL; }
            snprintf(tmp, sizeof(tmp), "%s", n->string_);
        }
        size_t need = strlen(tmp) + (len ? 1 : 0) + 1;
        if (len + need > cap) {
            cap = (len + need) * 2;
            char *p = REALLOC(out, cap);
            if (!p) { FREE(out); return NULL; }
            out = p;
        }
        if (len) out[len++] = ',';
        memcpy(out + len, tmp, strlen(tmp));
        len += strlen(tmp);
    }
    if (!len) { FREE(out); return NULL; }
    out[len] = 0;
    return out;
}

static bool arg_append(char **out, size_t *len, size_t *cap, const char *s,
                       size_t n) {
    if (*len + n + 1 > *cap) {
        size_t want = (*len + n + 1) * 2;
        char  *p    = REALLOC(*out, want);
        if (!p) return false;
        *out = p;
        *cap = want;
    }
    memcpy(*out + *len, s, n);
    *len += n;
    (*out)[*len] = 0;
    return true;
}

static bool arg_needs_quote(const char *v) {
    for (; *v; v++) {
        if (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n' ||
            *v == '\'' || *v == '"' || *v == '\\')
            return true;
    }
    return false;
}

static bool arg_append_string(char **out, size_t *len, size_t *cap,
                              const char *key, const char *value) {
    char head[320];
    int  n = snprintf(head, sizeof(head), "--%s=", key);
    if (n < 0 || (size_t)n >= sizeof(head)) return false;
    if (!arg_append(out, len, cap, head, (size_t)n)) return false;
    if (!arg_needs_quote(value))
        return arg_append(out, len, cap, value, strlen(value));
    if (!arg_append(out, len, cap, "'", 1)) return false;
    for (const char *p = value; *p; p++) {
        if (*p == '\'' || *p == '\\') {
            char esc = '\\';
            if (!arg_append(out, len, cap, &esc, 1)) return false;
        }
        if (!arg_append(out, len, cap, p, 1)) return false;
    }
    return arg_append(out, len, cap, "'", 1);
}

static char *args_string(JsonNode *obj) {
    if (!obj || obj->tag != JSON_OBJECT) return NULL;
    size_t cap = 128, len = 0;
    char  *out = MALLOC(cap);
    if (!out) return NULL;
    out[0] = 0;
    for (JsonNode *n = obj->children.head; n; n = n->next) {
        char keybuf[256];
        snprintf(keybuf, sizeof(keybuf), "%s", n->key ? n->key : "");
        for (char *p = keybuf; *p; p++)
            if (*p == '_') *p = '-';
        const char *key = keybuf;
        if (len && !arg_append(&out, &len, &cap, " ", 1)) goto fail;
        if (n->tag == JSON_BOOL) {
            if (!n->bool_) {
                if (len) len--;
                out[len] = 0;
                continue;
            }
            char tmp[320];
            int  k = snprintf(tmp, sizeof(tmp), "--%s", key);
            if (k < 0 || (size_t)k >= sizeof(tmp) ||
                !arg_append(&out, &len, &cap, tmp, (size_t)k))
                goto fail;
        } else if (n->tag == JSON_STRING) {
            if (!arg_append_string(&out, &len, &cap, key,
                                   n->string_ ? n->string_ : ""))
                goto fail;
        } else if (n->tag == JSON_NUMBER) {
            char tmp[320];
            int  k = snprintf(tmp, sizeof(tmp), "--%s=%g", key, n->number_);
            if (k < 0 || (size_t)k >= sizeof(tmp) ||
                !arg_append(&out, &len, &cap, tmp, (size_t)k))
                goto fail;
        } else {
            goto fail;
        }
    }
    out[len] = 0;
    return len ? out : NULL;
fail:
    FREE(out);
    return NULL;
}

unsigned scan_request_timeout(const char *filename) {
    FILE *fp = file_open_utf8_mode(filename, "rb");
    if (!fp) return 0;
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); rewind(fp);
    if (sz <= 0 || sz > 1024*1024) { fclose(fp); return 0; }
    char *buf = MALLOC((size_t)sz + 1);
    if (!buf) { fclose(fp); return 0; }
    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp); buf[n] = 0;
    JsonNode *root = json_decode(buf);
    FREE(buf);
    unsigned out = 0;
    if (root && root->tag == JSON_OBJECT) {
        JsonNode *t = json_find_member(root, "timeout_sec");
        if (t && t->tag == JSON_NUMBER && t->number_ > 0)
            out = (unsigned)t->number_;
    }
    if (root) json_delete(root);
    return out;
}

int scan_request_build_argv(const char *filename, int *argc_out,
                            char ***argv_out) {
    FILE *fp = file_open_utf8_mode(filename, "rb");
    if (!fp) { req_error(ERR_IO_ERROR, "cannot open scan request"); return -1; }
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); rewind(fp);
    if (sz <= 0 || sz > 1024*1024) { fclose(fp); req_error(ERR_INVALID_ARGUMENT,"bad request size"); return -1; }
    char *buf = MALLOC((size_t)sz + 1);
    if (!buf || fread(buf,1,(size_t)sz,fp)!=(size_t)sz) { fclose(fp); FREE(buf); req_error(ERR_IO_ERROR,"read failed"); return -1; }
    fclose(fp); buf[sz]=0;
    JsonNode *root = json_decode(buf);
    FREE(buf);
    if (!root || root->tag != JSON_OBJECT) { req_error(ERR_INVALID_JSON,"request must be a JSON object"); if(root) json_delete(root); return -1; }
    for (JsonNode *n=root->children.head; n; n=n->next)
        if (!allowed(n->key ? n->key : "")) { req_error(ERR_INVALID_ARGUMENT,"unknown field"); json_delete(root); return -1; }
    JsonNode *scan=json_find_member(root,"scan"), *targets=json_find_member(root,"targets");
    JsonNode *inc=json_find_member(root,"include_file");
    bool has_targets = targets && targets->tag == JSON_ARRAY && targets->children.head;
    bool has_file = inc && inc->tag == JSON_STRING && inc->string_[0];
    if (!scan || scan->tag!=JSON_STRING || (!has_targets && !has_file)) {
        req_error(ERR_INVALID_ARGUMENT,"scan and targets or include_file are required"); json_delete(root); return -1;
    }
    if (has_targets && has_file) {
        req_error(ERR_INVALID_ARGUMENT,"targets and include_file are mutually exclusive");
        json_delete(root); return -1;
    }
    if (!get_scan_module_by_name(scan->string_)) {
        req_error(ERR_UNSUPPORTED_SCAN, "unknown scan module");
        json_delete(root);
        return -1;
    }
    JsonNode *probe_check = json_find_member(root, "probe");
    if (probe_check) {
        if (probe_check->tag != JSON_STRING ||
            !get_probe_module_by_name(probe_check->string_)) {
            req_error(ERR_UNSUPPORTED_PROBE, "unknown probe module");
            json_delete(root);
            return -1;
        }
    }
    for (JsonNode *n = has_targets ? targets->children.head : NULL; n; n = n->next) {
        if (n->tag != JSON_STRING) {
            req_error(ERR_TARGET_INVALID, "target must be a string");
            json_delete(root); return -1;
        }
        const char *t = n->string_;
        size_t off = 0;
        struct Range  r4;
        struct Range6 r6;
        while (off < strlen(t)) {
            if (target_parse_range(t, &off, strlen(t), &r4, &r6) ==
                Bad_Address) {
                req_error(ERR_TARGET_INVALID, "invalid target address/range");
                json_delete(root); return -1;
            }
        }
    }
    char *ip = has_targets ? join_array(targets,false) : NULL;
    if (has_targets && !ip) { req_error(ERR_TARGET_INVALID,"invalid targets"); json_delete(root); return -1; }
    JsonNode *ga = json_find_member(root, "global_args");
    size_t ga_count = 0;
    if (ga) {
        if (ga->tag != JSON_OBJECT) {
            req_error(ERR_INVALID_ARGUMENT, "global_args must be an object");
            json_delete(root);
            return -1;
        }
        for (JsonNode *n = ga->children.head; n; n = n->next) ga_count++;
    }
    char **argv = CALLOC(36 + 2 * ga_count + 1, sizeof(char*)); int ac=0;
    argv[ac++] = STRDUP("xtate");
    argv[ac++] = STRDUP("-scan"); argv[ac++] = STRDUP(scan->string_);
    JsonNode *probe=json_find_member(root,"probe");
    if (probe) { if(probe->tag!=JSON_STRING){req_error(ERR_INVALID_ARGUMENT,"probe must be string");} argv[ac++]=STRDUP("-probe"); argv[ac++]=STRDUP(probe->string_); }
    if (has_targets) { argv[ac++]=STRDUP("-ip"); argv[ac++]=ip; }
    else { argv[ac++]=STRDUP("--include-file"); argv[ac++]=STRDUP(inc->string_); }
    JsonNode *ports=json_find_member(root,"ports");
    if (ports) { char *p=join_array(ports,true); if(!p){req_error(ERR_INVALID_ARGUMENT,"invalid ports");} argv[ac++]=STRDUP("-p"); argv[ac++]=p; }
    JsonNode *rate=json_find_member(root,"rate");
    if (rate && rate->tag==JSON_NUMBER) {
        double rv = rate->number_;
        if (!isfinite(rv) || rv < 0 || rv > 10000) {
            req_error(ERR_INVALID_ARGUMENT, "rate must be finite and in 0..10000");
            json_delete(root); return -1;
        }
        char t[32]; snprintf(t,sizeof(t),"%d",(int)rv);
        argv[ac++]=STRDUP("-rate"); argv[ac++]=STRDUP(t);
    }
    JsonNode *pa=json_find_member(root,"probe_args"); char *pas=args_string(pa);
    if (pas) { argv[ac++]=STRDUP("-probe-arg"); argv[ac++]=pas; }
    JsonNode *sa=json_find_member(root,"scan_args"); char *sas=args_string(sa);
    if (sas) { argv[ac++]=STRDUP("-scan-arg"); argv[ac++]=sas; }
    if (ga) {
        for (JsonNode *n = ga->children.head; n; n = n->next) {
            const char *name = n->key ? n->key : "";
            if (!scan_request_global_arg_allowed(name)) {
                req_error(ERR_INVALID_ARGUMENT, "global_args contains an unsupported option");
                for (int i=0;i<ac;i++) free(argv[i]);
                free(argv); json_delete(root); return -1;
            }
            if (scan_request_global_arg_is_flag(name)) {
                if (n->tag != JSON_BOOL) {
                    req_error(ERR_INVALID_ARGUMENT, "global flag arguments must be true or false");
                    for (int i=0;i<ac;i++) free(argv[i]);
                    free(argv); json_delete(root); return -1;
                }
                if (n->bool_) {
                    size_t ln = strlen(name) + 3;
                    char *a = MALLOC(ln);
                    snprintf(a, ln, "--%s", name);
                    argv[ac++] = a;
                }
            } else {
                char num[64];
                const char *val = NULL;
                if (n->tag == JSON_STRING) val = n->string_;
                else if (n->tag == JSON_NUMBER) {
                    snprintf(num, sizeof(num), "%.17g", n->number_);
                    val = num;
                }
                if (!val) {
                    req_error(ERR_INVALID_ARGUMENT, "global argument values must be strings or numbers");
                    for (int i=0;i<ac;i++) free(argv[i]);
                    free(argv); json_delete(root); return -1;
                }
                if (!scan_request_global_arg_value_valid(name, val)) {
                    req_error(ERR_INVALID_ARGUMENT, "invalid value for a global argument");
                    for (int i=0;i<ac;i++) free(argv[i]);
                    free(argv); json_delete(root); return -1;
                }
                size_t ln = strlen(name) + strlen(val) + 4;
                char *a = MALLOC(ln);
                snprintf(a, ln, "--%s=%s", name, val);
                argv[ac++] = a;
            }
        }
    }
    JsonNode *dry=json_find_member(root,"dry_run");
    if (dry && dry->tag==JSON_BOOL && dry->bool_) argv[ac++]=STRDUP("--list-target");
    argv[ac]=NULL; *argc_out=ac; *argv_out=argv; json_delete(root); return 0;
}
