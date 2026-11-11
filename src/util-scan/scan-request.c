#include "scan-request.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
                               "scan_args","rate","timeout_sec","dry_run",0};
    for (int i=0; ok[i]; i++) if (strcmp(name, ok[i]) == 0) return true;
    return false;
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

static char *args_string(JsonNode *obj) {
    if (!obj || obj->tag != JSON_OBJECT) return NULL;
    size_t cap = 128, len = 0;
    char *out = MALLOC(cap);
    if (!out) return NULL;
    for (JsonNode *n = obj->children.head; n; n = n->next) {
        char tmp[512];
        char keybuf[256];
        snprintf(keybuf, sizeof(keybuf), "%s", n->key ? n->key : "");
        for (char *p=keybuf; *p; p++) if (*p=='_') *p='-';
        const char *key = keybuf;
        if (n->tag == JSON_BOOL) {
            if (!n->bool_) continue;
            snprintf(tmp, sizeof(tmp), "--%s", key);
        } else if (n->tag == JSON_STRING) {
            snprintf(tmp, sizeof(tmp), "--%s=%s", key, n->string_);
        } else if (n->tag == JSON_NUMBER) {
            snprintf(tmp, sizeof(tmp), "--%s=%g", key, n->number_);
        } else return NULL;
        size_t need = strlen(tmp) + (len ? 1 : 0) + 1;
        if (len + need > cap) {
            cap = (len + need) * 2;
            char *p = REALLOC(out, cap);
            if (!p) { FREE(out); return NULL; }
            out = p;
        }
        if (len) out[len++] = ' ';
        memcpy(out + len, tmp, strlen(tmp));
        len += strlen(tmp);
    }
    out[len] = 0;
    return len ? out : NULL;
}

int scan_request_build_argv(const char *filename, int *argc_out,
                            char ***argv_out) {
    FILE *fp = fopen(filename, "rb");
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
    if (!scan || scan->tag!=JSON_STRING || !targets || targets->tag!=JSON_ARRAY || !targets->children.head) {
        req_error(ERR_INVALID_ARGUMENT,"scan and non-empty targets are required"); json_delete(root); return -1;
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
    for (JsonNode *n = targets->children.head; n; n = n->next) {
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
    char *ip=join_array(targets,false); if (!ip) { req_error(ERR_TARGET_INVALID,"invalid targets"); json_delete(root); return -1; }
    char **argv = CALLOC(32, sizeof(char*)); int ac=0;
    argv[ac++] = STRDUP("xtate");
    argv[ac++] = STRDUP("-scan"); argv[ac++] = STRDUP(scan->string_);
    JsonNode *probe=json_find_member(root,"probe");
    if (probe) { if(probe->tag!=JSON_STRING){req_error(ERR_INVALID_ARGUMENT,"probe must be string");} argv[ac++]=STRDUP("-probe"); argv[ac++]=STRDUP(probe->string_); }
    argv[ac++]=STRDUP("-ip"); argv[ac++]=ip;
    JsonNode *ports=json_find_member(root,"ports");
    if (ports) { char *p=join_array(ports,true); if(!p){req_error(ERR_INVALID_ARGUMENT,"invalid ports");} argv[ac++]=STRDUP("-p"); argv[ac++]=p; }
    JsonNode *rate=json_find_member(root,"rate");
    if (rate && rate->tag==JSON_NUMBER) { char t[32]; snprintf(t,sizeof(t),"%d",(int)rate->number_); argv[ac++]=STRDUP("-rate"); argv[ac++]=STRDUP(t); }
    JsonNode *pa=json_find_member(root,"probe_args"); char *pas=args_string(pa);
    if (pas) { argv[ac++]=STRDUP("-probe-arg"); argv[ac++]=pas; }
    JsonNode *sa=json_find_member(root,"scan_args"); char *sas=args_string(sa);
    if (sas) { argv[ac++]=STRDUP("-scan-arg"); argv[ac++]=sas; }
    JsonNode *dry=json_find_member(root,"dry_run");
    if (dry && dry->tag==JSON_BOOL && dry->bool_) argv[ac++]=STRDUP("--list-target");
    argv[ac]=NULL; *argc_out=ac; *argv_out=argv; json_delete(root); return 0;
}
