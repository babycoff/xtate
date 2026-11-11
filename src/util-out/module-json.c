#include "module-json.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <process.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif
#include <string.h>
#include "../probe-modules/probe-modules.h"
#include "../scan-modules/scan-modules.h"
#include "../output-modules/output-modules.h"
#include "../generate-modules/generate-modules.h"
#include "../util-data/json-escape.h"
#include "../crypto/crypto-json.h"

static FILE *g_out = NULL;

extern Scanner   *scan_modules_list[];
extern Probe     *probe_modules_list[];
extern Output    *output_modules_list[];
extern Generator *generate_modules_list[];

static void out_sink(void *ctx, const char *data, size_t len) {
    fwrite(data, 1, len, (FILE *)ctx);
}
static void jstr(const char *s) {
    fputc('"', g_out);
    if (s) json_escape_to(out_sink, g_out, (const unsigned char *)s, strlen(s));
    fputc('"', g_out);
}
static void jparams(ConfParam *p) {
    fputc('[', g_out);
    for (int first = 1; p && p->name; p++) {
        if (!first) fputc(',', g_out);
        first = 0;
        fputc('{', g_out);
        fputs("\"name\":", g_out); jstr(p->name);
        fputs(",\"type\":", g_out); jstr(p->type == Type_FLAG ? "flag" : "arg");
        fputs(",\"description\":", g_out); jstr(p->help_text);
        fputs(",\"aliases\":[", g_out);
        for (int i = 0; i < 8 && p->alt_names[i]; i++) {
            if (i) fputc(',', g_out); jstr(p->alt_names[i]);
        }
        fputs("]}", g_out);
    }
    fputc(']', g_out);
}
static const char *ptype(ProbeType t) {
    switch (t) { case ProbeType_TCP: return "tcp"; case ProbeType_UDP: return "udp"; case ProbeType_STATE: return "state"; default: return "none"; }
}
void list_modules_json(void) {
    if (!g_out) g_out = stdout;
    fputs("{\"modules\":[", g_out);
    int first = 1;
    for (int i = 0; scan_modules_list[i]; i++) {
        Scanner *m = scan_modules_list[i];
        if (!first) fputc(',', g_out); first = 0;
        fputs("{\"name\":", g_out); jstr(m->name);
        fputs(",\"kind\":\"scan\",\"probe_type\":", g_out); jstr(ptype(m->required_probe_type));
        fputs(",\"short_description\":", g_out); jstr(m->short_desc);
        fputs(",\"description\":", g_out); jstr(m->desc);
        fputs(",\"parameters\":", g_out); jparams(m->params);
        fputc('}', g_out);
    }
    for (int i = 0; probe_modules_list[i]; i++) {
        Probe *m = probe_modules_list[i];
        if (!first) fputc(',', g_out); first = 0;
        fputs("{\"name\":", g_out); jstr(m->name);
        fputs(",\"kind\":\"probe\",\"probe_type\":", g_out); jstr(ptype(m->type));
        fputs(",\"short_description\":", g_out); jstr(m->short_desc);
        fputs(",\"description\":", g_out); jstr(m->desc);
        fputs(",\"parameters\":", g_out); jparams(m->params);
        fputc('}', g_out);
    }
    for (int i = 0; output_modules_list[i]; i++) {
        Output *m = output_modules_list[i];
        if (!first) fputc(',', g_out); first = 0;
        fputs("{\"name\":", g_out); jstr(m->name);
        fputs(",\"kind\":\"output\",\"short_description\":", g_out); jstr(m->short_desc);
        fputs(",\"description\":", g_out); jstr(m->desc);
        fputs(",\"parameters\":", g_out); jparams(m->params);
        fputc('}', g_out);
    }
    for (int i = 0; generate_modules_list[i]; i++) {
        Generator *m = generate_modules_list[i];
        if (!first) fputc(',', g_out); first = 0;
        fputs("{\"name\":", g_out); jstr(m->name);
        fputs(",\"kind\":\"generate\",\"short_description\":", g_out); jstr(m->short_desc);
        fputs(",\"description\":", g_out); jstr(m->desc);
        fputs(",\"parameters\":", g_out); jparams(m->params);
        fputc('}', g_out);
    }
    fputs("]}\n", g_out);
}

char *module_json_string(void) {
    const char *tmpdir = getenv("TMPDIR");
#ifdef _WIN32
    if (!tmpdir || !tmpdir[0]) tmpdir = getenv("TEMP");
#endif
    if (!tmpdir || !tmpdir[0]) tmpdir = "/tmp";
    char tmppath[1200];
    snprintf(tmppath, sizeof(tmppath), "%s/xtate-modules-%ld.tmp", tmpdir,
             (long)getpid());
    FILE *f = fopen(tmppath, "w+b");
    if (!f) {
        snprintf(tmppath, sizeof(tmppath), "xtate-modules-%ld.tmp", (long)getpid());
        f = fopen(tmppath, "w+b");
    }
    if (!f) return NULL;
    FILE *old = g_out;
    g_out = f;
    list_modules_json();
    fflush(f); rewind(f);
    fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (buf && fread(buf, 1, (size_t)n, f) == (size_t)n) buf[n] = 0;
    else { free(buf); buf = NULL; }
    fclose(f); remove(tmppath); g_out = old ? old : stdout;
    return buf;
}

char *module_json_describe(const char *name) {
    char *all = module_json_string();
    if (!all || !name) { free(all); return NULL; }
    JsonNode *root = json_decode(all);
    free(all);
    char *out = NULL;
    if (root && root->tag == JSON_OBJECT) {
        JsonNode *mods = json_find_member(root, "modules");
        for (JsonNode *m = mods ? mods->children.head : NULL; m; m = m->next) {
            JsonNode *n = json_find_member(m, "name");
            if (n && n->tag == JSON_STRING && strcmp(n->string_, name) == 0) {
                out = json_encode(m);
                break;
            }
        }
    }
    if (root) json_delete(root);
    return out;
}
