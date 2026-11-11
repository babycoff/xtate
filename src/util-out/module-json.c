#include "module-json.h"
#include <stdio.h>
#include <string.h>
#include "../probe-modules/probe-modules.h"
#include "../scan-modules/scan-modules.h"
#include "../output-modules/output-modules.h"
#include "../generate-modules/generate-modules.h"
#include "../util-data/json-escape.h"

extern Scanner   *scan_modules_list[];
extern Probe     *probe_modules_list[];
extern Output    *output_modules_list[];
extern Generator *generate_modules_list[];

static void out_sink(void *ctx, const char *data, size_t len) {
    fwrite(data, 1, len, (FILE *)ctx);
}
static void jstr(const char *s) {
    fputc('"', stdout);
    if (s) json_escape_to(out_sink, stdout, (const unsigned char *)s, strlen(s));
    fputc('"', stdout);
}
static void jparams(ConfParam *p) {
    fputc('[', stdout);
    for (int first = 1; p && p->name; p++) {
        if (!first) fputc(',', stdout);
        first = 0;
        fputc('{', stdout);
        fputs("\"name\":", stdout); jstr(p->name);
        fputs(",\"type\":", stdout); jstr(p->type == Type_FLAG ? "flag" : "arg");
        fputs(",\"description\":", stdout); jstr(p->help_text);
        fputs(",\"aliases\":[", stdout);
        for (int i = 0; i < 8 && p->alt_names[i]; i++) {
            if (i) fputc(',', stdout); jstr(p->alt_names[i]);
        }
        fputs("]}", stdout);
    }
    fputc(']', stdout);
}
static const char *ptype(ProbeType t) {
    switch (t) { case ProbeType_TCP: return "tcp"; case ProbeType_UDP: return "udp"; case ProbeType_STATE: return "state"; default: return "none"; }
}
void list_modules_json(void) {
    fputs("{\"modules\":[", stdout);
    int first = 1;
    for (int i = 0; scan_modules_list[i]; i++) {
        Scanner *m = scan_modules_list[i];
        if (!first) fputc(',', stdout); first = 0;
        fputs("{\"name\":", stdout); jstr(m->name);
        fputs(",\"kind\":\"scan\",\"probe_type\":", stdout); jstr(ptype(m->required_probe_type));
        fputs(",\"short_description\":", stdout); jstr(m->short_desc);
        fputs(",\"description\":", stdout); jstr(m->desc);
        fputs(",\"parameters\":", stdout); jparams(m->params);
        fputc('}', stdout);
    }
    for (int i = 0; probe_modules_list[i]; i++) {
        Probe *m = probe_modules_list[i];
        if (!first) fputc(',', stdout); first = 0;
        fputs("{\"name\":", stdout); jstr(m->name);
        fputs(",\"kind\":\"probe\",\"probe_type\":", stdout); jstr(ptype(m->type));
        fputs(",\"short_description\":", stdout); jstr(m->short_desc);
        fputs(",\"description\":", stdout); jstr(m->desc);
        fputs(",\"parameters\":", stdout); jparams(m->params);
        fputc('}', stdout);
    }
    for (int i = 0; output_modules_list[i]; i++) {
        Output *m = output_modules_list[i];
        if (!first) fputc(',', stdout); first = 0;
        fputs("{\"name\":", stdout); jstr(m->name);
        fputs(",\"kind\":\"output\",\"short_description\":", stdout); jstr(m->short_desc);
        fputs(",\"description\":", stdout); jstr(m->desc);
        fputs(",\"parameters\":", stdout); jparams(m->params);
        fputc('}', stdout);
    }
    for (int i = 0; generate_modules_list[i]; i++) {
        Generator *m = generate_modules_list[i];
        if (!first) fputc(',', stdout); first = 0;
        fputs("{\"name\":", stdout); jstr(m->name);
        fputs(",\"kind\":\"generate\",\"short_description\":", stdout); jstr(m->short_desc);
        fputs(",\"description\":", stdout); jstr(m->desc);
        fputs(",\"parameters\":", stdout); jparams(m->params);
        fputc('}', stdout);
    }
    fputs("]}\n", stdout);
}
