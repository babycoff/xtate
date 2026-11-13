#include "capabilities.h"

#include "../crypto/crypto-json.h"
#include "../util-out/module-json.h"
#include "../version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void count_kind(JsonNode *root, const char *kind, int *out) {
    JsonNode *modules = json_find_member(root, "modules");
    JsonNode *m;
    if (!modules || modules->tag != JSON_ARRAY) return;
    json_foreach(m, modules) {
        JsonNode *k = json_find_member(m, "kind");
        JsonNode *n = json_find_member(m, "name");
        if (!k || k->tag != JSON_STRING || !k->string_) continue;
        if (strcmp(k->string_, kind) != 0) continue;
        (*out)++;
        (void)n;
    }
}

char *capabilities_json(void) {
    char *catalog = module_json_string();
    JsonNode *root;
    JsonNode *modules;
    JsonNode *out;
    char *text;
    int scan = 0, probe = 0, output = 0, generate = 0;

    if (!catalog) return NULL;
    root = json_decode(catalog);
    free(catalog);
    if (!root || root->tag != JSON_OBJECT) {
        if (root) json_delete(root);
        return NULL;
    }
    count_kind(root, "scan", &scan);
    count_kind(root, "probe", &probe);
    count_kind(root, "output", &output);
    count_kind(root, "generate", &generate);

    out = json_mkobject();
    if (!out) { json_delete(root); return NULL; }
    json_append_member(out, "version", json_mkstring(XTATE_VERSION));
#ifdef _WIN32
    json_append_member(out, "platform", json_mkstring("windows"));
    json_append_member(out, "raw_sockets", json_mkbool(1));
#else
    json_append_member(out, "platform", json_mkstring("linux"));
    json_append_member(out, "raw_sockets", json_mkbool(1));
#endif
#ifdef HAVE_NGTCP2
    json_append_member(out, "http3", json_mkbool(1));
    json_append_member(out, "quic_transport", json_mkbool(1));
    json_append_member(out, "http3_reason", json_mknull());
#else
    json_append_member(out, "http3", json_mkbool(0));
    json_append_member(out, "quic_transport", json_mkbool(0));
#ifdef _WIN32
    json_append_member(out, "http3_reason",
                       json_mkstring("HTTP/3 requires ngtcp2/GnuTLS; not built for Windows"));
#else
    json_append_member(out, "http3_reason",
                       json_mkstring("HTTP/3 requires ngtcp2/GnuTLS; not present in this build"));
#endif
#endif
    modules = json_mkobject();
    json_append_member(modules, "scan", json_mknumber((double)scan));
    json_append_member(modules, "probe", json_mknumber((double)probe));
    json_append_member(modules, "output", json_mknumber((double)output));
    json_append_member(modules, "generate", json_mknumber((double)generate));
    json_append_member(out, "modules", modules);

    text = json_stringify(out, NULL);
    json_delete(out);
    json_delete(root);
    return text;
}
