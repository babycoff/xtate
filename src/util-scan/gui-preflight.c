/*
    Xtate GUI: server-side scan preflight.

    This module validates the New scan form without sending a packet.  It is
    deliberately independent of the child scan process: the browser gets an
    authoritative target count, route/interface/link-type report, and a list
    of blocking errors before the authorization checkbox can unlock Start.
*/

#include "gui-data.h"
#include "scan-request.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../crypto/crypto-json.h"
#include "../util-out/module-json.h"
#include "../rawsock/rawsock.h"
#include "../rawsock/rawsock-route.h"
#include "../stub/stub-pcap-dlt.h"
#include "../target/target-set.h"

#define GUI_PREFLIGHT_SAMPLES 64

static JsonNode *member(JsonNode *root, const char *name) {
    return json_find_member(root, name);
}

/* Port protocol offsets used by targetset_add_port_str().  Plain ports are
 * assigned to the scan engine's protocol so a TCP scan cannot be reported as
 * ready while its UDP-only port list would produce zero packets. */
enum {
    PREFLIGHT_PROTO_NONE = 0,
    PREFLIGHT_PROTO_TCP = 1,
    PREFLIGHT_PROTO_UDP = 2,
    PREFLIGHT_PROTO_SCTP = 3,
};

static int scan_expected_proto(const char *name) {
    if (!name) return PREFLIGHT_PROTO_NONE;
    if (strcmp(name, "tcp-syn") == 0 || strcmp(name, "zbanner") == 0 ||
        strcmp(name, "tcp-state") == 0)
        return PREFLIGHT_PROTO_TCP;
    if (strcmp(name, "udp") == 0 || strcmp(name, "yarrp-udp") == 0)
        return PREFLIGHT_PROTO_UDP;
    if (strcmp(name, "sctp-init") == 0) return PREFLIGHT_PROTO_SCTP;
    return PREFLIGHT_PROTO_NONE;
}

static unsigned proto_offset(int proto) {
    switch (proto) {
    case PREFLIGHT_PROTO_UDP: return 65536u;
    case PREFLIGHT_PROTO_SCTP: return 131072u;
    default: return 0u;
    }
}

static const char *scan_probe_type(const char *name) {
    if (!name) return NULL;
    if (strcmp(name, "zbanner") == 0) return "tcp";
    if (strcmp(name, "udp") == 0) return "udp";
    if (strcmp(name, "tcp-state") == 0 || strcmp(name, "quic-state") == 0)
        return "state";
    return NULL;
}

static int catalog_probe_type(const char *name, char *out, size_t cap) {
    char *catalog = module_json_string();
    JsonNode *root;
    JsonNode *mods;
    JsonNode *m;
    int found = 0;
    if (!catalog) return -1;
    root = json_decode(catalog);
    free(catalog);
    if (!root) return -1;
    mods = json_find_member(root, "modules");
    if (mods && mods->tag == JSON_ARRAY) {
        for (m = mods->children.head; m; m = m->next) {
            JsonNode *k = json_find_member(m, "kind");
            JsonNode *n = json_find_member(m, "name");
            if (k && n && k->tag == JSON_STRING && n->tag == JSON_STRING &&
                strcmp(k->string_, "probe") == 0 &&
                strcmp(n->string_, name) == 0) {
                JsonNode *t = json_find_member(m, "probe_type");
                if (t && t->tag == JSON_STRING && t->string_) {
                    snprintf(out, cap, "%s", t->string_);
                    found = 1;
                }
                break;
            }
        }
    }
    json_delete(root);
    return found;
}

static int catalog_has(const char *kind, const char *name) {
    char *catalog = module_json_string();
    JsonNode *root;
    JsonNode *mods;
    JsonNode *m;
    int found = 0;
    if (!catalog) return -1;
    root = json_decode(catalog);
    free(catalog);
    if (!root) return -1;
    mods = json_find_member(root, "modules");
    if (mods && mods->tag == JSON_ARRAY) {
        for (m = mods->children.head; m; m = m->next) {
            JsonNode *k = json_find_member(m, "kind");
            JsonNode *n = json_find_member(m, "name");
            if (k && n && k->tag == JSON_STRING && n->tag == JSON_STRING &&
                strcmp(k->string_, kind) == 0 &&
                strcmp(n->string_, name) == 0) {
                found = 1;
                break;
            }
        }
    }
    json_delete(root);
    return found;
}

/* JSON tool clients send arrays; the GUI sends comma-separated strings.
 * Normalize both forms to the target-set parser's string input. */
static char *join_string_array(JsonNode *node, int allow_numbers) {
    size_t cap = 64, len = 0;
    char *out;
    JsonNode *item;

    if (!node || node->tag != JSON_ARRAY) return NULL;
    out = (char *)malloc(cap);
    if (!out) return NULL;
    out[0] = 0;
    for (item = node->children.head; item; item = item->next) {
        char num[64];
        const char *s = NULL;
        size_t need;
        char *grown;
        if (item->tag == JSON_STRING) {
            s = item->string_;
        } else if (allow_numbers && item->tag == JSON_NUMBER) {
            snprintf(num, sizeof(num), "%.17g", item->number_);
            s = num;
        }
        if (!s || !s[0]) {
            free(out);
            return NULL;
        }
        need = strlen(s) + 2;
        if (len + need > cap) {
            while (len + need > cap) cap *= 2;
            grown = (char *)realloc(out, cap);
            if (!grown) { free(out); return NULL; }
            out = grown;
        }
        if (len) out[len++] = ',';
        memcpy(out + len, s, strlen(s));
        len += strlen(s);
        out[len] = 0;
    }
    return out;
}

static void add_message(JsonNode *root, const char *kind, const char *message) {
    JsonNode *array = member(root, kind);
    if (array && array->tag == JSON_ARRAY)
        json_append_element(array, json_mkstring(message));
}

static void add_error(JsonNode *root, const char *message) {
    add_message(root, "errors", message);
}

static void add_warning(JsonNode *root, const char *message) {
    add_message(root, "warnings", message);
}

static uint64_t count_proto_ports(const TargetSet *targets, int proto) {
    unsigned base = proto_offset(proto);
    unsigned limit = base + 65535u;
    uint64_t count = 0;
    unsigned i;
    for (i = 0; i < targets->ports.list_len; i++) {
        unsigned lo = targets->ports.list[i].begin;
        unsigned hi = targets->ports.list[i].end;
        if (lo < base) lo = base;
        if (hi > limit) hi = limit;
        if (lo <= hi) count += (uint64_t)(hi - lo) + 1u;
    }
    return count;
}

static int add_group(JsonNode *routes, const char *ifname,
                     const RawRoute *route) {
    JsonNode *group;
    struct ipaddress_formatted src;
    struct ipaddress_formatted gw;
    unsigned link_type = 0;
    int have_link;
    const char *link_name;

    for (group = routes->children.head; group; group = group->next) {
        JsonNode *name = member(group, "interface");
        if (name && name->tag == JSON_STRING && name->string_ &&
            strcmp(name->string_, ifname) == 0)
            return 0;
    }

    group = json_mkobject();
    if (!group) return -1;
    json_append_member(group, "interface", json_mkstring(ifname));

    src = ipaddress_fmt(route->source_ip);
    gw  = ipaddress_fmt(route->gateway);
    json_append_member(group, "source", json_mkstring(src.string));
    json_append_member(group, "gateway", json_mkstring(gw.string));

    have_link = rawsock_get_adapter_link_type(ifname, &link_type) == 0;
    if (have_link) {
        link_name = rawsock_link_type_name(link_type);
        json_append_member(group, "link_type", json_mknumber(link_type));
        json_append_member(group, "link_type_name",
                           json_mkstring(link_name ? link_name : "unknown"));
        json_append_member(group, "raw_capable",
                           json_mkbool(link_type == PCAP_DLT_NULL ||
                                       link_type == PCAP_DLT_ETHERNET ||
                                       link_type == PCAP_DLT_RAW));
    } else {
        json_append_member(group, "link_type", json_mknull());
        json_append_member(group, "link_type_name",
                           json_mkstring("unavailable"));
        json_append_member(group, "raw_capable", json_mkbool(0));
    }
    json_append_element(routes, group);
    return 1;
}

char *gui_preflight_json(const char *body) {
    JsonNode *root = NULL;
    JsonNode *input = NULL;
    JsonNode *errors;
    JsonNode *warnings;
    JsonNode *routes;
    JsonNode *iface_json = NULL;
    JsonNode *targets_node;
    JsonNode *ports_node;
    JsonNode *scan_node;
    JsonNode *probe_node;
    JsonNode *rate_node;
    JsonNode *timeout_node;
    JsonNode *iface_node;
    char *targets_join = NULL;
    char *ports_join = NULL;
    const char *targets_text = NULL;
    const char *ports_text = NULL;
    TargetSet targets = {0};
    int128_t total;
    uint64_t ip_count;
    uint64_t samples;
    uint64_t i;
    unsigned ports;
    double attempts;
    int ok = 1;
    int rate = 1000;
    int timeout_sec = 300;
    const char *iface = NULL;
    const char *scan_name = NULL;
    const char *probe_name = NULL;
    const char *probe_required = NULL;
    int scan_proto = PREFLIGHT_PROTO_NONE;
    int port_scoped = 0;
    char probe_type[32] = {0};
    char *text;

    root = json_mkobject();
    if (!root) return NULL;
    errors   = json_mkarray();
    warnings = json_mkarray();
    routes   = json_mkarray();
    if (!errors || !warnings || !routes) {
        json_delete(errors);
        json_delete(warnings);
        json_delete(routes);
        json_delete(root);
        return NULL;
    }
    json_append_member(root, "errors", errors);
    json_append_member(root, "warnings", warnings);
    json_append_member(root, "routes", routes);

    input = json_decode(body);
    if (!input || input->tag != JSON_OBJECT) {
        add_error(root, "request body must be a JSON object");
        ok = 0;
        goto done;
    }

    {
        static const char *known[] = {
            "scan", "probe", "targets", "include_file", "ports", "rate",
            "timeout_sec", "interface", "scan_args", "probe_args",
            "global_args", "chunk_size", "quota_bytes", "compression",
            "index", "dry_run", "authorized"
        };
        JsonNode *f;
        for (f = input->children.head; f; f = f->next) {
            size_t i; int okfield = 0;
            for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
                if (f->key && strcmp(f->key, known[i]) == 0) { okfield = 1; break; }
            }
            if (!okfield)
                add_error(root, "unknown field in preflight request");
        }
        if (member(input, "include_file"))
            add_error(root, "preflight does not support include_file; use explain_target for route checks");
    }

    targets_node = member(input, "targets");
    ports_node   = member(input, "ports");
    scan_node    = member(input, "scan");
    probe_node   = member(input, "probe");
    rate_node    = member(input, "rate");
    timeout_node = member(input, "timeout_sec");
    iface_node   = member(input, "interface");

    if (scan_node && scan_node->tag == JSON_STRING && scan_node->string_ &&
        scan_node->string_[0])
        scan_name = scan_node->string_;
    if (probe_node && probe_node->tag == JSON_STRING && probe_node->string_ &&
        probe_node->string_[0])
        probe_name = probe_node->string_;
    else if (probe_node && probe_node->tag != JSON_NULL &&
             probe_node->tag != JSON_STRING)
        add_error(root, "probe must be a string");
    if (!scan_name) {
        add_error(root, "scan is required");
    } else {
        int has_scan = catalog_has("scan", scan_name);
        if (has_scan < 0)
            add_error(root, "module catalog is unavailable");
        else if (!has_scan)
            add_error(root, "unknown scan module");
        else {
            scan_proto = scan_expected_proto(scan_name);
            probe_required = scan_probe_type(scan_name);
            port_scoped = scan_proto != PREFLIGHT_PROTO_NONE;
        }
    }
    if (probe_required && !probe_name)
        add_error(root, "probe is required for this scan");
    if (!probe_required && probe_name)
        add_error(root, "this scan does not accept a probe");
    if (probe_name) {
        if (catalog_probe_type(probe_name, probe_type, sizeof(probe_type)) != 1)
            add_error(root, "unknown probe module");
        else if (probe_required && strcmp(probe_type, probe_required) != 0)
            add_error(root, "probe type does not match the scan engine");
    }
    if (targets_node && targets_node->tag == JSON_STRING) {
        targets_text = targets_node->string_;
    } else if (targets_node && targets_node->tag == JSON_ARRAY) {
        targets_join = join_string_array(targets_node, 0);
        if (targets_join)
            targets_text = targets_join;
        else
            add_error(root, "targets must be strings or an array of strings");
    } else if (targets_node && targets_node->tag != JSON_NULL) {
        add_error(root, "targets must be a string or an array of strings");
    }
    if (!targets_text || !targets_text[0]) {
        add_error(root, "targets are required");
    } else if (targetset_add_ip_str(&targets, targets_text) != 0) {
        add_error(root, "one or more targets could not be parsed");
    }

    if (ports_node && ports_node->tag == JSON_STRING) {
        ports_text = ports_node->string_;
    } else if (ports_node && ports_node->tag == JSON_ARRAY) {
        ports_join = join_string_array(ports_node, 1);
        if (ports_join)
            ports_text = ports_join;
        else
            add_error(root, "ports must be numbers or an array of strings/numbers");
    } else if (ports_node && ports_node->tag != JSON_NULL) {
        add_error(root, "ports must be a string or an array");
    }
    if (port_scoped) {
        if (!ports_text || !ports_text[0]) {
            add_error(root, "ports are required for this scan");
        } else if (targetset_add_port_str(&targets, ports_text,
                                          proto_offset(scan_proto)) != 0) {
            add_error(root,
                  "ports could not be parsed (use 80,443,8000-8100)");
        }
    } else {
        /* Keep one non-port slot so targetset_count() returns the address
         * count; the scan engine itself sends no port-based packets. */
        if (targetset_add_port_str(&targets, "o:0", 0) != 0)
            add_error(root, "could not initialize target set");
    }
    JsonNode *global_node = member(input, "global_args");
    if (global_node) {
        int gcount = 0;
        if (global_node->tag != JSON_OBJECT) {
            add_error(root, "global_args must be an object");
        } else {
            for (JsonNode *n = global_node->children.head; n; n = n->next) {
                const char *name = n->key ? n->key : "";
                char num[64];
                const char *val = NULL;
                if (++gcount > 24) {
                    add_error(root, "too many global parameters (maximum 24)");
                    break;
                }
                if (!scan_request_global_arg_allowed(name)) {
                    add_error(root, "global_args contains an option the GUI cannot set");
                    continue;
                }
                if (scan_request_global_arg_is_flag(name)) {
                    if (n->tag != JSON_BOOL)
                        add_error(root, "global flag parameters must be true or false");
                    continue;
                }
                if (n->tag == JSON_STRING) val = n->string_;
                else if (n->tag == JSON_NUMBER) {
                    snprintf(num, sizeof(num), "%.17g", n->number_);
                    val = num;
                }
                if (!val) {
                    add_error(root, "global argument values must be strings or numbers");
                } else if (strlen(val) > 512) {
                    add_error(root, "a global argument value is too long (maximum 512 bytes)");
                } else if (!scan_request_global_arg_value_valid(name, val)) {
                    add_error(root, "a global argument has an invalid value");
                }
            }
        }
    }

    if (rate_node) {
        if (rate_node->tag != JSON_NUMBER || !isfinite(rate_node->number_) ||
            rate_node->number_ != floor(rate_node->number_)) {
            add_error(root, "rate must be an integer");
        } else {
            rate = (int)rate_node->number_;
            if (rate < 1 || rate > 10000)
                add_error(root, "rate must be between 1 and 10000 packets/sec");
        }
    }
    if (timeout_node) {
        if (timeout_node->tag != JSON_NUMBER ||
            !isfinite(timeout_node->number_) ||
            timeout_node->number_ != floor(timeout_node->number_)) {
            add_error(root, "timeout_sec must be an integer");
        } else {
            timeout_sec = (int)timeout_node->number_;
            if (timeout_sec < 1 || timeout_sec > 86400)
                add_error(root, "timeout must be between 1 and 86400 seconds");
        }
    }
    if (iface_node && iface_node->tag == JSON_STRING && iface_node->string_ &&
        iface_node->string_[0])
        iface = iface_node->string_;
    else if (iface_node && iface_node->tag != JSON_NULL)
        add_error(root, "interface must be a string");

    targetset_optimize(&targets);
    total = targetset_count(&targets);
    ports = port_scoped ? (unsigned)count_proto_ports(&targets, scan_proto) : 0;
    if (total.hi != 0) {
        add_error(root, "target set is too large to preflight (more than 2^64 addresses)");
        ok = 0;
    } else if (total.lo == 0) {
        add_error(root, "no valid target addresses");
        ok = 0;
    }
    if (port_scoped && ports == 0) {
        add_error(root, "no ports match this scan engine's protocol");
        ok = 0;
    }
    if (port_scoped && ports > 0 && targets.count_ports > ports)
        add_warning(root, "ports for other protocols were ignored by this scan engine");

    if (total.hi == 0 && total.lo > 0 && (!port_scoped || ports > 0)) {
        uint64_t total_ports = port_scoped ? (uint64_t)targets.count_ports : 1u;
        uint64_t slot_ports = total_ports;
        ip_count = total.lo / total_ports;
        attempts = port_scoped ? (double)ip_count * (double)ports
                               : (double)ip_count;
        json_append_member(root, "targets", json_mknumber((double)ip_count));
        json_append_member(root, "ports", json_mknumber((double)ports));
        json_append_member(root, "attempts", json_mknumber(attempts));

        samples = ip_count < GUI_PREFLIGHT_SAMPLES ? ip_count
                                                  : GUI_PREFLIGHT_SAMPLES;
        for (i = 0; i < samples; i++) {
            uint64_t ip_index = samples <= 1 ? 0
                                             : (i * (ip_count - 1)) / (samples - 1);
            uint64_t idx = ip_index * slot_ports;
            ipaddress ip = {0};
            unsigned port = 0;
            RawRoute route;
            targetset_pick(&targets, idx, &ip, &port);
            if (rawsock_route_lookup(ip, &route) != 0) {
                add_warning(root, "no route for part of the target set");
                ok = 0;
                break;
            }
            if (iface) {
                JsonNode *selected;
                struct ipaddress_formatted src = ipaddress_fmt(route.source_ip);
                struct ipaddress_formatted gw  = ipaddress_fmt(route.gateway);
                unsigned lt = 0;
                int have_lt = rawsock_get_adapter_link_type(iface, &lt) == 0;
                selected = json_mkobject();
                if (selected) {
                    json_append_member(selected, "interface", json_mkstring(iface));
                    json_append_member(selected, "source", json_mkstring(src.string));
                    json_append_member(selected, "gateway", json_mkstring(gw.string));
                    if (have_lt) {
                        const char *ln = rawsock_link_type_name(lt);
                        int raw_ok = lt == PCAP_DLT_NULL ||
                                     lt == PCAP_DLT_ETHERNET ||
                                     lt == PCAP_DLT_RAW;
                        json_append_member(selected, "link_type", json_mknumber(lt));
                        json_append_member(selected, "link_type_name",
                                           json_mkstring(ln ? ln : "unknown"));
                        json_append_member(selected, "raw_capable",
                                           json_mkbool(raw_ok));
                        if (!raw_ok) {
                            add_error(root, "selected interface link type cannot carry raw IP packets");
                            ok = 0;
                        }
                    } else {
                        json_append_member(selected, "link_type", json_mknull());
                        json_append_member(selected, "link_type_name",
                                           json_mkstring("unavailable"));
                        json_append_member(selected, "raw_capable", json_mkbool(0));
                        add_error(root, "cannot inspect the selected interface link type; check permissions and adapter");
                        ok = 0;
                    }
                    iface_json = selected;
                }
                break;
            }
            if (add_group(routes, route.ifname, &route) < 0) {
                add_error(root, "out of memory while building routes");
                ok = 0;
                break;
            }
        }
        if (iface) {
            if (routes->children.head == NULL && iface_json == NULL) {
                add_error(root, "cannot inspect the selected interface");
                ok = 0;
            }
        } else if (routes->children.head) {
            unsigned groups = 0;
            for (JsonNode *g = routes->children.head; g; g = g->next) {
                JsonNode *cap = member(g, "raw_capable");
                groups++;
                if (cap && cap->tag == JSON_BOOL && !cap->bool_) {
                    add_error(root, "a resolved interface cannot carry raw IP packets; choose an Ethernet or Wi-Fi adapter");
                    ok = 0;
                }
            }
            json_append_member(root, "route_groups", json_mknumber(groups));
            if (groups > 1) {
                add_error(root, "targets resolve through multiple interfaces; choose an interface explicitly");
                ok = 0;
            }
        }
    }

    if (iface_json)
        json_append_member(root, "interface", iface_json);

done:
    if (errors->children.head) ok = 0;
    if (input) json_delete(input);
    json_append_member(root, "ok", json_mkbool(ok));
    text = json_stringify(root, NULL);
    targetset_rm_all(&targets);
    free(targets_join);
    free(ports_join);
    json_delete(root);
    return text;
}
