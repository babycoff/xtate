#include "gui-data.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../crypto/crypto-json.h"
#include "../rawsock/rawsock.h"
#include "../rawsock/rawsock-route.h"
#include "../stub/stub-pcap-dlt.h"
#include "../stub/stub-pcap.h"
#include "../target/target-set.h"
#include "../util-out/module-json.h"
#include "../version.h"

static void append_string_array(JsonNode *object, const char *name,
                                const char *value) {
    JsonNode *array = json_mkarray();
    if (!array) return;
    if (value && value[0]) json_append_element(array, json_mkstring(value));
    json_append_member(object, name, array);
}

static void count_modules(JsonNode *root, int *scan, int *probe, int *output,
                          int *generate, int *http3, int *quic) {
    JsonNode *mods = json_find_member(root, "modules");
    JsonNode *m;
    if (!mods || mods->tag != JSON_ARRAY) return;
    for (m = mods->children.head; m; m = m->next) {
        JsonNode *kind = json_find_member(m, "kind");
        JsonNode *name = json_find_member(m, "name");
        if (!kind || kind->tag != JSON_STRING) continue;
        if (strcmp(kind->string_, "scan") == 0) (*scan)++;
        else if (strcmp(kind->string_, "probe") == 0) (*probe)++;
        else if (strcmp(kind->string_, "output") == 0) (*output)++;
        else if (strcmp(kind->string_, "generate") == 0) (*generate)++;
        if (name && name->tag == JSON_STRING) {
            if (strcmp(name->string_, "http3-state") == 0) *http3 = 1;
            if (strcmp(name->string_, "quic-state") == 0) *quic = 1;
        }
    }
}

char *gui_system_json(const char *endpoint) {
    JsonNode *root = json_mkobject();
    JsonNode *modules;
    JsonNode *counts;
    JsonNode *caps;
    char *catalog;
    char *text;
    int scan = 0, probe = 0, output = 0, generate = 0, http3 = 0, quic = 0;

    if (!root) return NULL;
    catalog = module_json_string();
    if (catalog) {
        modules = json_decode(catalog);
        if (modules && modules->tag == JSON_OBJECT)
            count_modules(modules, &scan, &probe, &output, &generate, &http3,
                          &quic);
        if (modules) json_delete(modules);
        free(catalog);
    }

    json_append_member(root, "endpoint", json_mkstring(endpoint ? endpoint : ""));
    json_append_member(root, "version", json_mkstring(XTATE_VERSION));
#if defined(_WIN32)
    json_append_member(root, "platform", json_mkstring("windows"));
#else
    json_append_member(root, "platform", json_mkstring("linux"));
#endif

    counts = json_mkobject();
    if (counts) {
        json_append_member(counts, "scan", json_mknumber(scan));
        json_append_member(counts, "probe", json_mknumber(probe));
        json_append_member(counts, "output", json_mknumber(output));
        json_append_member(counts, "generate", json_mknumber(generate));
        json_append_member(root, "modules", counts);
    }

    caps = json_mkobject();
    if (caps) {
        json_append_member(caps, "http3", json_mkbool(http3));
        json_append_member(caps, "quic_transport", json_mkbool(quic));
        json_append_member(caps, "raw_sockets", json_mkbool(1));
        json_append_member(caps, "live_results", json_mkbool(0));
        json_append_member(root, "capabilities", caps);
    }

    text = json_stringify(root, NULL);
    json_delete(root);
    return text;
}

static void add_address(JsonNode *object, const char *name,
                        const char *value) {
    if (value && value[0]) {
        append_string_array(object, name, value);
    } else {
        json_append_member(object, name, json_mknull());
    }
}

char *gui_interfaces_json(void) {
    pcap_if_t *all = NULL;
    const pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char default_if[256] = {0};
    JsonNode *root;
    JsonNode *array;
    char *text;
    int index = 0;

    if (pcap_init() != 0) return NULL;
    if (PCAP.findalldevs(&all, errbuf) == -1) return NULL;

    root = json_mkobject();
    if (!root) {
        if (all) PCAP.freealldevs(all);
        return NULL;
    }
    array = json_mkarray();
    if (!array) {
        json_delete(root);
        if (all) PCAP.freealldevs(all);
        return NULL;
    }
    json_append_member(root, "interfaces", array);
    rawsock_get_default_interface(default_if, sizeof(default_if));

    for (d = all; d; d = PCAP.dev_next(d)) {
        const char *name = PCAP.dev_name(d);
        const char *desc = PCAP.dev_description(d);
        bool loopback;
        bool virt;
        unsigned ipv4 = 0;
        unsigned gw = 0;
        unsigned link_type = 0;
        bool has_gw = false;
        bool has_link = false;
        unsigned char macbuf[6] = {0};
        bool has_mac = false;
        char mac[20] = "-";
        char gw_s[64] = "";
        char ip6_s[64] = "";
        char state[20];
        JsonNode *item;

        if (!name) continue;
        if (!desc) desc = "";
        loopback = strstr(desc, "Loopback") != NULL ||
                   strstr(desc, "loopback") != NULL ||
                   strstr(name, "Loopback") != NULL;
        virt = strstr(desc, "WAN Miniport") != NULL ||
               strstr(desc, "VMware") != NULL ||
               strstr(desc, "Hyper-V") != NULL ||
               strstr(desc, "Virtual") != NULL ||
               strstr(desc, "Wi-Fi Direct") != NULL;

        /* Probing Windows loopback and virtual/WAN Npcap devices can fault
         * the adapter helpers; list them without querying. */
        if (!loopback && !virt) {
            ipv4 = rawsock_get_adapter_ip(name);
            if (rawsock_get_adapter_mac(name, macbuf) == 0) {
                has_mac = 1;
                snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         macbuf[0], macbuf[1], macbuf[2], macbuf[3], macbuf[4],
                         macbuf[5]);
            }
            has_gw = rawsock_get_default_gateway(name, &gw) == 0 && gw != 0;
            if (has_gw) {
                ipaddress_formatted_t fmt = ipv4address_fmt(gw);
                snprintf(gw_s, sizeof(gw_s), "%s", fmt.string);
            }
            if (rawsock_get_adapter_link_type(name, &link_type) == 0)
                has_link = true;
            {
                ipv6address ip6 = rawsock_get_adapter_ipv6(name);
                if (!ipv6address_is_zero(ip6)) {
                    ipaddress_formatted_t fmt = ipv6address_fmt(ip6);
                    snprintf(ip6_s, sizeof(ip6_s), "%s", fmt.string);
                }
            }
        }

        if (loopback) snprintf(state, sizeof(state), "loopback");
        else if (virt) snprintf(state, sizeof(state), "virtual");
        else if (ipv4) snprintf(state, sizeof(state), "up");
        else snprintf(state, sizeof(state), "no-ipv4");

        item = json_mkobject();
        if (!item) continue;
        json_append_member(item, "index", json_mknumber(index++));
        json_append_member(item, "name", json_mkstring(name));
        json_append_member(item, "description", json_mkstring(desc));
        {
            char ip4_s[64] = "";
            if (ipv4) {
                ipaddress_formatted_t fmt = ipv4address_fmt(ipv4);
                snprintf(ip4_s, sizeof(ip4_s), "%s", fmt.string);
            }
            add_address(item, "ipv4", ip4_s);
            add_address(item, "ipv6", ip6_s);
        }
        json_append_member(item, "mac",
                           json_mkstring(has_mac ? mac : "-"));
        json_append_member(item, "gateway", json_mkstring(gw_s));
        json_append_member(item, "default",
                           json_mkbool(default_if[0] &&
                                       strcmp(default_if, name) == 0));
        json_append_member(item, "state", json_mkstring(state));
        if (has_link) {
            const char *ltname = rawsock_link_type_name(link_type);
            json_append_member(item, "link_type", json_mknumber(link_type));
            json_append_member(item, "link_type_name",
                               json_mkstring(ltname ? ltname : "unknown"));
            json_append_member(item, "raw_capable",
                               json_mkbool(link_type == PCAP_DLT_NULL ||
                                           link_type == PCAP_DLT_ETHERNET ||
                                           link_type == PCAP_DLT_RAW));
        } else {
            json_append_member(item, "link_type", json_mknull());
            json_append_member(item, "link_type_name",
                               json_mkstring(virt ? "not probed" : "unavailable"));
            json_append_member(item, "raw_capable", json_mkbool(0));
        }
        json_append_element(array, item);
    }
    if (all) PCAP.freealldevs(all);

    text = json_stringify(root, NULL);
    json_delete(root);
    return text;
}
