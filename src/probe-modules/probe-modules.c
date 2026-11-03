#include "probe-modules.h"
#include "../util-misc/i18n.h"

#include <string.h>
#include <stdio.h>

#include "../xconf.h"
#include "../util-out/xprint.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

/*
This is an Application-layer Probe(or Request) Plugin System
*/

// clang-format off
extern Probe NullProbe;
extern Probe HttpProbe;
extern Probe HttpStateProbe;
extern Probe EchoProbe;
extern Probe GetStateProbe;
extern Probe JarmProbe;
extern Probe TlsStateProbe;
extern Probe DnsProbe;
extern Probe LuaTcpProbe;
extern Probe LuaUdpProbe;
extern Probe SnmpProbe;
extern Probe HelloProbe;
extern Probe HelloUdpProbe;
extern Probe HelloStateProbe;
extern Probe RecogProbe;
extern Probe RecogUdpProbe;
extern Probe RecogStateProbe;
extern Probe CloseStateProbe;
extern Probe TlsHelloProbe;
extern Probe NmapProbe;
extern Probe NmapUdpProbe;
extern Probe SlotTestProbe;
extern Probe SlotTestUdpProbe;
//! ADD YOUR PROBE MODULE HERE


Probe *probe_modules_list[] = {
    &NullProbe, /* its also the default probe*/
    &HttpProbe,
    &HttpStateProbe,
    &EchoProbe,
    &GetStateProbe,

#ifndef NOT_FOUND_OPENSSL
    &JarmProbe,
    &TlsStateProbe,
#endif

    &DnsProbe,
    &LuaTcpProbe,
    &LuaUdpProbe,
    &SnmpProbe,
    &HelloProbe,

#ifndef NOT_FOUND_PCRE2
    &HelloUdpProbe,
#endif

    &HelloStateProbe,

#ifndef NOT_FOUND_PCRE2
    &RecogProbe,
    &RecogUdpProbe,
    &RecogStateProbe,
#endif

    &CloseStateProbe,
    &TlsHelloProbe,

#ifndef NOT_FOUND_PCRE2
    &NmapProbe,
    &NmapUdpProbe,
#endif

    /* Developer examples / test fixtures for ProbeSlot_Always. */
    &SlotTestProbe,
    &SlotTestUdpProbe,

    //! REGISTER YOUR PROBE MODULE HERE

    NULL /*keep the null tail*/
};
// clang-format on

Probe *get_probe_module_by_name(const char *name) {
    int len = (int)ARRAY_SIZE(probe_modules_list) - 1;
    for (int i = 0; i < len; i++) {
        if (conf_equals(probe_modules_list[i]->name, name)) {
            return probe_modules_list[i];
        }
    }
    return NULL;
}

const char *get_probe_type_name(const ProbeType type) {
    switch (type) {
        case ProbeType_NULL:
            return "null";
        case ProbeType_TCP:
            return "tcp";
        case ProbeType_UDP:
            return "udp";
        case ProbeType_STATE:
            return "state";
        default:
            return "";
    }
}

int probe_type_to_string(unsigned type, char *string, size_t str_len) {
    int ret = 0;

    ret = snprintf(string, str_len, "%s%s%s",
                   (type & ProbeType_TCP) ? "tcp|" : "",
                   (type & ProbeType_UDP) ? "udp|" : "",
                   (type & ProbeType_STATE) ? "state|" : "");
    if (string[0] == '\0') {
        ret = snprintf(string, str_len, "no probe");
    } else {
        string[strlen(string) - 1] = '\0';
        ret--;
    }

    return ret;
}

#define printf i18n_printf

void list_searched_probe_modules(const char *name) {
    int len = (int)(ARRAY_SIZE(probe_modules_list)) - 1;
    int distance;
    for (int i = 0; i < len; i++) {
        distance = conf_fuzzy_distance(probe_modules_list[i]->name, name);
        if (distance < 0) {
            LOG(LEVEL_ERROR, "(%s) failed to matching.\n", __func__);
            break;
        }
        if (distance <= 2) {
            printf("    %s -> %s\n", probe_modules_list[i]->name,
                   i18n_tr_module_desc(
                       probe_modules_list[i]->name,
                       probe_modules_list[i]->short_desc
                           ? probe_modules_list[i]->short_desc
                           : probe_modules_list[i]->desc));
        }
    }
}

void list_all_probe_modules() {
    int len = (int)(ARRAY_SIZE(probe_modules_list)) - 1;

    printf("\n");

    for (int i = 0; i < len; i++) {
        printf("  %d.%s\n", i + 1, probe_modules_list[i]->name);
        printf("    %s\n", i18n_tr_module_desc(probe_modules_list[i]->name, probe_modules_list[i]->short_desc ? probe_modules_list[i]->short_desc : probe_modules_list[i]->desc));
        printf("\n");
    }
}

void help_probe_module(Probe *module) {
    if (!module) {
        LOG(LEVEL_ERROR, "no specified probe module.\n");
        return;
    }

    printf("\n");
    printf("  %s%s\n", i18n_tr("ProbeModule Name: "), module->name);
    printf("  %s%s\n", i18n_tr("ProbeModule Type: "),
           get_probe_type_name(module->type));
    printf("  %s%u\n", i18n_tr("Slot count: "),
           probe_slot_count(module));
    printf("  %s%s\n", i18n_tr("Slot trigger: "),
           module->slots.trigger == ProbeSlot_Always
               ? "all slots"
               : (module->slots.trigger == ProbeSlot_AfterFirstReply
                      ? "after first reply"
                      : "single"));
    printf("  %s%u (for stateful probe)\n", i18n_tr("Hello wait second: "),
           module->hello_wait);
    printf("\n");
    printf("  %s", i18n_tr("Description:\n"));
    xprint(i18n_tr_module_desc(module->name, module->desc), 6, 80);
    printf("\n");
    printf("\n");
    if (module->params) {
        for (unsigned j = 0; module->params[j].name; j++) {
            if (!module->params[j].help_text)
                continue;

            printf("  --%s", module->params[j].name);
            for (unsigned k = 0; module->params[j].alt_names[k]; k++) {
                printf(", %s", module->params[j].alt_names[k]);
            }
            printf("\n");
            xprint(i18n_tr_module_param(module->name, module->params[j].name,
                                     module->params[j].help_text),
               6, 80);
            printf("\n\n");
        }
    }

    printf("\n");
}

#undef printf

bool probe_init_nothing(const XConf *xconf) { return true; }

size_t probe_make_no_payload(ProbeTarget *target, unsigned char *payload_buf) {
    return 0;
}

size_t probe_no_payload_length(ProbeTarget *target) { return 0; }

unsigned probe_report_nothing(unsigned th_idx, ProbeTarget *target,
                              const unsigned char *px, unsigned sizeof_px,
                              OutItem *item) {
    item->no_output = 1;
    return 0;
}

unsigned probe_just_report_banner(unsigned th_idx, ProbeTarget *target,
                                  const unsigned char *px, unsigned sizeof_px,
                                  OutItem *item) {
    item->level = OUT_SUCCESS;
    dach_append_banner(&item->probe_report, "banner", px, sizeof_px);

    return 0;
}

void probe_close_nothing() { return; }

bool probe_conn_init_nothing(ProbeState *state, ProbeTarget *target) {
    return true;
}

void probe_conn_close_nothing(ProbeState *state, ProbeTarget *target) {
    return;
}

bool probe_all_response_valid(ProbeTarget *target, const unsigned char *px,
                              unsigned sizeof_px) {
    return true;
}