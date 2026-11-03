#ifndef NOT_FOUND_PCRE2

#include "probe-modules.h"

#include <string.h>

#include "../xconf.h"
#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"
#include "../nmap/nmap-service.h"

#define PROBER "NmapUdpProbe"

/*for internal x-ref*/
extern Probe NmapUdpProbe;

struct NmapUdpConf {
    struct NmapServiceProbeList *probe_list;
    struct NmapServiceProbe     *probe;
    char                        *probe_file;
    char                        *probe_name;
    char                        *softmatch;
};

static struct NmapUdpConf nmapudp_conf = {0};

static ConfRes SET_softmatch(void *conf, const char *name, const char *value) {
    UNUSEDPARM(name);

    FREE(nmapudp_conf.softmatch);

    nmapudp_conf.softmatch = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_probe_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(name);

    FREE(nmapudp_conf.probe_name);

    nmapudp_conf.probe_name = STRDUP(value);
    return Conf_OK;
}

static ConfRes SET_probe_file(void *conf, const char *name, const char *value) {
    UNUSEDPARM(name);

    FREE(nmapudp_conf.probe_file);

    nmapudp_conf.probe_file = STRDUP(value);
    return Conf_OK;
}

static ConfParam nmapservice_parameters[] = {
    {"probe-file",
     SET_probe_file,
     Type_ARG,
     {"file", 0},
     "Specifies nmap-service-probes file for probes loading."},
    {"probe-name",
     SET_probe_name,
     Type_ARG,
     {"probe", 0},
     "Specifies a probe in nmap-service-probes file for sending."},
    {"softmatch",
     SET_softmatch,
     Type_ARG,
     {0},
     "Specifies what service has been softmatched for target ports before, "
     "so " PROBER " could use more accurate probes to reduce cost and just do "
     "hard matching.\n"
     "NOTE: This param exists because the strategy of Nmap services matching "
     "cannot be implemented completely in stateless mode."},

    {0}};

static bool nmapudp_init(const XConf *xconf) {
    if (!nmapudp_conf.probe_file) {
        LOG(LEVEL_ERROR,
            "(" PROBER ") no nmap-service-probes file specified.\n");
        return false;
    }
    nmapudp_conf.probe_list = nmapservice_read_file(nmapudp_conf.probe_file);
    if (!nmapudp_conf.probe_list) {
        LOG(LEVEL_ERROR, "(" PROBER ") invalid nmap-service-probes file: %s\n",
            nmapudp_conf.probe_file);
        return false;
    }

    if (!nmapudp_conf.probe_list->count) {
        LOG(LEVEL_ERROR, "(" PROBER ") no probe has been loaded from %s\n",
            nmapudp_conf.probe_file);
        nmapservice_free(nmapudp_conf.probe_list);
        return false;
    }

    if (!nmapudp_conf.probe_name) {
        LOG(LEVEL_WARN,
            "(" PROBER ") No probe specified, use default `NULL`.\n");
        nmapudp_conf.probe_name = STRDUP("NULL");
    }

    nmapudp_conf.probe = nmapservice_get_probe_by_name(
        nmapudp_conf.probe_list, nmapudp_conf.probe_name, IP_PROTO_UDP);
    if (!nmapudp_conf.probe) {
        LOG(LEVEL_ERROR, "(" PROBER ") invalid probe name: %s\n",
            nmapudp_conf.probe_name);
        return false;
    }

    nmapservice_match_compile(nmapudp_conf.probe_list);
    LOG(LEVEL_DEBUG, "(" PROBER ") probes loaded and compiled.\n");

    nmapservice_link_fallback(nmapudp_conf.probe_list);
    LOG(LEVEL_DEBUG, "(" PROBER ") probe fallbacks linked.\n");

    return true;
}

static void nmapudp_close() {
    if (nmapudp_conf.probe_list) {
        nmapservice_match_free(nmapudp_conf.probe_list);
        LOG(LEVEL_DETAIL, "(" PROBER ") probes compilation freed.\n");

        nmapservice_free(nmapudp_conf.probe_list);
        LOG(LEVEL_DETAIL, "(" PROBER ") probes freed.\n");

        nmapudp_conf.probe_list = NULL;
    }

    nmapudp_conf.probe = NULL;

    FREE(nmapudp_conf.probe_file);
    FREE(nmapudp_conf.probe_name);
    FREE(nmapudp_conf.softmatch);
}

static size_t nmapudp_make_payload(ProbeTarget   *target,
                                   unsigned char *payload_buf) {
    memcpy(payload_buf, nmapudp_conf.probe->hellostring,
           nmapudp_conf.probe->hellolength);

    return nmapudp_conf.probe->hellolength;
}

unsigned nmapudp_handle_response(unsigned th_idx, ProbeTarget *target,
                                 const unsigned char *px, unsigned sizeof_px,
                                 OutItem *item) {
    struct NmapServiceProbeList *list  = nmapudp_conf.probe_list;
    struct NmapServiceProbe     *probe = nmapudp_conf.probe;

    struct ServiceProbeMatch *match = nmapservice_match_service(
        list, probe, px, sizeof_px, IP_PROTO_UDP, nmapudp_conf.softmatch);

    if (match) {
        item->level = OUT_SUCCESS;

        safe_strcpy(item->classification, OUT_CLS_SIZE, "identified");
        safe_strcpy(item->reason, OUT_RSN_SIZE,
                    match->is_softmatch ? "softmatch" : "matched");

        dach_set_int(&item->probe_report, "line", match->line);
        if (!match->is_softmatch && match->versioninfo) {
            dach_append_str(&item->probe_report, "info",
                            match->versioninfo->value,
                            strlen(match->versioninfo->value));
        }
        dach_append_str(&item->probe_report, "service", match->service,
                        strlen(match->service));

        return 0;
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "unknown");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");

    return 0;
}

Probe NmapUdpProbe = {
    .name       = "nmap-udp",
    .type       = ProbeType_UDP,
    .params     = nmapservice_parameters,
    .short_desc = "Use specified Nmap probe to identify service over udp.",
    .desc       = "NmapUdpProbe sends specified Nmap probe from loaded "
                  "nmap-service-probes file and identifies service/version of "
                  "target udp port. Unlike real Nmap, we just send one "
                  "specified probe and try to match the results. We can load "
                  "specific version of nmap-service-probes file by using "
                  "`-probe-file` subparam and specify probe name by `-probe`.\n"
                  "NOTE1: This cannot perform a complete Nmap service "
                  "identification. Just for researches now.\n"
                  "NOTE2: All probe info can be check with global param "
                  "`-list-nmap-probe`.\n"
                  "Dependencies: PCRE2.",

    .init_cb              = &nmapudp_init,
    .make_payload_cb      = &nmapudp_make_payload,
    .validate_response_cb = &probe_all_response_valid,
    .handle_response_cb   = &nmapudp_handle_response,
    .close_cb             = &nmapudp_close,
};

#endif /*ifndef NOT_FOUND_PCRE2*/