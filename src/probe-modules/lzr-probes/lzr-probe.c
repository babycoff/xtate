#include "../probe-modules.h"

#include <stdio.h>

#include "../../xconf.h"
#include "../../version.h"
#include "../../util-data/safe-string.h"
#include "../../util-data/fine-malloc.h"
#include "../../util-out/logger.h"
#include "../../util-misc/misc.h"

#define LZR_HANDSHAKE_NAME_LEN 20

/*
 * LZR Probe will use `handle_response_cb` of all subprobes(handshakes) listed
 * here to match the banner and identify its service automaticly.
 *
 * Subprobes' names always start with 'lzr-' and could be used as a normal
 * ProbeModule. Subprobes set classification of result to the service name and
 * output level to success if it identified successfully.
 *
 * When they specified as subprobes in LZR probe with `--probe-args`, we should
 * omit the 'lzr-' prefix like 'lzr-http' -> 'http'.
 *
 * LZR probe uses specified subprobe to send payload, and matches all subprobes
 * for result reporting. It could reports more than one identified service type
 * or 'unknown' if nothing identified.
 *
 * NOTE: While ProbeModule is as Subprobe of LZR, its `params` will not be
 * configured.
 */

//! ADD NEW LZR SUBPROBES(HANDSHAKES) HERE
//! ALSO ADD TO stateless-probes.c IF NEEDED
extern Probe LzrHttpProbe;
extern Probe LzrTlsProbe;
extern Probe LzrFtpProbe;
extern Probe LzrPop3Probe;
extern Probe LzrImapProbe;
extern Probe LzrSmtpProbe;
extern Probe LzrSshProbe;
extern Probe LzrSocks5Probe;
extern Probe LzrTelnetProbe;
extern Probe LzrFixProbe;
extern Probe LzrSmbProbe;
extern Probe LzrMqttProbe;
extern Probe LzrAmqpProbe;
extern Probe LzrMysqlProbe;
extern Probe LzrMongodbProbe;
extern Probe LzrRedisProbe;
extern Probe LzrPostgresProbe;
extern Probe LzrMssqlProbe;
extern Probe LzrOracleProbe;
extern Probe LzrRdpProbe;
extern Probe LzrX11Probe;
extern Probe LzrVncProbe;
extern Probe LzrK8sProbe;
extern Probe LzrRtspProbe;
extern Probe LzrModbusProbe;
extern Probe LzrSiemensProbe;
extern Probe LzrBgpProbe;
extern Probe LzrPptpProbe;
extern Probe LzrDnsProbe;
extern Probe LzrIpmiProbe;
extern Probe LzrDnp3Probe;
extern Probe LzrFoxProbe;
extern Probe LzrMemcachedAsciiProbe;
extern Probe LzrMemcachedBinaryProbe;
extern Probe LzrIppProbe;
extern Probe LzrWaitProbe;
extern Probe LzrNewlinesProbe;
extern Probe LzrNewlines50Probe;

//! ADD NEW LZR SUBPROBES(HANDSHAKES) HERE
//! ALSO ADD TO probe-modules.c IF NEEDED
static Probe *lzr_handshakes[] = {
    &LzrHttpProbe,
    &LzrTlsProbe,
    &LzrFtpProbe,
    &LzrPop3Probe,
    &LzrImapProbe,
    &LzrSmtpProbe,
    &LzrSshProbe,
    &LzrSocks5Probe,
    &LzrTelnetProbe,
    &LzrFixProbe,
    &LzrSmbProbe,
    &LzrAmqpProbe,
    &LzrMysqlProbe,
    &LzrMongodbProbe,
    &LzrRedisProbe,
    &LzrPostgresProbe,
    &LzrMssqlProbe,
    &LzrOracleProbe,
    &LzrRdpProbe,
    &LzrX11Probe,
    &LzrVncProbe,
    &LzrK8sProbe,
    &LzrRtspProbe,
    &LzrModbusProbe,
    &LzrSiemensProbe,
    &LzrBgpProbe,
    &LzrPptpProbe,
    &LzrDnsProbe,
    &LzrIpmiProbe,
    &LzrMqttProbe,
    &LzrDnp3Probe,
    &LzrFoxProbe,
    &LzrMemcachedAsciiProbe,
    &LzrMemcachedBinaryProbe,
    &LzrIppProbe,
    &LzrWaitProbe,
    &LzrNewlinesProbe,
    &LzrNewlines50Probe,
};

/******************************************************************/

/*for x-refer*/
extern Probe LzrProbe;

struct LzrConf {
    Probe  **handshake;
    unsigned hs_count;
    unsigned force_all_handshakes : 1;
    unsigned force_all_match      : 1;
};

static struct LzrConf lzr_conf = {0};

static ConfRes SET_force_all_match(void *conf, const char *name,
                                   const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    lzr_conf.force_all_match = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_force_all_handshake(void *conf, const char *name,
                                       const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    lzr_conf.force_all_handshakes = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_handshake(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    char  *str     = STRDUP(value);
    size_t str_len = strlen(str);
    if (str_len == 0) {
        LOG(LEVEL_ERROR, "invalid name of handshake for lzr.\n");
        return Conf_ERR;
    }

    size_t hs_count = 0;
    char  *p        = str;
    for (; p - str < str_len; p++) {
        if (*p != ' ' && *p != ',') {
            hs_count++;
        }
        for (; p - str < str_len && *p != ' ' && *p != ','; p++) {
        }
        /*create C string*/
        *p = '\0';
    }

    lzr_conf.hs_count  = hs_count;
    lzr_conf.handshake = MALLOC(sizeof(Probe *) * hs_count);
    size_t hs_index    = 0;
    p                  = str;
    for (; p - str < str_len; p++) {
        if (*p != '\0') {
            char hs_name[LZR_HANDSHAKE_NAME_LEN] = "lzr-";
            safe_strcpy(hs_name + strlen(hs_name), LZR_HANDSHAKE_NAME_LEN - 4,
                        p);
            lzr_conf.handshake[hs_index] = get_probe_module_by_name(hs_name);

            if (lzr_conf.handshake[hs_index] == NULL) {
                LOG(LEVEL_ERROR, "invalid name of handshake for lzr.\n");
                FREE(str);
                return Conf_ERR;
            }

            hs_index++;
        }
        for (; p - str < str_len && *p != '\0'; p++) {
        }
    }

    FREE(str);

    return Conf_OK;
}

static ConfParam lzr_parameters[] = {
    {"handshake",
     SET_handshake,
     Type_ARG,
     {"subprobe", "handshakes", "subprobes", 0},
     "Specifies handshakes(subprobes) for probe sending. Handshake names are "
     "splitted by comma like `--handshake http,tls`."},
    {"force-all-match",
     SET_force_all_match,
     Type_FLAG,
     {"all-match", 0},
     "Complete all matching process for one banner even if a service "
     "identified. This might get multiple identified results."},
    {"force-all-handshakes",
     SET_force_all_handshake,
     Type_FLAG,
     {"force-all-handshake", "all-handshake", "all-handshakes", 0},
     "Send all specified handshakes even if identified. This could got "
     "multiple output item for a target."},

    {0}};

static bool lzr_init(const XConf *xconf) {
    /*Use LzrWait if no subprobe specified*/
    if (!lzr_conf.handshake) {
        lzr_conf.handshake    = MALLOC(sizeof(Probe *));
        lzr_conf.handshake[0] = &LzrHttpProbe;
        lzr_conf.hs_count     = 1;
        LOG(LEVEL_HINT,
            "use default LzrHttpProbe(http) as handshake of LzrProbe "
            "because no handshake was specified by --handshake.\n");
    }

    /*do init for all handshakes*/
    for (unsigned i = 0; i < lzr_conf.hs_count; i++) {
        if (!lzr_conf.handshake[i]->init_cb(xconf)) {
            LOG(LEVEL_ERROR, "handshake [%s] initiating error in LzrProbe.\n",
                lzr_conf.handshake[i]->name);
            return false;
        }
    }

    return true;
}

static size_t lzr_make_payload(ProbeTarget   *target,
                               unsigned char *payload_buf) {
    if (target->index >= lzr_conf.hs_count)
        return 0;

    return lzr_conf.handshake[target->index]->make_payload_cb(target,
                                                              payload_buf);
}

static size_t lzr_get_payload_length(ProbeTarget *target) {
    if (target->index < lzr_conf.hs_count)
        return lzr_conf.handshake[target->index]->get_payload_length_cb(target);

    return 0;
}

static unsigned lzr_handle_response(unsigned th_idx, ProbeTarget *target,
                                    const unsigned char *px, unsigned sizeof_px,
                                    OutItem *item) {
    /**
     * print results just like lzr:
     *     pop3-smtp-http
     */
    bool      identified = false;
    DataLink *res_link;
    res_link = dach_new_link(&item->probe_report, "result", 1, false);

    size_t i = 0;
    for (; i < ARRAY_SIZE(lzr_handshakes); i++) {
        lzr_handshakes[i]->handle_response_cb(th_idx, target, px, sizeof_px,
                                              item);

        if (item->level == OUT_SUCCESS) {
            res_link   = dach_append_by_link(res_link, item->classification,
                                             strlen(item->classification));
            identified = true;
            break;
        }
    }

    if (lzr_conf.force_all_match) {
        for (++i; i < ARRAY_SIZE(lzr_handshakes); i++) {
            lzr_handshakes[i]->handle_response_cb(th_idx, target, px, sizeof_px,
                                                  item);

            if (item->level == OUT_SUCCESS) {
                res_link =
                    dach_printf_by_link(res_link, "-%s", item->classification);
            }
        }
    }

    dach_append_str(&item->probe_report, "handshake",
                    lzr_conf.handshake[target->index]->name,
                    strlen(lzr_conf.handshake[target->index]->name));

    if (identified) {
        item->level = OUT_SUCCESS;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "identified");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "matched");

        if (lzr_conf.force_all_handshakes &&
            target->index != lzr_conf.hs_count - 1) {
            return target->index + 2;
        }
    } else {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "unknown");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not matched");
        dach_del_by_link(&item->probe_report, res_link);

        /*last handshake*/
        if (target->index != lzr_conf.hs_count - 1 &&
            lzr_conf.force_all_handshakes) {
            return target->index + 2;
        } else {
            return 0;
        }
    }

    return 0;
}

void lzr_close() {
    /*close for every handshake*/
    /*do init for all handshakes*/
    for (unsigned i = 0; i < lzr_conf.hs_count; i++)
        lzr_conf.handshake[i]->close_cb();

    FREE(lzr_conf.handshake);
}

Probe LzrProbe = {
    .name       = "lzr",
    .type       = ProbeType_TCP,
    .multi_mode = Multi_DynamicNext,
    .multi_num  = 1,
    .params     = lzr_parameters,
    .short_desc = "An implementation of LZR-like service identifier "
                  "in " XTATE_NAME_TITLE_CASE ".",
    .desc =
        "LzrProbe is an implementation of LZR-like service identifier "
        "in " XTATE_NAME_TITLE_CASE
        ". It sends a serias specified LZR handshakes(subprobes) until "
        "identified the service by matching responsed data with all LZR "
        "handshakes. I had fixed some matching bugs and errors from original "
        "LZR and added more useful handshakes. So, enjoy it!\n"
        "NOTE1: Recommended optimal handshake order by LZR paper:\n"
        "1)wait\n"
        "2)tls\n"
        "3)http\n"
        "4)dns\n"
        "5)pptp\n"
        "NOTE2: LzrProbe's defect is driven by ZBanner mechanism so that works "
        "in complete stateless mode. So it cannot recognize timeout for "
        "handshakes it sent.",

    .init_cb               = &lzr_init,
    .make_payload_cb       = &lzr_make_payload,
    .get_payload_length_cb = &lzr_get_payload_length,
    .handle_response_cb    = &lzr_handle_response,
    .close_cb              = &lzr_close,
};