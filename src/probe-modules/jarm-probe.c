#ifndef NOT_FOUND_OPENSSL

#include "probe-modules.h"

#include "../proto/proto-jarm.h"
#include "../proto/proto-tls.h"
#include "../util-out/logger.h"
#include "../util-data/safe-string.h"
#include "../util-misc/misc.h"

static struct JarmConfig jc_list[] = {
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_FORWARD,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_2_SUPPORT,
        .ext_order       = ExtOrder_REVERSE,
    },
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_REVERSE,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_2_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_TOP_HALF,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_NO_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_BOTTOM_HALF,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_RARE,
        .support_ver_ext = SupportVerExt_NO_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_2_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_MIDDLE_OUT,
        .grease_use      = GreaseUse_YES,
        .alpn_use        = AlpnUse_RARE,
        .support_ver_ext = SupportVerExt_NO_SUPPORT,
        .ext_order       = ExtOrder_REVERSE,
    },
    {
        .version         = TLS1_1_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_FORWARD,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_NO_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_3_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_FORWARD,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_3_SUPPORT,
        .ext_order       = ExtOrder_REVERSE,
    },
    {
        .version         = TLS1_3_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_REVERSE,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_3_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_3_VERSION,
        .cipher_list     = CipherList_NO_1_3,
        .cipher_order    = CipherOrder_FORWARD,
        .grease_use      = GreaseUse_NO,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_3_SUPPORT,
        .ext_order       = ExtOrder_FORWARD,
    },
    {
        .version         = TLS1_3_VERSION,
        .cipher_list     = CipherList_ALL,
        .cipher_order    = CipherOrder_MIDDLE_OUT,
        .grease_use      = GreaseUse_YES,
        .alpn_use        = AlpnUse_ALL,
        .support_ver_ext = SupportVerExt_1_3_SUPPORT,
        .ext_order       = ExtOrder_REVERSE,
    },
};

/******************************************************************/

/*for x-refer*/
extern Probe JarmProbe;

struct JarmConf {
    unsigned probe_index;
};

static struct JarmConf jarm_conf = {0};

static ConfRes SET_probe_index(void *conf, const char *name,
                               const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    jarm_conf.probe_index = conf_parse_int(value);

    if (jarm_conf.probe_index < 1 || jarm_conf.probe_index > 10) {
        LOG(LEVEL_ERROR, "(JarmProbe) probe index should be in 1..10\n");
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfParam jarm_parameters[] = {
    {"probe-index",
     SET_probe_index,
     Type_ARG,
     {"index", 0},
     "Just send one specified jarm probe to target."},

    {0}};

static size_t jarm_make_payload(ProbeTarget   *target,
                                unsigned char *payload_buf) {
    struct JarmConfig jc;

    if (jarm_conf.probe_index)
        jc = jc_list[jarm_conf.probe_index - 1];
    else
        jc = jc_list[target->index];

    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(target->target.ip_them);
    jc.servername                     = ip_them_fmt.string;
    jc.dst_port                       = target->target.port_them;

    return jarm_create_ch(&jc, payload_buf, PM_PAYLOAD_SIZE);
}

static size_t jarm_get_payload_length(ProbeTarget *target) {
    if (target->index >= JarmProbe.slots.count)
        return 0;

    struct JarmConfig jc;

    if (jarm_conf.probe_index)
        jc = jc_list[jarm_conf.probe_index - 1];
    else
        jc = jc_list[target->index];

    ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(target->target.ip_them);
    jc.servername                     = ip_them_fmt.string;
    jc.dst_port                       = target->target.port_them;
    unsigned char buf[TLS_CLIENTHELLO_MAX_LEN];

    return jarm_create_ch(&jc, buf, TLS_CLIENTHELLO_MAX_LEN);
}

static bool jarm_should_continue(ProbeTarget *target,
                                 const unsigned char *px,
                                 unsigned sizeof_px) {
    UNUSEDPARM(target);
    return sizeof_px >= 7 && px[1] == 0x03 &&
           (px[2] == 0x00 || px[2] == 0x01 || px[2] == 0x02 ||
            px[2] == 0x03) &&
           (px[0] == TLS_RECORD_CONTENT_TYPE_ALERT ||
            px[0] == TLS_RECORD_CONTENT_TYPE_HANDSHAKE);
}

static unsigned jarm_handle_response(unsigned th_idx, ProbeTarget *target,
                                     const unsigned char *px,
                                     unsigned sizeof_px, OutItem *item) {
    /**
     * The min length for ALERT
     * eg. \x15\x03\x01\x00\x02\x02
     * */
    if (sizeof_px < 7) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "no jarm");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "not tls");
        return 0;
    }

    char tmp_data[100];

    /*Just ALERT or HANDSHAKE are valid*/
    if (px[0] == TLS_RECORD_CONTENT_TYPE_ALERT ||
        px[0] == TLS_RECORD_CONTENT_TYPE_HANDSHAKE) {
        /*Validate the VERSION field*/
        if (px[1] == 0x03) {
            if (px[2] == 0x00 || px[2] == 0x01 || px[2] == 0x02 ||
                px[2] == 0x03) {
                item->level = OUT_SUCCESS;
                safe_strcpy(item->classification, OUT_CLS_SIZE, "jarmed");
                jarm_decipher_one(px, sizeof_px, tmp_data, sizeof(tmp_data));

                /* One OutItem per slot.  No per-target group is kept in the
                 * scanner: an output-side aggregator joins these parts. */
                dach_append_str(&item->probe_report, "jarm_part", tmp_data,
                                strlen(tmp_data));
                dach_set_int(&item->probe_report, "jarm_slots",
                             JarmProbe.slots.count);

                if (jarm_conf.probe_index) {
                    dach_set_int(&item->probe_report, "jarm_slot",
                                 jarm_conf.probe_index);
                    return 0;
                } else {
                    dach_set_int(&item->probe_report, "jarm_slot",
                                 target->index + 1);
                    return 0;
                }
            }
        }
    }

    item->level = OUT_FAILURE;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "no jarm");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "not tls");
    return 0;
}

Probe JarmProbe = {
    .name       = "jarm",
    .type       = ProbeType_TCP,
    .slots      = {.count = 10,
                   .trigger = ProbeSlot_AfterFirstReply,
                   .continue_cb = jarm_should_continue},
    .params     = jarm_parameters,
    .short_desc = "Collect JARM probe parts from 10 ClientHello slots.",
    .desc = "Jarm Probe sends 10 TLS ClientHello variants if the first response "
            "shows TLS. Each slot emits jarm_part/jarm_slot; no per-target "
            "group is kept in the scanner. Aggregate them with "
            "tools/jarm_aggregate.py.\n"
            "Dependencies: OpenSSL.",

    .init_cb               = &probe_init_nothing,
    .make_payload_cb       = &jarm_make_payload,
    .get_payload_length_cb = &jarm_get_payload_length,
    .handle_response_cb    = &jarm_handle_response,
    .close_cb              = &probe_close_nothing,
};

#endif /*ifndef NOT_FOUND_OPENSSL*/