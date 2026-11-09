#include "probe-modules.h"

#include "../xconf.h"
#include "../proto/proto-dns.h"
#include "../target/target-parse.h"
#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"
#include "../util-data/data-convert.h"
#include "../util-out/logger.h"
#include "../util-misc/misc.h"

/*for internal x-ref*/
extern Probe DnsProbe;

struct DnsConf {
    char           *req_name;
    dns_record_type req_type;
    unsigned        recursive_desired : 1;
    unsigned        print_all_ans     : 1;
    unsigned        print_all_auth    : 1;
    unsigned        print_all_add     : 1;
    unsigned        dnssec            : 1;
    unsigned        edns_size;
};

static struct DnsConf dns_conf = {0};

static ConfRes SET_ptr(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    ipaddress ip = target_parse_ip(value);
    if (ip.version == 0) {
        LOG(LEVEL_ERROR, "PTR request ip is invalid: %s.\n", value);
        return Conf_ERR;
    }

    ipaddress_ptr_t ip_ptr = ipaddress_ptr_fmt(ip);

    FREE(dns_conf.req_name);
    dns_conf.req_name = STRDUP(ip_ptr.string);
    dns_conf.req_type = dns_str_to_record_type("ptr");

    if (dns_conf.req_type == DNS_REC_INVALID) {
        LOG(LEVEL_ERROR, "(dns internal) invalide request type.\n");
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_recursive_desired(void *conf, const char *name,
                                     const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    dns_conf.recursive_desired = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_print_all_add(void *conf, const char *name,
                                 const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    dns_conf.print_all_add = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_print_all_auth(void *conf, const char *name,
                                  const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    dns_conf.print_all_auth = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_print_all_answer(void *conf, const char *name,
                                    const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    dns_conf.print_all_ans = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_req_name(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    size_t str_len = strlen(value);
    if (str_len == 0) {
        LOG(LEVEL_ERROR, "request name of dns is error.\n");
        return Conf_ERR;
    }

    FREE(dns_conf.req_name);
    dns_conf.req_name = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_req_type(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf);
    UNUSEDPARM(name);

    size_t str_len = strlen(value);
    if (str_len == 0) {
        LOG(LEVEL_ERROR, "request type of dns is error.\n");
        return Conf_ERR;
    }

    dns_conf.req_type = dns_str_to_record_type(value);

    if (dns_conf.req_type == DNS_REC_INVALID) {
        LOG(LEVEL_ERROR, "invalide request type of dns.\n");
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_dnssec(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    dns_conf.dnssec = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_edns_size(void *conf, const char *name, const char *value) {
    UNUSEDPARM(conf); UNUSEDPARM(name);
    unsigned v = (unsigned)strtoul(value, NULL, 0);
    if (v < 512 || v > 65535)
        return Conf_ERR;
    dns_conf.edns_size = v;
    return Conf_OK;
}

static ConfParam dns_parameters[] = {
    {"req-name",
     SET_req_name,
     Type_ARG,
     {"name", 0},
     "Specifies dns request name like 'www.google.com'."},
    {"req-type",
     SET_req_type,
     Type_ARG,
     {"type", 0},
     "Specifies dns request type like 'A', 'AAAA'."},
    {"ptr-request",
     SET_ptr,
     Type_ARG,
     {"ptr", "ptr-ip", 0},
     "This is a wrapper of setting request type to PTR and request name by "
     "the ip we specified."},
    {"recursive-desired",
     SET_recursive_desired,
     Type_FLAG,
     {"recursive", "rd", 0},
     "Sets recursive desired flag to true in DNS header and expects target DNS "
     "server to answer our question by recursive requesting."},
    {"all-answer",
     SET_print_all_answer,
     Type_FLAG,
     {"all-ans", 0},
     "Print all answer records instead of only the first in default."},
    {"all-authority",
     SET_print_all_auth,
     Type_FLAG,
     {"all-auth", 0},
     "Print all authority records instead of only the first in default."},
    {"dnssec",
     SET_dnssec,
     Type_FLAG,
     {"do", 0},
     "Send an EDNS0 OPT record with DO=1 and report DNSSEC evidence "
     "(AD/DO, RRSIG/DNSKEY/DS/NSEC counts). This observes deployment; it does "
     "not validate the DNSSEC chain."},
    {"edns-size",
     SET_edns_size,
     Type_ARG,
     {"udp-size", 0},
     "EDNS0 UDP payload size, 512..65535; default 1232. A truncated response "
     "is reported with dns_truncated=1."},
    {"all-additional",
     SET_print_all_add,
     Type_FLAG,
     {"all-addition", "all-add", 0},
     "Print all additional records instead of only the first in default."},

    {0}};

static bool dns_init(const XConf *xconf) {
    if (!dns_conf.req_name) {
        LOG(LEVEL_ERROR, "please specify a dns request name by --req-name.\n");
        return false;
    }

    if (dns_conf.req_type == 0) {
        LOG(LEVEL_HINT, "use default dns A record type because no request type "
                        "was specified by --req-type.\n");
        dns_conf.req_type = DNS_REC_A;
    }

    return true;
}

static size_t dns_make_payload(ProbeTarget   *target,
                               unsigned char *payload_buf) {
    memset(payload_buf, 0, PM_PAYLOAD_SIZE);
    int res_len =
        dns_question_create(payload_buf, dns_conf.req_name, dns_conf.req_type,
                            target->cookie & 0xFFFF);
    if (dns_conf.recursive_desired)
        dns_buf_set_rd(payload_buf, true);

    if (dns_conf.dnssec && res_len > 0) {
        unsigned char *p = payload_buf + res_len;
        p[0] = 0;                    /* root */
        p[1] = 0x00; p[2] = 0x29;    /* OPT */
        unsigned sz = dns_conf.edns_size ? dns_conf.edns_size : 1232;
        p[3] = (unsigned char)(sz >> 8); p[4] = (unsigned char)sz;
        p[5] = 0; p[6] = 0; p[7] = 0x80; p[8] = 0; p[9] = 0; /* DO */
        p[10] = 0; p[11] = 0;        /* RDLEN */
        res_len += 11;
        payload_buf[10] = 0; payload_buf[11] = 1; /* ARCOUNT */
    }

    return (size_t)res_len;
}

static bool dns_validate_response(ProbeTarget *target, const unsigned char *px,
                                  unsigned sizeof_px) {
    if (sizeof_px < 2) {
        return false;
    }

    /*maybe we can do more validation to ensure this is a valid dns packet*/
    if (U16_EQUAL_TO_BE(px, target->cookie & 0xFFFF)) {
        return true;
    }

    return false;
}

static unsigned dns_handle_response(unsigned th_idx, ProbeTarget *target,
                                    const unsigned char *px, unsigned sizeof_px,
                                    OutItem *item) {
    dns_pkt_t dns_pkt;

    if (!dns_parse_reply((uint8_t *)px, sizeof_px, &dns_pkt)) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "not dns");
        safe_strcpy(item->reason, OUT_RSN_SIZE, "parse failed");
        return 0;
    }
    if (dns_pkt.head.header.rcode != DNS_RCODE_NOERROR) {
        item->level = OUT_FAILURE;
        safe_strcpy(item->classification, OUT_CLS_SIZE, "dns error");
        safe_strcpy(item->reason, OUT_RSN_SIZE,
                    dns_rcode2str(dns_pkt.head.header.rcode));
        return 0;
    }

    if (dns_conf.dnssec) {
        unsigned flags = ((unsigned)px[2] << 8) | px[3];
        dach_set_bool(&item->probe_report, "dns_ad", (flags & 0x0020) != 0);
        dach_set_bool(&item->probe_report, "dns_truncated",
                      (flags & 0x0200) != 0);
        unsigned sig = 0, key = 0, ds = 0, nsec = 0;
        for (unsigned i = 0; i < dns_pkt.head.header.ans_count +
                                  dns_pkt.head.header.auth_count +
                                  dns_pkt.head.header.add_count; i++) {
            dns_record_t *r = NULL;
            if (i < dns_pkt.head.header.ans_count)
                r = &dns_pkt.body.ans[i];
            else if (i < dns_pkt.head.header.ans_count +
                            dns_pkt.head.header.auth_count)
                r = &dns_pkt.body.auth[i - dns_pkt.head.header.ans_count];
            else
                r = &dns_pkt.body.add[i - dns_pkt.head.header.ans_count -
                                       dns_pkt.head.header.auth_count];
            if (r->type == 46) sig++;
            else if (r->type == 48) key++;
            else if (r->type == 43) ds++;
            else if (r->type == 47 || r->type == 50) nsec++;
        }
        dach_set_int(&item->probe_report, "dns_rrsig_count", sig);
        dach_set_int(&item->probe_report, "dns_dnskey_count", key);
        dach_set_int(&item->probe_report, "dns_ds_count", ds);
        dach_set_int(&item->probe_report, "dns_nsec_count", nsec);
        dach_set_bool(&item->probe_report, "dns_dnssec_present",
                      sig || key || ds || nsec);
    }
    item->level = OUT_SUCCESS;
    safe_strcpy(item->classification, OUT_CLS_SIZE, "dns reply");
    safe_strcpy(item->reason, OUT_RSN_SIZE,
                dns_rcode2str(dns_pkt.head.header.rcode));

    dns_record_t *rec;
    char          tmp_data[50];
    DataLink     *link;

    if (dns_pkt.head.header.ans_count > 0) {
        rec = &dns_pkt.body.ans[0];
        dns_raw_record_data2str(rec, (uint8_t *)px, (uint8_t *)px + sizeof_px,
                                false, tmp_data, sizeof(tmp_data));
        const char *type_str  = dns_record_type2str(rec->type);
        const char *class_str = dns_class2str(rec->class);

        link = dach_append_char(&item->probe_report, "answer", '[',
                                LinkType_String);
        link = dach_append_by_link(link, type_str, strlen(type_str));
        link = dach_append_char_by_link(link, ' ');
        link = dach_append_by_link(link, class_str, strlen(class_str));
        link = dach_append_char_by_link(link, ' ');
        link = dach_append_by_link(link, tmp_data, strlen(tmp_data));
        link = dach_append_char_by_link(link, ']');
    }

    if (dns_pkt.head.header.ans_count > 1 && dns_conf.print_all_ans) {
        for (uint16_t i = 1; i < dns_pkt.head.header.ans_count; i++) {
            rec = &dns_pkt.body.ans[i];
            dns_raw_record_data2str(rec, (uint8_t *)px,
                                    (uint8_t *)px + sizeof_px, false, tmp_data,
                                    sizeof(tmp_data));
            const char *type_str  = dns_record_type2str(rec->type);
            const char *class_str = dns_class2str(rec->class);

            link = dach_append_by_link(link, ", [", 3);
            link = dach_append_by_link(link, type_str, strlen(type_str));
            link = dach_append_char_by_link(link, ' ');
            link = dach_append_by_link(link, class_str, strlen(class_str));
            link = dach_append_char_by_link(link, ' ');
            link = dach_append_by_link(link, tmp_data, strlen(tmp_data));
            link = dach_append_char_by_link(link, ']');
        }
    }

    if (dns_pkt.head.header.auth_count > 0) {
        rec = &dns_pkt.body.auth[0];
        dns_raw_record_data2str(rec, (uint8_t *)px, (uint8_t *)px + sizeof_px,
                                false, tmp_data, sizeof(tmp_data));
        const char *type_str  = dns_record_type2str(rec->type);
        const char *class_str = dns_class2str(rec->class);

        link = dach_append_char(&item->probe_report, "authority", '[',
                                LinkType_String);
        link = dach_append_by_link(link, type_str, strlen(type_str));
        link = dach_append_char_by_link(link, ' ');
        link = dach_append_by_link(link, class_str, strlen(class_str));
        link = dach_append_char_by_link(link, ' ');
        link = dach_append_by_link(link, tmp_data, strlen(tmp_data));
        link = dach_append_char_by_link(link, ']');
    }

    if (dns_pkt.head.header.auth_count > 1 && dns_conf.print_all_auth) {
        for (uint16_t i = 1; i < dns_pkt.head.header.auth_count; i++) {
            rec = &dns_pkt.body.auth[i];
            dns_raw_record_data2str(rec, (uint8_t *)px,
                                    (uint8_t *)px + sizeof_px, false, tmp_data,
                                    sizeof(tmp_data));
            const char *type_str  = dns_record_type2str(rec->type);
            const char *class_str = dns_class2str(rec->class);

            link = dach_append_by_link(link, ", [", 3);
            link = dach_append_by_link(link, type_str, strlen(type_str));
            link = dach_append_char_by_link(link, ' ');
            link = dach_append_by_link(link, class_str, strlen(class_str));
            link = dach_append_char_by_link(link, ' ');
            link = dach_append_by_link(link, tmp_data, strlen(tmp_data));
            link = dach_append_char_by_link(link, ']');
        }
    }

    if (dns_pkt.head.header.add_count > 0) {
        rec = &dns_pkt.body.add[0];
        dns_raw_record_data2str(rec, (uint8_t *)px, (uint8_t *)px + sizeof_px,
                                false, tmp_data, sizeof(tmp_data));
        const char *type_str  = dns_record_type2str(rec->type);
        const char *class_str = dns_class2str(rec->class);

        link = dach_append_char(&item->probe_report, "additional", '[',
                                LinkType_String);
        link = dach_append_by_link(link, type_str, strlen(type_str));
        link = dach_append_char_by_link(link, ' ');
        link = dach_append_by_link(link, class_str, strlen(class_str));
        link = dach_append_char_by_link(link, ' ');
        link = dach_append_by_link(link, tmp_data, strlen(tmp_data));
        link = dach_append_char_by_link(link, ']');
    }

    if (dns_pkt.head.header.add_count > 1 && dns_conf.print_all_add) {
        for (uint16_t i = 1; i < dns_pkt.head.header.add_count; i++) {
            rec = &dns_pkt.body.add[i];
            dns_raw_record_data2str(rec, (uint8_t *)px,
                                    (uint8_t *)px + sizeof_px, false, tmp_data,
                                    sizeof(tmp_data));
            const char *type_str  = dns_record_type2str(rec->type);
            const char *class_str = dns_class2str(rec->class);

            link = dach_append_by_link(link, ", [", 3);
            link = dach_append_by_link(link, type_str, strlen(type_str));
            link = dach_append_char_by_link(link, ' ');
            link = dach_append_by_link(link, class_str, strlen(class_str));
            link = dach_append_char_by_link(link, ' ');
            link = dach_append_by_link(link, tmp_data, strlen(tmp_data));
            link = dach_append_char_by_link(link, ']');
        }
    }

    return 0;
}

static void dns_close() { FREE(dns_conf.req_name); }

Probe DnsProbe = {
    .name       = "dns",
    .type       = ProbeType_UDP,
    .params     = dns_parameters,
    .short_desc = "Do specified DNS record request.",
    .desc =
        "DnsProbe sends a dns request specified by user to target udp port and "
        "expects a dns reply. DnsProbe is used for scanning multiple dns "
        "servers by one type request, instead of doing multiple dns requests "
        "to one dns server.\n"
        "NOTE: If we have not added iptables rules to ban the outwards ICMP "
        "Port Unreachable sending, dns response retransmission will happen and "
        "waste resource both on scanner and targets. And an interesting thing "
        "will happen: every retransmited dns reply carries a different answer.",

    .init_cb              = &dns_init,
    .make_payload_cb      = &dns_make_payload,
    .validate_response_cb = &dns_validate_response,
    .handle_response_cb   = &dns_handle_response,
    .close_cb             = &dns_close,
};