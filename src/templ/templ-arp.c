#include "templ-arp.h"

#include <string.h>

#include "../globals.h"
#include "../util-out/logger.h"
#include "../util-data/data-convert.h"

static size_t arp_create_by_template_ipv4(const TmplPkt *tmpl,
                                          ipv4address    ip_them,
                                          ipv4address ip_me, unsigned char *px,
                                          size_t sizeof_px) {
    if (tmpl->tmpl_type != TmplType_ARP) {
        LOG(LEVEL_ERROR, "(arp_create_by_template_ipv4) need a TmplType_ARP "
                         "TemplatePacket.\n");
        return 0;
    }
    unsigned r_len = tmpl->ipv4.length;

    if (sizeof_px < r_len) {
        LOG(LEVEL_ERROR, "(arp_create_by_template_ipv4) buffer too small\n");
        return 0;
    }
    memcpy(px, tmpl->ipv4.packet, r_len);
    px = px + tmpl->ipv4.offset_ip;
    U32_TO_BE(px + 14, ip_me);
    U32_TO_BE(px + 24, ip_them);

    return r_len;
}

size_t arp_create_by_template(const TmplPkt *tmpl, ipaddress ip_them,
                              ipaddress ip_me, unsigned char *px,
                              size_t sizeof_px) {
    if (tmpl->tmpl_type != TmplType_ARP) {
        LOG(LEVEL_ERROR,
            "(arp_create_by_template) need a TmplType_ARP TemplatePacket.\n");
        return 0;
    }

    size_t r_len = 0;

    if (ip_them.version == 4) {
        r_len = arp_create_by_template_ipv4(tmpl, ip_them.ipv4, ip_me.ipv4, px,
                                            sizeof_px);
    } else {
        ipaddress_formatted_t ip_them_fmt = ipaddress_fmt(ip_them);
        LOG(LEVEL_WARN,
            "arp_create_by_template: cannot generate arp packet for ipv6: %s\n",
            ip_them_fmt.string);
    }

    return r_len;
}

size_t arp_create_request_packet(ipaddress ip_them, ipaddress ip_me,
                                 unsigned char *px, size_t sizeof_px) {
    return arp_create_by_template(&global_tmplset->pkts[TmplType_ARP], ip_them,
                                  ip_me, px, sizeof_px);
}