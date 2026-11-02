#include "scan-modules.h"
#include "../generate-modules/generate-modules.h"

#include <stdlib.h>
#include <string.h>

#include "../xconf.h"
#include "../templ/templ-arp.h"
#include "../util-data/safe-string.h"
#include "../util-out/logger.h"

extern Scanner ArpReqScan; /*for internal x-ref*/

static const TargetSet *_targets = NULL;

static bool arpreq_init(const XConf *xconf) {
    if (xconf->nic.link_type != 1) {
        LOG(LEVEL_ERROR, "ArpReqScan cannot work on non-ethernet link type.\n");
        return false;
    }

    if (strcmp(xconf->generator->name, "blackrock") == 0) {
        _targets = &xconf->targets;
    } else {
        LOG(LEVEL_WARN, "use non-default generator so that may get "
                        "irrelated results.\n");
    }

    return true;
}

static bool arpreq_transmit(uint64_t entropy, ScanTarget *target,
                            unsigned char *px, size_t *len) {
    if (target->target.ip_proto != IP_PROTO_Other)
        return false;

    /*arp is just for ipv4*/
    if (target->target.ip_them.version != 4)
        return false;

    /*we do not need a cookie and actually cannot set it*/
    *len = arp_create_request_packet(target->target.ip_them,
                                     target->target.ip_me, px, PKT_BUF_SIZE);

    return false;
}

static void arpreq_validate(uint64_t entropy, Recved *recved, PreHandle *pre) {
    /*do not care about any other types of arp packet.*/
    if (recved->parsed.found == FOUND_ARP && recved->is_myip &&
        recved->parsed.arp_info.opcode == ARP_OPCODE_REPLY)
        ;
    else
        return;

    if (_targets && !targetset_has_ip(_targets, recved->parsed.src_ip)) {
        return;
    }

    pre->go_record       = 1;
    pre->dedup_port_them = 0;
    pre->dedup_port_me   = 0;
    pre->go_dedup        = 1;
}

static void arpreq_handle(unsigned th_idx, uint64_t entropy,
                          ValidPacket *valid_pkt, OutItem *item,
                          NetStack *stack) {
    if (valid_pkt->repeats) {
        item->no_output = 1;
        return;
    }
    Recved *recved = &valid_pkt->recved;

    item->target.port_them = 0;
    item->target.port_me   = 0;
    item->no_port          = 1;
    item->level            = OUT_SUCCESS;

    safe_strcpy(item->classification, OUT_CLS_SIZE, "alive");
    safe_strcpy(item->reason, OUT_RSN_SIZE, "arp reply");
    dach_printf(&item->scan_report, "mac addr", "%02X:%02X:%02X:%02X:%02X:%02X",
                recved->parsed.arp_info.sender_mac[0],
                recved->parsed.arp_info.sender_mac[1],
                recved->parsed.arp_info.sender_mac[2],
                recved->parsed.arp_info.sender_mac[3],
                recved->parsed.arp_info.sender_mac[4],
                recved->parsed.arp_info.sender_mac[5]);
}

Scanner ArpReqScan = {
    .name                = "arp-req",
    .required_probe_type = ProbeType_NULL,
    .params              = NULL,
    .bpf_filter          = "arp && arp[6:2]==2", /*arp reply*/
    .short_desc          = "ARP scan for local network.",
    .desc = "ArpReqScan sends an ARP Request packet to broadcast mac addr(all "
            "one) with target ipv4 addr we request. Expect an ARP Reply packet "
            "with actual mac addr of requested target and print mac addr as "
            "report. ArpReqScan does not support ipv6 target because ipv6 use "
            "neighbor discovery messages of Neighbor Dicovery Protocol(NDP) "
            "implemented by ICMPv6 to dicovery neighbors and their mac addr. "
            "ArpReqScan will ignore ipv6 targets.\n"
            "NOTE1: ArpReqScan works in local area network only, so remember "
            "to use\n"
            "    `--lan-mode`\n"
            "or to set router mac like:\n"
            "    `--router-mac ff-ff-ff-ff-ff-ff`.\n"
            "NOTE2: Don't specify any ports for this module.",

    .init_cb     = &arpreq_init,
    .transmit_cb = &arpreq_transmit,
    .validate_cb = &arpreq_validate,
    .handle_cb   = &arpreq_handle,
    .poll_cb     = &scan_poll_nothing,
    .close_cb    = &scan_close_nothing,
    .status_cb   = &scan_no_status,
};