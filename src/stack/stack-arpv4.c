/*
    handle ARP

    Usage #1:
        At startup, we make a synchronous request for the local router.
        We'll wait several seconds for a response, but abort the program
        if we don't receive a response.

    Usage #2:
        While running, we'll need to respond to ARPs. That's because we
        may be bypassing the stack of the local machine with a "spoofed"
        IP address. Every so often, the local router may drop it's route
        entry and re-request our address.
*/
#include "stack-arpv4.h"

#include <string.h>
#include <time.h>

#include "stack-queue.h"
#include "../rawsock/rawsock.h"
#include "../util-out/logger.h"
#include "../proto/proto-preprocess.h"
#include "../stub/stub-pcap-dlt.h"
#include "../templ/templ-arp.h"
#include "../util-data/data-convert.h"

#define VERIFY_REMAINING(n)                                                    \
    if (offset + (n) > max)                                                    \
        return;

/**
 * A structure representing the information parsed from an incoming
 * ARP packet. Note: unlike normal programming style, this isn't
 * overlayed on the incoming ARP header, but instead each field
 * is parsed one-by-one and converted into this internal structure.
 */
struct ARP_IncomingRequest {
    unsigned             is_valid;
    unsigned             opcode;
    unsigned             hardware_type;
    unsigned             protocol_type;
    unsigned             hardware_length;
    unsigned             protocol_length;
    unsigned             ip_src;
    unsigned             ip_dst;
    const unsigned char *mac_src;
    const unsigned char *mac_dst;
};

/****************************************************************************
 ****************************************************************************/
static void proto_arp_parse(struct ARP_IncomingRequest *arp,
                            const unsigned char px[], unsigned offset,
                            unsigned max) {
    /*
     * parse the header
     */
    VERIFY_REMAINING(8);
    arp->is_valid = 0; /* not valid yet */

    arp->hardware_type   = BE_TO_U16(px + offset + 0);
    arp->protocol_type   = BE_TO_U16(px + offset + 2);
    arp->hardware_length = px[offset + 4];
    arp->protocol_length = px[offset + 5];
    arp->opcode          = BE_TO_U16(px + offset + 6);
    offset += 8;

    /* We only support IPv4 and Ethernet addresses */
    if (arp->protocol_length != 4)
        return;
    if (arp->hardware_length != 6)
        return;
    if (arp->protocol_type != ETHERTYPE_IPv4)
        return;
    if (arp->hardware_type != 1)
        return;

    /*
     * parse the addresses
     */
    VERIFY_REMAINING(2 * arp->hardware_length + 2 * arp->protocol_length);
    arp->mac_src = px + offset;
    offset += arp->hardware_length;

    arp->ip_src = BE_TO_U32(px + offset);
    offset += arp->protocol_length;

    arp->mac_dst = px + offset;
    offset += arp->hardware_length;

    arp->ip_dst = BE_TO_U32(px + offset);
    // offset += arp->protocol_length;

    arp->is_valid = 1;
}

/****************************************************************************
 * Resolve the IP address into a MAC address. Do this synchronously, meaning,
 * we'll stop and wait for the response. This is done at program startup,
 * but not during then normal asynchronous operation during the scan.
 ****************************************************************************/
int stack_arp_resolve(Adapter *adapter, AdapterCache *acache,
                      ipv4address_t my_ipv4, macaddress_t my_mac_address,
                      ipv4address_t your_ipv4, macaddress_t *your_mac_address) {
    /* zero out bytes in packet to avoid leaking stuff in the padding
     * (ARP is 42 byte packet, Ethernet is 60 byte minimum) */
    unsigned char              xarp_packet[64] = {0};
    unsigned char             *arp_packet      = &xarp_packet[0];
    unsigned                   i;
    time_t                     start;
    unsigned                   is_arp_notice_given = 0;
    struct ARP_IncomingRequest response            = {0};
    int                        is_delay_reported   = 0;

    /*
     * [KLUDGE]
     *  If this is a raw ip connection
     */
    if (rawsock_if_datalink(adapter) == PCAP_DLT_RAW) {
        memcpy(your_mac_address->addr, "\0\0\0\0\0\2", 6);
        return 0; /* success */
    }

    /*
     * Create the request packet
     */
    memcpy(arp_packet + 0, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
    memcpy(arp_packet + 6, my_mac_address.addr, 6);

    if (adapter->is_vlan) {
        memcpy(arp_packet + 12, "\x81\x00", 2);
        arp_packet[14] = (unsigned char)(adapter->vlan_id >> 8);
        arp_packet[15] = (unsigned char)(adapter->vlan_id & 0xFF);
        arp_packet += 4;
    }

    memcpy(arp_packet + 12, "\x08\x06", 2);

    memcpy(arp_packet + 14,
           "\x00\x01" /* hardware = Ethernet */
           "\x08\x00" /* protocol = IPv4 */
           "\x06\x04" /* MAC length = 6, IPv4 length = 4 */
           "\x00\x01" /* opcode = request */
           ,
           8);

    memcpy(arp_packet + 22, my_mac_address.addr, 6);
    U32_TO_BE(arp_packet + 28, my_ipv4);

    memcpy(arp_packet + 32, "\x00\x00\x00\x00\x00\x00", 6);
    U32_TO_BE(arp_packet + 38, your_ipv4);

    /* Kludge: handle VLNA header if it exists. This is probably
     * the wrong way to handle this. */
    if (adapter->is_vlan)
        arp_packet -= 4;

    /*
     * Now loop for a few seconds looking for the response
     */
    rawsock_send_packet(adapter, acache, arp_packet, 60);
    rawsock_flush(adapter, acache);
    start = time(0);
    i     = 0;
    for (;;) {
        unsigned             length;
        unsigned             secs;
        unsigned             usecs;
        const unsigned char *px;
        int                  err;

        if (time(0) != start) {
            start = time(0);
            rawsock_send_packet(adapter, acache, arp_packet, 60);
            rawsock_flush(adapter, acache);
            if (i++ >= 10)
                break; /* timeout */

            /* It's taking too long, so notify the user */
            if (!is_delay_reported) {
                ipaddress_formatted_t fmt = ipv4address_fmt(your_ipv4);
                LOG(LEVEL_HINT,
                    "resolving router %s with ARP (may take some time)...\n",
                    fmt.string);
                is_delay_reported = 1;
            }
        }

        /* If we aren't getting a response back to our ARP, then print a
         * status message */
        if (time(0) > start + 1 && !is_arp_notice_given) {
            ipaddress_formatted_t fmt = ipv4address_fmt(your_ipv4);
            LOG(LEVEL_HINT, "arping local router %s\n", fmt.string);
            is_arp_notice_given = 1;
        }

        err = rawsock_recv_packet(adapter, &length, &secs, &usecs, &px);

        if (err != 0)
            continue;

        if (length < (size_t)(adapter->is_vlan ? 18 : 14))
            continue;
        if (adapter->is_vlan && px[17] != 6)
            continue;
        if (!adapter->is_vlan && px[13] != 6)
            continue;

        /*
         * Parse the response as an ARP packet
         */
        if (adapter->is_vlan)
            proto_arp_parse(&response, px, 18, length);
        else
            proto_arp_parse(&response, px, 14, length);

        /* Is this an ARP packet? */
        if (!response.is_valid) {
            LOG(LEVEL_DETAIL, "(arp) etype=0x%04x, not ARP\n",
                px[12] * 256 + px[13]);
            continue;
        }

        /* Is this an ARP "reply"? */
        if (response.opcode != ARP_OPCODE_REPLY) {
            LOG(LEVEL_DETAIL, "(arp) opcode=%u, not reply(2)\n",
                response.opcode);
            continue;
        }

        /* Is this response directed at us? */
        if (response.ip_dst != my_ipv4) {
            LOG(LEVEL_DETAIL, "(arp) dst=%08x, not my ip 0x%08x\n",
                response.ip_dst, my_ipv4);
            continue;
        }
        if (memcmp(response.mac_dst, my_mac_address.addr, 6) != 0)
            continue;

        /* Is this the droid we are looking for? */
        if (response.ip_src != your_ipv4) {
            ipaddress_formatted_t fmt1 = ipv4address_fmt(response.ip_src);
            ipaddress_formatted_t fmt2 = ipv4address_fmt(your_ipv4);
            LOG(LEVEL_DETAIL, "(arp) target=%s, not desired %s\n", fmt1.string,
                fmt2.string);
            continue;
        }

        /*
         * GOT IT!
         *  we've got a valid response, so save the results and
         *  return.
         */
        memcpy(your_mac_address->addr, response.mac_src, 6);
        {
            ipaddress_formatted_t fmt1 = ipv4address_fmt(response.ip_src);
            ipaddress_formatted_t fmt2 = macaddress_fmt(*your_mac_address);
            LOG(LEVEL_DETAIL, "(arp) %s == %s\n", fmt1.string, fmt2.string);
        }
        return 0;
    }

    return 1;
}

/****************************************************************************
 * Handle an incoming ARP request.
 ****************************************************************************/
int stack_arp_incoming_request(NetStack *stack, ipv4address_t my_ip,
                               macaddress_t my_mac, const unsigned char *px,
                               unsigned length) {
    PktBuf                    *response = 0;
    struct ARP_IncomingRequest request  = {0};

    /* Need at least a full Ethernet+ARP header before touching px[12..13]. */
    if (length < 14) {
        return -1;
    }

    /*
     * Parse the response as an ARP packet
     */
    proto_arp_parse(&request, px, 14, length);

    /* Is this an ARP packet? */
    if (!request.is_valid) {
        LOG(LEVEL_DETAIL, "(arp) etype=0x%04x, not ARP\n",
            px[12] * 256 + px[13]);
        return -1;
    }

    /* Is this an ARP "request"? */
    if (request.opcode != ARP_OPCODE_REQUEST) {
        LOG(LEVEL_DETAIL, "(arp) opcode=%u, not request(1)\n", request.opcode);
        return -1;
    }

    /* Is this response directed at us? */
    if (request.ip_dst != my_ip) {
        LOG(LEVEL_DETAIL, "(arp) dst=%08x, not my ip 0x%08x\n", request.ip_dst,
            my_ip);
        return -1;
    }

    /* Get a buffer for sending the response packet. This thread doesn't
     * send the packet itself. Instead, it formats a packet, then hands
     * that packet off to a transmit thread for later transmission. */
    response = stack_get_pktbuf(stack);

    /* ARP packets are too short, so increase the packet size to
     * the Ethernet minimum */
    response->length = 60;

    /* Fill the padded area with zeroes to avoid leaking data */
    memset(response->px, 0, response->length);

    /*
     * Create the response packet
     */
    memcpy(response->px + 0, request.mac_src, 6);
    memcpy(response->px + 6, my_mac.addr, 6);
    memcpy(response->px + 12, "\x08\x06", 2);

    memcpy(response->px + 14,
           "\x00\x01" /* hardware = Ethernet */
           "\x08\x00" /* protocol = IPv4 */
           "\x06\x04" /* MAC length = 6, IPv4 length = 4 */
           "\x00\x02" /* opcode = reply(2) */
           ,
           8);

    memcpy(response->px + 22, my_mac.addr, 6);
    U32_TO_BE(response->px + 28, my_ip);

    memcpy(response->px + 32, request.mac_src, 6);
    U32_TO_BE(response->px + 38, request.ip_src);

    /*
     * Now queue the packet up for transmission
     */
    stack_transmit_pktbuf(stack, response);

    return 0;
}
