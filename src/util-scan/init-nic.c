#include "./init-nic.h"

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#endif

#include "../rawsock/rawsock.h"
#include "../stub/stub-pcap-dlt.h"
#include "../stack/stack-arpv4.h"
#include "../stack/stack-ndpv6.h"
#include "../util-out/logger.h"
#include "../util-data/safe-string.h"

/***************************************************************************
 * Initialize the struct NIC in XConf.
 *
 * This requires finding things like our IP address, MAC address, and router
 * MAC address. The user could configure these things manually instead.
 *
 * Note that we don't update the "static" configuration with the discovered
 * values, but instead return them as the "running" configuration. That's
 * so if we pause and resume a scan, auto discovered values don't get saved
 * in the configuration file.
 ***************************************************************************/
int init_nic(XConf *xconf, bool has_ipv4_targets, bool has_ipv6_targets) {

    ipaddress_formatted_t fmt;
    char                 *ifname;
    char                  ifname2[256];
    unsigned              adapter_ip = 0;
    AdapterCache *tmp_acache     = rawsock_init_cache(false, 0, 0, false, 0);
    bool          is_usable_ipv4 = !has_ipv4_targets;
    bool          is_usable_ipv6 = !has_ipv6_targets;

    rawsock_firewall_warn();

    /*
     * ADAPTER/NETWORK-INTERFACE
     *
     * If no network interface was configured, we need to go hunt down
     * the best Interface to use. We do this by choosing the first
     * interface with a "default route" (aka. "gateway") defined
     */
    if (xconf->nic.ifname[0])
        ifname = xconf->nic.ifname;
    else {
        int n = rawsock_count_default_interfaces();
        if (n > 1) {
            LOG(LEVEL_ERROR,
                "multiple default interfaces detected (%d); use -if to choose explicitly\n",
                n);
            return -1;
        }
        /* no adapter specified, so find a default one */
        int err;
        ifname2[0] = '\0';
        err        = rawsock_get_default_interface(ifname2, sizeof(ifname2));
        if (err || ifname2[0] == '\0') {
            LOG(LEVEL_ERROR, "could not determine default interface\n");
            LOG(LEVEL_ERROR, "try \"--interface ethX\"\n");
            rawsock_close_cache(tmp_acache);
            return -1;
        }
        ifname = ifname2;
        /*pass the ifname we chose to global*/
        safe_strcpy(xconf->nic.ifname, 256, ifname2);
    }
    if (xconf->nic.ifname[0]) {
        char resolved[256];
        int  rr = rawsock_resolve_ifname(ifname, resolved, sizeof(resolved));
        if (rr == 0) {
            safe_strcpy(xconf->nic.ifname, sizeof(xconf->nic.ifname),
                        resolved);
            ifname = xconf->nic.ifname;
        } else if (rr > 1) {
            LOG(LEVEL_ERROR,
                "interface name is ambiguous: %s\n", xconf->nic.ifname);
            return -1;
        }
    }
    LOG(LEVEL_DEBUG, "interface = %s\n", ifname);

    /*
     * START ADAPTER
     */
    xconf->nic.adapter = rawsock_init_adapter(
        ifname, xconf->is_pfring, xconf->is_rawsocket, xconf->is_sendmmsg,
        xconf->is_sendq, xconf->is_packet_trace, xconf->is_offline,
        xconf->nic.is_vlan, xconf->nic.vlan_id, xconf->nic.snaplen);
    if (xconf->nic.adapter == 0) {
        LOG(LEVEL_ERROR, "(if:%s) init failed\n", ifname);
        rawsock_close_cache(tmp_acache);
        return -1;
    }
    xconf->nic.link_type = xconf->nic.adapter->link_type;
    LOG(LEVEL_DEBUG, "interface-type = %u\n", xconf->nic.link_type);

    rawsock_ignore_transmits(xconf->nic.adapter, ifname);

    /*
     * MAC ADDRESS
     *
     * This is the address we send packets from. It actually doesn't really
     * matter what this address is, but to be a "responsible" citizen we
     * try to use the hardware address in the network card.
     */
    if (xconf->nic.link_type == PCAP_DLT_NULL) {
        LOG(LEVEL_DEBUG, "source-mac = %s\n", "none");
    } else if (xconf->nic.link_type == PCAP_DLT_RAW) {
        LOG(LEVEL_DEBUG, "source-mac = %s\n", "none");
    } else {
        if (xconf->nic.my_mac_count == 0) {
            if (macaddress_is_zero(xconf->nic.source_mac)) {
                rawsock_get_adapter_mac(ifname, xconf->nic.source_mac.addr);
            }
            /* If still zero, then print error message */
            if (macaddress_is_zero(xconf->nic.source_mac)) {
                LOG(LEVEL_ERROR,
                    "failed to detect MAC address of interface:"
                    " \"%s\"\n",
                    ifname);
                LOG(LEVEL_ERROR, "try something like "
                                 "\"--source-mac 00-11-22-33-44-55\"\n");
                rawsock_close_cache(tmp_acache);
                return -1;
            }
        }

        fmt = macaddress_fmt(xconf->nic.source_mac);
        LOG(LEVEL_DEBUG, "source-mac = %s\n", fmt.string);
    }

    /*
     * IPv4 ADDRESS
     */
    if (has_ipv4_targets) {
        adapter_ip = xconf->nic.src.ipv4.first;
        if (adapter_ip == 0) {
            adapter_ip                = rawsock_get_adapter_ip(ifname);
            xconf->nic.src.ipv4.first = adapter_ip;
            xconf->nic.src.ipv4.last  = adapter_ip;
            xconf->nic.src.ipv4.range = 1;
        }
        if (adapter_ip == 0) {
            /* We appear to have IPv4 targets, yet we cannot find an adapter
             * to use for those targets. We are having trouble querying the
             * operating system stack. */
            LOG(LEVEL_ERROR, "failed to detect IP of interface \"%s\"\n",
                ifname);
            LOG(LEVEL_HINT, "did you spell the name correctly?\n");
            LOG(LEVEL_HINT,
                "if it has no IP address, manually set with something like "
                "\"--source-ip 198.51.100.17\"\n");
            if (targetset_has_any_ipv4(&xconf->targets)) {
                rawsock_close_cache(tmp_acache);
                return -1;
            }
        }

        fmt = ipv4address_fmt(adapter_ip);
        LOG(LEVEL_DEBUG, "source-ip = %s\n", fmt.string);

        if (adapter_ip != 0)
            is_usable_ipv4 = 1;

        /*
         * ROUTER MAC ADDRESS
         */
        if (xconf->is_offline) {
            /* If we are doing offline benchmarking/testing, then create
             * a fake MAC address fro the router */
            memcpy(xconf->nic.router_mac_ipv4.addr, "\x66\x55\x44\x33\x22\x11",
                   6);
        } else if (xconf->nic.link_type == PCAP_DLT_NULL) {
            /* If it's a VPN tunnel, then there is no Ethernet MAC address */
            LOG(LEVEL_DEBUG, "router-mac-ipv4 = %s\n", "implicit");
        } else if (xconf->nic.link_type == PCAP_DLT_RAW) {
            /* If it's a VPN tunnel, then there is no Ethernet MAC address */
            LOG(LEVEL_DEBUG, "router-mac-ipv4 = %s\n", "implicit");
        } else if (macaddress_is_zero(xconf->nic.router_mac_ipv4)) {
            ipv4address_t router_ipv4 = xconf->nic.router_ip;
            int           err         = 0;

            LOG(LEVEL_DETAIL, "if(%s): looking for default gateway\n", ifname);
            if (router_ipv4 == 0)
                err = rawsock_get_default_gateway(ifname, &router_ipv4);
            if (err == 0) {
                fmt = ipv4address_fmt(router_ipv4);
                LOG(LEVEL_DEBUG, "router-ip = %s\n", fmt.string);
                LOG(LEVEL_DETAIL, "if(%s):arp: resolving IPv4 address\n",
                    ifname);

#ifdef _WIN32
                {
                    ULONG m[2] = {0, 0};
                    ULONG mlen = 6;
                    if (SendARP(htonl(router_ipv4), 0, m, &mlen) == NO_ERROR &&
                        mlen == 6) {
                        memcpy(xconf->nic.router_mac_ipv4.addr, m, 6);
                    } else {
                        stack_arp_resolve(
                            xconf->nic.adapter, tmp_acache, adapter_ip,
                            xconf->nic.source_mac, router_ipv4,
                            &xconf->nic.router_mac_ipv4);
                    }
                }
#else
                stack_arp_resolve(xconf->nic.adapter, tmp_acache, adapter_ip,
                                  xconf->nic.source_mac, router_ipv4,
                                  &xconf->nic.router_mac_ipv4);
#endif
                rawsock_flush(xconf->nic.adapter, tmp_acache);
            }

            fmt = macaddress_fmt(xconf->nic.router_mac_ipv4);
            LOG(LEVEL_DEBUG, "router-mac-ipv4 = %s\n", fmt.string);
            if (macaddress_is_zero(xconf->nic.router_mac_ipv4)) {
                fmt = ipv4address_fmt(xconf->nic.router_ip);
                LOG(LEVEL_ERROR,
                    "arp timed-out resolving MAC address for router %s: "
                    "\"%s\"\n",
                    ifname, fmt.string);
                LOG(LEVEL_HINT, "try \"--router ip 192.0.2.1\" to specify "
                                "different router\n");
                LOG(LEVEL_HINT, "try \"--router-mac 66-55-44-33-22-11\" "
                                "instead to bypass ARP\n");
                LOG(LEVEL_HINT,
                    "try \"--interface eth0\" to change interface\n");
                rawsock_close_cache(tmp_acache);
                return -1;
            }
        }
    }

    /*
     * IPv6 ADDRESS
     */
    if (has_ipv6_targets) {
        ipv6address adapter_ipv6 = xconf->nic.src.ipv6.first;
        if (ipv6address_is_zero(adapter_ipv6)) {
            adapter_ipv6              = rawsock_get_adapter_ipv6(ifname);
            xconf->nic.src.ipv6.first = adapter_ipv6;
            xconf->nic.src.ipv6.last  = adapter_ipv6;
            xconf->nic.src.ipv6.range = 1;
        }
        if (ipv6address_is_zero(adapter_ipv6)) {
            LOG(LEVEL_ERROR,
                "failed to detect IPv6 address of interface \"%s\"\n", ifname);
            LOG(LEVEL_HINT, "did you spell the name correctly?\n");
            LOG(LEVEL_HINT,
                "if it has no IP address, manually set with something like "
                "\"--source-ip 2001:3b8::1234\"\n");
            rawsock_close_cache(tmp_acache);
            return -1;
        }
        fmt = ipv6address_fmt(adapter_ipv6);
        LOG(LEVEL_DEBUG, "source-ip = [%s]\n", fmt.string);
        is_usable_ipv6 = 1;

        /*
         * ROUTER MAC ADDRESS
         */
        if (xconf->is_offline) {
            memcpy(xconf->nic.router_mac_ipv6.addr, "\x66\x55\x44\x33\x22\x11",
                   6);
        }
        if (macaddress_is_zero(xconf->nic.router_mac_ipv6)) {
            /* [synchronous]
             * Wait for router neighbor notification. This may take
             * some time */
            stack_ndpv6_resolve(xconf->nic.adapter, tmp_acache, adapter_ipv6,
                                xconf->nic.source_mac,
                                &xconf->nic.router_mac_ipv6);
            rawsock_flush(xconf->nic.adapter, tmp_acache);
        }

        fmt = macaddress_fmt(xconf->nic.router_mac_ipv6);
        LOG(LEVEL_DEBUG, "router-mac-ipv6 = %s\n", fmt.string);
        if (macaddress_is_zero(xconf->nic.router_mac_ipv6)) {
            fmt = ipv4address_fmt(xconf->nic.router_ip);
            LOG(LEVEL_ERROR,
                "ndp timed-out resolving MAC address for router %s: \"%s\"\n",
                ifname, fmt.string);
            LOG(LEVEL_HINT, "try \"--router-mac-ipv6 66-55-44-33-22-11\" "
                            "instead to bypass ARP\n");
            LOG(LEVEL_HINT, "try \"--interface eth0\" to change interface\n");
            rawsock_close_cache(tmp_acache);
            return -1;
        }
    }

    /*
     * NOTE:
     *
     * Set to non-block mode will cause a weired sending latency on Windows.
     *
     * Set to block mode will cause disgarding of read timeout on Linux.
     * Especialy while using BPF filter, rx thread may be blocked in a long
     * time because no valid packet can be recved, so that rx thread exits so
     * late.
     *
     * Actually I have not found actual reason to it, so just adapt it.
     *
     * The good news is xtate's tx/rx mechanism won't be affected by the mode.
     */
#ifndef _WIN32
    rawsock_set_nonblock(xconf->nic.adapter);
#endif

    xconf->nic.is_usable = (is_usable_ipv4 & is_usable_ipv6);

    LOG(LEVEL_DETAIL, "if(%s): initialization done.\n", ifname);
    rawsock_close_cache(tmp_acache);
    return 0;
}