#include "rawsock-route.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include "../stub/stub-pcap.h"

static char *wstr_to_mb(const wchar_t *w, char *out, size_t out_size) {
    if (!w || !out || !out_size)
        return NULL;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)out_size, NULL,
                                NULL);
    if (n <= 0)
        return NULL;
    out[n - 1] = '\0';
    return out;
}

static int pcap_name_for_guid(const char *guid, char *out, size_t out_size) {
    pcap_if_t *alldevs = NULL;
    char       errbuf[PCAP_ERRBUF_SIZE];

    if (!guid || !out || !out_size || pcap_init() != 0)
        return -1;
    if (PCAP.findalldevs(&alldevs, errbuf) == -1 || !alldevs)
        return -1;

    for (const pcap_if_t *d = alldevs; d; d = PCAP.dev_next(d)) {
        const char *name = PCAP.dev_name(d);
        if (name && strstr(name, guid)) {
            safe_strcpy(out, out_size, name);
            return 0;
        }
    }
    return -1;
}

static int adapter_addr_for_index(ULONG ifindex, unsigned *ipv4,
                                  ipaddress *ip6) {
    ULONG  size = 0;
    ULONG  flags = GAA_FLAG_INCLUDE_GATEWAYS;
    PIP_ADAPTER_ADDRESSES addrs = NULL, a = NULL;
    int    rc = 0;

    GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &size);
    addrs = (PIP_ADAPTER_ADDRESSES)MALLOC(size);
    if (!addrs)
        return -1;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addrs, &size) !=
        NO_ERROR) {
        rc = -1;
        goto out;
    }

    for (a = addrs; a; a = a->Next) {
        if (a->IfIndex != ifindex || a->OperStatus != IfOperStatusUp)
            continue;
        for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress; u;
             u = u->Next) {
            if (u->Address.lpSockaddr->sa_family == AF_INET && ipv4) {
                const SOCKADDR_IN *sin =
                    (const SOCKADDR_IN *)u->Address.lpSockaddr;
                *ipv4 = ntohl(sin->sin_addr.s_addr);
            } else if (u->Address.lpSockaddr->sa_family == AF_INET6 && ip6) {
                const SOCKADDR_IN6 *sin6 =
                    (const SOCKADDR_IN6 *)u->Address.lpSockaddr;
                ip6->version = 6;
                ip6->ipv6 = ipv6address_from_bytes(
                    (const unsigned char *)&sin6->sin6_addr);
            }
        }
        if (a->PhysicalAddressLength >= 6) {
            /* route struct does not carry MAC; diag reads it separately */
        }
        if (ipv4 && *ipv4)
            break;
    }
out:
    FREE(addrs);
    return rc;
}

int rawsock_route_lookup(ipaddress target, RawRoute *out) {
    if (!out || (target.version != 4 && target.version != 6))
        return -1;
    memset(out, 0, sizeof(*out));

    SOCKADDR_INET dst;
    memset(&dst, 0, sizeof(dst));
    if (target.version == 4) {
        dst.si_family = AF_INET;
        dst.Ipv4.sin_family = AF_INET;
        dst.Ipv4.sin_addr.s_addr = htonl(target.ipv4);
    } else {
        return -1; /* IPv6 route lookup not wired yet */
    }

    DWORD ifindex = 0;
    if (GetBestInterfaceEx((const SOCKADDR *)&dst, &ifindex) != NO_ERROR)
        return -1;

    /* Find the matching pcap device for the interface. */
    PIP_ADAPTER_ADDRESSES a = NULL;
    char                 guid[64] = {0};
    ULONG                size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, NULL,
                         &size);
    a = (PIP_ADAPTER_ADDRESSES)MALLOC(size);
    if (!a)
        return -1;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, a,
                             &size) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES cur = a; cur; cur = cur->Next) {
            if (cur->IfIndex != ifindex)
                continue;
            wstr_to_mb(cur->AdapterName, guid, sizeof(guid));
            break;
        }
    }
    FREE(a);

    if (guid[0] && pcap_name_for_guid(guid, out->ifname,
                                      sizeof(out->ifname)) == 0) {
        out->source_ip.version = 4;
        adapter_addr_for_index(ifindex, &out->source_ip.ipv4,
                               &out->source_ip);
    } else {
        /* Fall back to default interface name and address. */
        char name[256] = {0};
        if (rawsock_get_default_interface(name, sizeof(name)) != 0)
            return -1;
        safe_strcpy(out->ifname, sizeof(out->ifname), name);
        out->source_ip.version = 4;
        out->source_ip.ipv4 = rawsock_get_adapter_ip(name);
    }

    if (out->source_ip.version == 4) {
        out->gateway.version = 4;
        unsigned gw = 0;
        if (rawsock_get_default_gateway(out->ifname, &gw) == 0)
            out->gateway.ipv4 = gw;
    }
    return 0;
}
#else
int rawsock_route_lookup(ipaddress target, RawRoute *out) {
    char name[256] = {0};
    unsigned gw = 0;
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (rawsock_get_default_interface(name, sizeof(name)) != 0)
        return -1;
    safe_strcpy(out->ifname, sizeof(out->ifname), name);
    out->source_ip.version = 4;
    out->source_ip.ipv4 = rawsock_get_adapter_ip(name);
    out->gateway.version = 4;
    if (rawsock_get_default_gateway(name, &gw) == 0)
        out->gateway.ipv4 = gw;
    (void)target;
    return 0;
}
#endif
