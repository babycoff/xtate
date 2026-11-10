#include "rawsock-route.h"

#include <stdio.h>
#include <string.h>

#include "../util-data/safe-string.h"
#include "../util-data/fine-malloc.h"

#ifndef _WIN32
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

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
        unsigned char b[16];
        for (int i = 0; i < 8; i++) {
            b[i] = (unsigned char)(target.ipv6.hi >> (56 - i * 8));
            b[8 + i] = (unsigned char)(target.ipv6.lo >> (56 - i * 8));
        }
        dst.si_family = AF_INET6;
        dst.Ipv6.sin6_family = AF_INET6;
        memcpy(&dst.Ipv6.sin6_addr, b, 16);
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

    unsigned v4src = 0;
    ipaddress v6src = {0};
    adapter_addr_for_index(ifindex, &v4src, &v6src);
    out->source_ip = target.version == 6 ? v6src : (ipaddress){0};
    if (target.version == 4) {
        out->source_ip.version = 4;
        out->source_ip.ipv4 = v4src;
    }

    if (guid[0] && pcap_name_for_guid(guid, out->ifname,
                                      sizeof(out->ifname)) == 0) {
        /* mapped to a pcap device */
    } else {
        /* Fall back to default interface name, but keep the routed source. */
        char name[256] = {0};
        if (rawsock_get_default_interface(name, sizeof(name)) != 0)
            return -1;
        safe_strcpy(out->ifname, sizeof(out->ifname), name);
        if (target.version == 4 && !out->source_ip.ipv4)
            out->source_ip.ipv4 = rawsock_get_adapter_ip(name);
        if (target.version == 6 &&
            !(out->source_ip.ipv6.hi || out->source_ip.ipv6.lo))
            out->source_ip.ipv6 = rawsock_get_adapter_ipv6(name);
    }

    if (target.version == 4) {
        out->gateway.version = 4;
        unsigned gw = 0;
        if (rawsock_get_default_gateway(out->ifname, &gw) == 0)
            out->gateway.ipv4 = gw;
    }
    return 0;
}
#else
static int netlink_route(ipaddress target, RawRoute *out) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
        return -1;
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char            buf[64];
    } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type  = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.rtm.rtm_family  = target.version == 6 ? AF_INET6 : AF_INET;
    req.rtm.rtm_dst_len = target.version == 6 ? 128 : 32;
    req.rtm.rtm_table   = RT_TABLE_UNSPEC;

    struct rtattr *rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(
        req.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    if (target.version == 6) {
        rta->rta_len = RTA_LENGTH(16);
        unsigned char b[16];
        for (int i = 0; i < 8; i++) {
            b[i] = (unsigned char)(target.ipv6.hi >> (56 - i * 8));
            b[8 + i] = (unsigned char)(target.ipv6.lo >> (56 - i * 8));
        }
        memcpy(RTA_DATA(rta), b, 16);
    } else {
        rta->rta_len = RTA_LENGTH(4);
        unsigned v = htonl(target.ipv4);
        memcpy(RTA_DATA(rta), &v, 4);
    }
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    if (sendto(fd, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa,
               sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    char buf[4096];
    int  n = (int)recv(fd, buf, sizeof(buf), 0);
    close(fd);
    if (n <= 0)
        return -1;

    for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, n);
         nh = NLMSG_NEXT(nh, n)) {
        if (nh->nlmsg_type != RTM_NEWROUTE)
            continue;
        struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
        unsigned oif = 0, gw = 0, src = 0;
        bool have_src = false;
        unsigned char gw6[16] = {0}, src6[16] = {0};
        bool have_gw6 = false, have_src6 = false;
        int  alen = (int)(nh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm)));
        for (struct rtattr *a = (struct rtattr *)((char *)rtm +
                                                  NLMSG_ALIGN(sizeof(*rtm)));
             RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
            if (a->rta_type == RTA_OIF && RTA_PAYLOAD(a) >= 4)
                memcpy(&oif, RTA_DATA(a), 4);
            else if (a->rta_type == RTA_GATEWAY &&
                     RTA_PAYLOAD(a) >= (rtm->rtm_family == AF_INET6 ? 16u : 4u)) {
                if (rtm->rtm_family == AF_INET)
                    memcpy(&gw, RTA_DATA(a), 4);
                else {
                    memcpy(gw6, RTA_DATA(a), 16);
                    have_gw6 = true;
                }
            } else if (a->rta_type == RTA_PREFSRC &&
                       RTA_PAYLOAD(a) >= (rtm->rtm_family == AF_INET6 ? 16u : 4u)) {
                if (rtm->rtm_family == AF_INET) {
                    memcpy(&src, RTA_DATA(a), 4);
                    have_src = true;
                } else {
                    memcpy(src6, RTA_DATA(a), 16);
                    have_src6 = true;
                }
            }
        }
        if (!oif || !if_indextoname(oif, out->ifname))
            return -1;
        out->source_ip.version = target.version;
        out->gateway.version   = target.version;
        if (target.version == 4) {
            out->source_ip.ipv4 = have_src ? ntohl(src)
                                           : rawsock_get_adapter_ip(out->ifname);
            out->gateway.ipv4 = ntohl(gw);
        } else {
            out->source_ip.version = 6;
            if (have_src6)
                out->source_ip.ipv6 = ipv6address_from_bytes(src6);
            else
                out->source_ip.ipv6 = rawsock_get_adapter_ipv6(out->ifname);
            if (have_gw6) {
                out->gateway.version = 6;
                out->gateway.ipv6 = ipv6address_from_bytes(gw6);
            }
        }
        return 0;
    }
    return -1;
}

int rawsock_route_lookup(ipaddress target, RawRoute *out) {
    if (!out || (target.version != 4 && target.version != 6))
        return -1;
    memset(out, 0, sizeof(*out));
    if (netlink_route(target, out) == 0)
        return 0;

    /* Conservative fallback: default interface. */
    char name[256] = {0};
    unsigned gw = 0;
    if (rawsock_get_default_interface(name, sizeof(name)) != 0)
        return -1;
    safe_strcpy(out->ifname, sizeof(out->ifname), name);
    out->source_ip.version = 4;
    out->source_ip.ipv4 = rawsock_get_adapter_ip(name);
    out->gateway.version = 4;
    if (rawsock_get_default_gateway(name, &gw) == 0)
        out->gateway.ipv4 = gw;
    return 0;
}
#endif
