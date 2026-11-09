#include "rawsock-route.h"
#include <stdio.h>
#include "../util-data/safe-string.h"

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
