#ifndef RAWSOCK_ROUTE_H
#define RAWSOCK_ROUTE_H
#include "rawsock.h"

typedef struct RawRoute {
    char      ifname[256];
    ipaddress source_ip;
    ipaddress gateway;
} RawRoute;

int rawsock_route_lookup(ipaddress target, RawRoute *out);
#endif
