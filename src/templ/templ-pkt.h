/**
 * Store the declare of struct and corresponding funcs
 */
#ifndef TCP_PKT_H
#define TCP_PKT_H

#include <stdint.h>

typedef enum Template_TYPE {
    TmplType_TCP = 0,
    /*for specific SYN settings and belongs to TCP*/
    TmplType_TCP_SYN,
    /*for specific RST settings and belongs to TCP*/
    TmplType_TCP_RST,
    TmplType_UDP,
    TmplType_SCTP,
    TmplType_ICMP_ECHO,
    TmplType_ICMP_TS,
    TmplType_ARP,
    TmplType_NDP_NS,
    TmplType_Count,
} TmplType;

typedef struct TemplatePacket {
    struct {
        unsigned       length; /*packet len*/
        unsigned       offset_ip;
        unsigned       offset_tcp;
        unsigned       offset_app;
        unsigned       ip_ttl;
        unsigned char *packet;
    } ipv4;
    struct {
        unsigned       length; /*packet len*/
        unsigned       offset_ip;
        unsigned       offset_tcp;
        unsigned       offset_app;
        unsigned       ip_ttl;
        unsigned char *packet;
    } ipv6;
    TmplType tmpl_type;
} TmplPkt;

typedef struct TemplateSet {
    unsigned count;
    uint64_t entropy;
    TmplPkt  pkts[TmplType_Count];
} TmplSet;


#endif